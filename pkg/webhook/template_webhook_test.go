package webhook

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type uid2CountingServingDriver struct {
	drivers.Driver
	addCalls    atomic.Int64
	removeCalls atomic.Int64
}

func (d *uid2CountingServingDriver) Name() string { return "counting-serving-driver" }

func (d *uid2CountingServingDriver) AddTemplate(context.Context, *templates.ConstraintTemplate) error {
	d.addCalls.Add(1)
	return errors.New("serving AddTemplate must not be called")
}

func (d *uid2CountingServingDriver) RemoveTemplate(context.Context, *templates.ConstraintTemplate) error {
	d.removeCalls.Add(1)
	return errors.New("serving RemoveTemplate must not be called")
}

func TestUID2TemplateAdmissionHandlerRejectsWrongGVKAndDeleteWith400(t *testing.T) {
	h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
	tests := []struct {
		name string
		req  admission.Request
	}{
		{
			name: "other GVK",
			req: admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				UID:       "uid-other",
				Operation: admissionv1.Create,
				Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
			}},
		},
		{
			name: "delete template",
			req: admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				UID:       "uid-delete",
				Operation: admissionv1.Delete,
				Kind: metav1.GroupVersionKind{
					Group: constraintTemplateGroup, Kind: "ConstraintTemplate",
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := h.Handle(context.Background(), tt.req)
			require.False(t, resp.Allowed)
			require.NotNil(t, resp.Result)
			require.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
			require.Equal(t, tt.req.UID, resp.UID)
		})
	}
}

func TestUID2TemplateAdmissionDoesNotTouchServingTemplateClient(t *testing.T) {
	servingDriver := &uid2CountingServingDriver{}
	servingClient, err := constraintclient.NewClient(
		constraintclient.Driver(servingDriver),
		constraintclient.Targets(&target.K8sValidationTarget{}),
		constraintclient.EnforcementPoints(util.WebhookEnforcementPoint),
	)
	require.NoError(t, err)

	isolated := newUID2FakeCompiler()
	h := newUID2PoolHandler(servingClient, isolated)
	ct := validRegoTemplate()

	resp := h.Handle(context.Background(), uid2TemplateRequest(t, ct))
	require.True(t, resp.Allowed, "expected isolated fake compile to succeed: %+v", resp.Result)
	require.Equal(t, int64(0), servingDriver.addCalls.Load())
	require.Equal(t, int64(0), servingDriver.removeCalls.Load())
	adds, removes := isolated.counts()
	require.Equal(t, int64(1), adds)
	require.Equal(t, int64(1), removes)
}

func TestUID2TemplateAdmissionConcurrentIdenticalRequestsCompileOnce(t *testing.T) {
	isolated := newUID2FakeCompiler()
	isolated.release = make(chan struct{})
	h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, isolated)
	req := uid2TemplateRequest(t, validRegoTemplate())

	const n = 64
	var wg sync.WaitGroup
	resps := make([]admission.Response, n)
	cancels := make([]context.CancelFunc, n)
	ctxs := make([]context.Context, n)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = ctx
		cancels[i] = cancel
	}

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			resps[i] = h.Handle(ctxs[i], req)
		}(i)
	}

	select {
	case <-isolated.started:
	case <-time.After(10 * time.Second):
		t.Fatal("isolated compile did not start")
	}
	// Give all identical callers an opportunity to attach to the singleflight call.
	time.Sleep(50 * time.Millisecond)
	cancels[0]()
	close(isolated.release)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent requests did not finish")
	}
	for _, cancel := range cancels {
		cancel()
	}

	adds, removes := isolated.counts()
	require.Equal(t, int64(1), adds)
	require.Equal(t, int64(1), removes)

	canceled := 0
	allowed := 0
	for i, resp := range resps {
		require.Equal(t, types.UID("test-uid"), resp.UID, "response %d did not backfill UID", i)
		if resp.Result != nil && resp.Result.Code == http.StatusServiceUnavailable {
			require.Equal(t, "Unavailable/TemplateCanceled", resp.AuditAnnotations[templateValidationAnnotation])
			canceled++
			continue
		}
		if resp.Allowed {
			allowed++
		}
	}
	require.Equal(t, 1, canceled, "exactly the canceled waiter should get TemplateCanceled")
	require.Equal(t, n-1, allowed)
}

func TestUID2TemplateCompilePoolDiscardsInstanceWhenCleanupFails(t *testing.T) {
	fc := newUID2FakeCompiler()
	fc.removeErr = errors.New("remove failed")
	h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, fc)
	req := uid2TemplateRequest(t, validRegoTemplate())

	resp, failure := h.review(context.Background(), req)
	require.Nil(t, failure)
	require.True(t, resp.Allowed)
	_, removes := fc.counts()
	require.Equal(t, int64(1), removes)
	require.Nil(t, h.pool.rego, "failed cleanup must discard isolated instance")

	replacement := newUID2FakeCompiler()
	h.pool.newRego = func() (templateCompilerInstance, error) { return replacement, nil }
	nextTemplate := validRegoTemplate()
	nextTemplate.Generation = 1
	_, failure = h.review(context.Background(), uid2TemplateRequest(t, nextTemplate))
	require.Nil(t, failure)
	adds, _ := replacement.counts()
	require.Equal(t, int64(1), adds)
}

func TestUID2TemplateWebhookConfigChecker(t *testing.T) {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	vwc.Name = *VwhName
	vwc.Webhooks = []admissionregistrationv1.ValidatingWebhook{{Name: templateWebhookName}}
	client := fake.NewClientBuilder().WithObjects(vwc).Build()
	checker := &templateWebhookConfigChecker{reader: client, name: *VwhName}
	require.NoError(t, checker.CheckOnce(context.Background()))

	vwc.Webhooks = nil
	client = fake.NewClientBuilder().WithObjects(vwc).Build()
	checker = &templateWebhookConfigChecker{reader: client, name: *VwhName}
	require.Error(t, checker.CheckOnce(context.Background()))
}
