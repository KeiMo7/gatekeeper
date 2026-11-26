package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	templatesv1beta1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	celSchema "github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel/schema"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type uid2FakeCRDGenerator struct {
	calls int
	err   error
}

func (f *uid2FakeCRDGenerator) CreateCRD(context.Context, *templates.ConstraintTemplate) (*apiextensionsinternal.CustomResourceDefinition, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &apiextensionsinternal.CustomResourceDefinition{}, nil
}

type uid2FakeCompiler struct {
	addCalls    atomic.Int64
	removeCalls atomic.Int64
	addErr      error
	removeErr   error
	panicValue  any
	started     chan struct{}
	startOnce   sync.Once
	release     chan struct{}
}

func newUID2FakeCompiler() *uid2FakeCompiler {
	return &uid2FakeCompiler{
		started: make(chan struct{}),
	}
}

func (f *uid2FakeCompiler) AddTemplate(ctx context.Context, _ *templates.ConstraintTemplate) error {
	f.startOnce.Do(func() { close(f.started) })
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.addCalls.Add(1)
	if f.panicValue != nil {
		panic(f.panicValue)
	}
	return f.addErr
}

func (f *uid2FakeCompiler) RemoveTemplate(context.Context, *templates.ConstraintTemplate) error {
	f.removeCalls.Add(1)
	return f.removeErr
}

func (f *uid2FakeCompiler) counts() (int64, int64) {
	return f.addCalls.Load(), f.removeCalls.Load()
}

func uid2TemplateRequest(t *testing.T, ct *templates.ConstraintTemplate) admission.Request {
	t.Helper()
	if ct.APIVersion == "" {
		ct.APIVersion = templatesv1beta1.SchemeGroupVersion.String()
	}
	if ct.Kind == "" {
		ct.Kind = "ConstraintTemplate"
	}
	raw, err := json.Marshal(ct)
	require.NoError(t, err)
	name := ct.Name
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       types.UID("test-uid"),
		Name:      name,
		Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{
			Group:   constraintTemplateGroup,
			Version: "v1beta1",
			Kind:    "ConstraintTemplate",
		},
		Object: runtime.RawExtension{Raw: raw},
	}}
}

func newUID2PoolHandler(crd templateCRDGenerator, compiler templateCompilerInstance) *templateAdmissionHandler {
	h := newTemplateAdmissionHandler(crd)
	if compiler != nil {
		h.pool.rego = compiler
		h.pool.cel = compiler
	}
	return h
}

func uid2RegoTemplate(rego string) *templates.ConstraintTemplate {
	ct := validRegoTemplate()
	source, ok := ct.Spec.Targets[0].Code[0].Source.Value.(map[string]any)
	if !ok {
		panic("test template source is not map[string]any")
	}
	source["rego"] = rego
	return ct
}

func TestUID2ValidateTemplateRegoCompilationFailures(t *testing.T) {
	tests := []struct {
		name string
		rego string
	}{
		{
			name: "syntax error",
			rego: `package x
violation[{"msg": msg}] { msg := "ok" }
anyrule[}}}`,
		},
		{
			name: "undefined function",
			rego: `package x
violation[{"msg": msg}] { msg := definitely_undefined_function() }`,
		},
		{
			name: "unsafe variable",
			rego: `package x
violation[{"msg": msg}] { msg := unsafe_variable }`,
		},
		{
			name: "missing violation rule",
			rego: `package x
hello := true`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTemplateAdmissionHandler(nil)
			req := uid2TemplateRequest(t, uid2RegoTemplate(tt.rego))

			resp, failure := h.review(context.Background(), req)

			if failure != nil {
				t.Logf("failure: %s | cause=%#v | retryable=%v", failure.Error(), failure.Cause, failure.Retryable)
			}
			require.NotNil(t, failure)
			require.Equal(t, TemplateFailureClassInvalid, failure.Class)
			require.Equal(t, TemplateInvalidRego, failure.Code)
			require.Equal(t, "spec.targets[0].code[0].source.rego", failure.Field)
			require.False(t, failure.Retryable)
			require.Equal(t, int32(http.StatusUnprocessableEntity), resp.Result.Code)
			require.Equal(t, metav1.StatusReasonInvalid, resp.Result.Reason)
			require.Equal(t, req.UID, resp.UID)
			require.Equal(t, "Invalid/TemplateInvalidRego", resp.AuditAnnotations[templateValidationAnnotation])
			require.Len(t, resp.Result.Details.Causes, 1)
			require.Equal(t, "spec.targets[0].code[0].source.rego", resp.Result.Details.Causes[0].Field)
			require.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
		})
	}
}

func TestUID2ValidateTemplateLegacyRegoSourcePathAndSingleCompile(t *testing.T) {
	ct := validRegoTemplate()
	ct.Spec.Targets[0].Code = nil
	ct.Spec.Targets[0].Rego = `package legacy
violation[{"msg": msg}] { msg := "ok" }
bad[}}}`
	fc := newUID2FakeCompiler()
	fc.addErr = errors.New("synthetic rego compilation failure")
	h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, fc)

	resp, failure := h.review(context.Background(), uid2TemplateRequest(t, ct))

	require.NotNil(t, failure)
	require.Equal(t, TemplateInvalidRego, failure.Code)
	require.Equal(t, "spec.targets[0].rego", failure.Field)
	require.Equal(t, int32(422), resp.Result.Code)
	adds, removes := fc.counts()
	require.EqualValues(t, 1, adds)
	require.EqualValues(t, 1, removes)

	// When code is present it wins over legacy rego and still compiles once.
	both := validRegoTemplate()
	both.Spec.Targets[0].Rego = `package legacy
violation[{"msg":"bad"}] { syntax !!!`
	fc2 := newUID2FakeCompiler()
	h2 := newUID2PoolHandler(&uid2FakeCRDGenerator{}, fc2)
	_, failure = h2.review(context.Background(), uid2TemplateRequest(t, both))
	require.Nil(t, failure)
	adds, _ = fc2.counts()
	require.EqualValues(t, 1, adds)
}

func TestUID2ValidateTemplateCRDFailures(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*templates.ConstraintTemplate)
		generator templateCRDGenerator
	}{
		{
			name: "empty kind",
			mutate: func(ct *templates.ConstraintTemplate) {
				ct.Spec.CRD.Spec.Names.Kind = ""
			},
			generator: &uid2FakeCRDGenerator{},
		},
		{
			name: "name kind mismatch",
			mutate: func(ct *templates.ConstraintTemplate) {
				ct.Spec.CRD.Spec.Names.Kind = "SomethingElse"
			},
			generator: &uid2FakeCRDGenerator{},
		},
		{
			name: "crd generation error",
			mutate: func(ct *templates.ConstraintTemplate) {
			},
			generator: &uid2FakeCRDGenerator{err: errors.New("schema is invalid")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := validRegoTemplate()
			tt.mutate(ct)
			h := newUID2PoolHandler(tt.generator, newUID2FakeCompiler())

			resp, failure := h.review(context.Background(), uid2TemplateRequest(t, ct))

			require.NotNil(t, failure)
			require.Equal(t, TemplateInvalidCRD, failure.Code)
			require.Equal(t, "spec.crd.spec", failure.Field)
			require.Equal(t, int32(422), resp.Result.Code)
			require.Equal(t, "Invalid/TemplateInvalidCRD", resp.AuditAnnotations[templateValidationAnnotation])
		})
	}
}

func TestUID2ValidateTemplateMalformed(t *testing.T) {
	h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       "uid-malformed",
		Name:      "bad",
		Operation: admissionv1.Create,
		Kind:      metav1.GroupVersionKind{Group: constraintTemplateGroup, Kind: "ConstraintTemplate"},
		Object:    runtime.RawExtension{Raw: []byte(`{not-json`)},
	}}

	resp, failure := h.review(context.Background(), req)
	require.NotNil(t, failure)
	require.Equal(t, TemplateMalformed, failure.Code)
	require.Equal(t, TemplateFailureClassInvalid, failure.Class)
	require.Equal(t, int32(422), resp.Result.Code)
	require.Equal(t, "Invalid/TemplateMalformed", resp.AuditAnnotations[templateValidationAnnotation])

	req.Object.Raw = []byte(`{"apiVersion":"templates.gatekeeper.sh/v999","kind":"ConstraintTemplate","metadata":{"name":"x"},"spec":{}}`)
	_, failure = h.review(context.Background(), req)
	require.NotNil(t, failure)
	require.Equal(t, TemplateMalformed, failure.Code)
}

func TestUID2ValidateTemplateTargetFailures(t *testing.T) {
	tests := []struct {
		name    string
		targets []templates.Target
		field   string
	}{
		{
			name:    "zero targets",
			targets: nil,
			field:   "spec.targets",
		},
		{
			name: "multiple targets",
			targets: []templates.Target{
				{Target: uid2TargetName()},
				{Target: uid2TargetName()},
			},
			field: "spec.targets",
		},
		{
			name: "empty target name",
			targets: []templates.Target{
				{Target: ""},
			},
			field: "spec.targets[0].target",
		},
		{
			name: "unsupported target",
			targets: []templates.Target{
				{Target: "other.example.com"},
			},
			field: "spec.targets[0].target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := validRegoTemplate()
			ct.Spec.Targets = tt.targets
			h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, newUID2FakeCompiler())

			resp, failure := h.review(context.Background(), uid2TemplateRequest(t, ct))

			require.NotNil(t, failure)
			require.Equal(t, TemplateInvalidTarget, failure.Code)
			require.Equal(t, tt.field, failure.Field)
			require.Equal(t, tt.field, resp.Result.Details.Causes[0].Field)
		})
	}
}

func uid2TargetName() string { return "admission.k8s.gatekeeper.sh" }

func TestUID2ValidateTemplateOperationsFailures(t *testing.T) {
	tests := []struct {
		name string
		ops  []uid2AdmissionOperation
	}{
		{"wildcard mixed", []uid2AdmissionOperation{"*", "CREATE"}},
		{"invalid operation", []uid2AdmissionOperation{"FETCH"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := validRegoTemplate()
			ct.Spec.Targets[0].Operations = tt.ops
			h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, newUID2FakeCompiler())

			resp, failure := h.review(context.Background(), uid2TemplateRequest(t, ct))

			require.NotNil(t, failure)
			require.Equal(t, TemplateInvalidOperations, failure.Code)
			require.Equal(t, "spec.targets[0].operations", failure.Field)
			require.Equal(t, "spec.targets[0].operations", resp.Result.Details.Causes[0].Field)
		})
	}
}

// uid2AdmissionOperation avoids importing the long admissionregistration alias solely in test tables.
type uid2AdmissionOperation = admissionregistrationv1.OperationType

func TestUID2ValidateTemplateCELCompilationFailures(t *testing.T) {
	tests := []struct {
		name   string
		source *celSchema.Source
	}{
		{
			name: "expression",
			source: &celSchema.Source{Validations: []celSchema.Validation{{
				Expression: "this is not cel",
			}}},
		},
		{
			name: "variable",
			source: &celSchema.Source{Variables: []celSchema.Variable{{
				Name: "bad", Expression: "missing_function()",
			}}},
		},
		{
			name: "matchCondition",
			source: &celSchema.Source{MatchConditions: []celSchema.MatchCondition{{
				Name: "bad", Expression: "broken(",
			}}},
		},
		{
			name: "messageExpression",
			source: &celSchema.Source{Validations: []celSchema.Validation{{
				Expression: "true", MessageExpression: "broken(",
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := uid2CELTemplate(tt.source)
			h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})

			resp, failure := h.review(context.Background(), uid2TemplateRequest(t, ct))

			require.NotNil(t, failure)
			require.Equal(t, TemplateInvalidCEL, failure.Code)
			require.Equal(t, "spec.targets[0].code[0].source", failure.Field)
			require.Equal(t, int32(422), resp.Result.Code)
			require.Equal(t, "Invalid/TemplateInvalidCEL", resp.AuditAnnotations[templateValidationAnnotation])
		})
	}
}

func uid2CELTemplate(source *celSchema.Source) *templates.ConstraintTemplate {
	ct := validRegoTemplate()
	raw := source.MustToUnstructured()
	ct.Spec.Targets[0].Code = []templates.Code{{
		Engine: celSchema.Name,
		Source: &templates.Anything{Value: raw},
	}}
	return ct
}

func TestUID2TemplateBackendUnavailableClassification(t *testing.T) {
	t.Run("driver initialization failure", func(t *testing.T) {
		h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
		h.pool.newRego = func() (templateCompilerInstance, error) {
			return nil, errors.New("init failed")
		}
		h.pool.rego = nil

		resp, failure := h.review(context.Background(), uid2TemplateRequest(t, uid2RegoTemplate(`package x
violation[{"msg":msg}] { msg := "ok" }`)))

		require.NotNil(t, failure)
		require.Equal(t, TemplateFailureClassUnavailable, failure.Class)
		require.Equal(t, TemplateBackendUnavailable, failure.Code)
		require.True(t, failure.Retryable)
		uid2AssertUnavailableResponse(t, &resp)
	})

	t.Run("driver panic", func(t *testing.T) {
		fc := newUID2FakeCompiler()
		fc.panicValue = "boom"
		h := newUID2PoolHandler(&uid2FakeCRDGenerator{}, fc)

		resp, failure := h.review(context.Background(), uid2TemplateRequest(t, uid2RegoTemplate(`package x
violation[{"msg":msg}] { msg := "ok" }`)))

		require.NotNil(t, failure)
		require.Equal(t, TemplateBackendUnavailable, failure.Code)
		uid2AssertUnavailableResponse(t, &resp)
		_, removes := fc.counts()
		require.EqualValues(t, 1, removes)
		require.Same(t, fc, h.pool.rego, "successful cleanup retains the isolated instance")
	})

	t.Run("context canceled while waiting for permit", func(t *testing.T) {
		h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
		h.pool.permit <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resp, failure := h.review(ctx, uid2TemplateRequest(t, uid2RegoTemplate(`package x
violation[{"msg":msg}] { msg := "ok" }`)))

		require.NotNil(t, failure)
		require.Equal(t, TemplateCanceled, failure.Code)
		require.True(t, failure.Retryable)
		uid2AssertUnavailableResponse(t, &resp)
	})
	t.Run("permit wait timeout", func(t *testing.T) {
		h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
		h.pool.acquireTimeout = 20 * time.Millisecond
		h.pool.permit <- struct{}{}
		start := time.Now()

		resp, failure := h.review(context.Background(), uid2TemplateRequest(t, uid2RegoTemplate(`package x
violation[{"msg":msg}] { msg := "ok" }`)))

		require.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
		require.NotNil(t, failure)
		require.Equal(t, TemplateBackendUnavailable, failure.Code)
		uid2AssertUnavailableResponse(t, &resp)
	})
}

func uid2AssertUnavailableResponse(t *testing.T, resp *admission.Response) {
	t.Helper()
	require.Equal(t, int32(http.StatusServiceUnavailable), resp.Result.Code)
	require.Equal(t, metav1.StatusReasonServiceUnavailable, resp.Result.Reason)
	require.Equal(t, int32(2), resp.Result.Details.RetryAfterSeconds)
	require.Contains(t, resp.AuditAnnotations[templateValidationAnnotation], "Unavailable/")
}

type uid2TimeoutNetError struct{}

func (uid2TimeoutNetError) Error() string   { return "timeout" }
func (uid2TimeoutNetError) Timeout() bool   { return true }
func (uid2TimeoutNetError) Temporary() bool { return true }

func TestUID2IsRetryableTemplateError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"canceled", context.Canceled, true},
		{"deadline", context.DeadlineExceeded, true},
		{"net timeout", uid2TimeoutNetError{}, true},
		{"timeout api error", apierrors.NewTimeoutError("test", 1), true},
		{"server timeout", apierrors.NewServerTimeout(schema.GroupResource{}, "get", 1), true},
		{"too many requests", apierrors.NewTooManyRequests("test", 1), true},
		{"service unavailable", apierrors.NewServiceUnavailable("test"), true},
		{"plain compile", errors.New("unsafe var"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var netErr net.Error
			if errors.As(tt.err, &netErr) {
				require.True(t, IsRetryableTemplateError(tt.err))
				return
			}
			require.Equal(t, tt.want, IsRetryableTemplateError(tt.err))
		})
	}
}

func TestUID2CanonicalTemplateSpecJSON(t *testing.T) {
	raw := []byte(`{"metadata":{"name":"x"},"spec":{"b":[1,{"y":2,"x":1}],"a":{"z":1,"a":2},"n":12345678901234567890}}`)
	canonical, err := canonicalTemplateSpecJSON(raw)
	require.NoError(t, err)
	require.JSONEq(t, `{"a":{"a":2,"z":1},"b":[1,{"x":1,"y":2}],"n":12345678901234567890}`, string(canonical))
	require.Contains(t, string(canonical), `"n":12345678901234567890`)

	key1 := templateCacheKeyFromCanonicalSpec(admissionv1.Create, "x", canonical)
	changed, err := canonicalTemplateSpecJSON([]byte(`{"spec":{"a":2}}`))
	require.NoError(t, err)
	key2 := templateCacheKeyFromCanonicalSpec(admissionv1.Create, "x", changed)
	require.NotEqual(t, key1, key2)
}

func TestUID2TemplateResultCacheTTLsLimitAndNoUnavailable(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	cache := newTemplateResultCache(1024)
	cache.now = clock
	h := newTemplateAdmissionHandler(&uid2FakeCRDGenerator{})
	h.cache = cache
	h.now = clock
	fc := newUID2FakeCompiler()
	fc.addErr = errors.New("invalid rego")
	h.pool.rego = fc
	ct := uid2RegoTemplate(`package x
violation[{"msg":msg}] { msg := "bad" }`)
	req := uid2TemplateRequest(t, ct)

	_, f1 := h.review(context.Background(), req)
	require.Equal(t, TemplateInvalidRego, f1.Code)
	require.Equal(t, 1, cache.len())
	_, f2 := h.review(context.Background(), req)
	require.Equal(t, f1.Code, f2.Code)
	adds, _ := fc.counts()
	require.EqualValues(t, 1, adds, "422 result should be cached")

	now = now.Add(29 * time.Second)
	_, _ = h.review(context.Background(), req)
	adds, _ = fc.counts()
	require.EqualValues(t, 1, adds, "422 result should still be valid within 30s")

	now = now.Add(2 * time.Second)
	_, _ = h.review(context.Background(), req)
	adds, _ = fc.counts()
	require.EqualValues(t, 2, adds, "expired 422 result should be recompiled")

	// Success TTL is five seconds.
	fc.addErr = nil
	successCT := validRegoTemplate()
	successReq := uid2TemplateRequest(t, successCT)
	now = time.Unix(2000, 0)
	_, f := h.review(context.Background(), successReq)
	require.Nil(t, f)
	_, _ = h.review(context.Background(), successReq)
	adds, _ = fc.counts()
	require.EqualValues(t, 3, adds) // previous invalid template recompiled twice + one success compile
	now = now.Add(5 * time.Second)
	_, _ = h.review(context.Background(), successReq)
	adds, _ = fc.counts()
	require.EqualValues(t, 4, adds, "success should expire at its 5s TTL boundary")

	for i := 0; i < 1025; i++ {
		cache.set(strconv.Itoa(i), &templateResultCacheEntry{expiresAt: now.Add(time.Minute)})
	}
	require.LessOrEqual(t, cache.len(), 1024)
}
