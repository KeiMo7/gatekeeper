/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/operations"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"golang.org/x/sync/singleflight"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const constraintTemplateGroup = "templates.gatekeeper.sh"

func init() {
	AddToManagerFuncs = append(AddToManagerFuncs, AddTemplateWebhook)
}

// templateAdmissionHandler serves /v1/admit-template and owns the isolated compile,
// singleflight deduplication, and terminal-result cache.
type templateAdmissionHandler struct {
	opa          *constraintclient.Client
	crdGenerator templateCRDGenerator
	crdMu        sync.RWMutex

	pool     *templateCompilePool
	group    singleflight.Group
	cache    *templateResultCache
	initOnce sync.Once

	clock clock.Clock
	log   logr.Logger
	now   func() time.Time
}

var _ admission.Handler = &templateAdmissionHandler{}

var (
	sharedTemplateHandlerOnce sync.Once
	sharedTemplateHandler     *templateAdmissionHandler
)

func newTemplateAdmissionHandler(crdGenerator templateCRDGenerator) *templateAdmissionHandler {
	now := time.Now
	var opaClient *constraintclient.Client
	if crdGenerator != nil {
		opaClient, _ = crdGenerator.(*constraintclient.Client)
	}
	h := &templateAdmissionHandler{
		pool:  newTemplateCompilePool(),
		cache: newTemplateResultCache(templateResultCacheLimit),
		log:   log.WithName("template-validation"),
		now:   now,
	}
	if opaClient != nil {
		h.opa = opaClient
		h.crdGenerator = opaClient
	} else if crdGenerator != nil {
		h.crdGenerator = crdGenerator
	}
	return h
}

// NewTemplateAdmissionHandler is the exported constructor for embedders and integration tests.
func NewTemplateAdmissionHandler(crdGenerator templateCRDGenerator) *templateAdmissionHandler {
	return newTemplateAdmissionHandler(crdGenerator)
}

func sharedTemplateAdmissionHandler(crdGenerator templateCRDGenerator) *templateAdmissionHandler {
	sharedTemplateHandlerOnce.Do(func() {
		sharedTemplateHandler = newTemplateAdmissionHandler(crdGenerator)
	})
	if crdGenerator != nil {
		sharedTemplateHandler.crdMu.Lock()
		if sharedTemplateHandler.crdGenerator == nil {
			shouldSet := true
			if opaClient, ok := crdGenerator.(*constraintclient.Client); ok {
				if opaClient == nil {
					shouldSet = false
				} else {
					sharedTemplateHandler.opa = opaClient
				}
			}
			if shouldSet {
				sharedTemplateHandler.crdGenerator = crdGenerator
			}
		}
		sharedTemplateHandler.crdMu.Unlock()
	}
	return sharedTemplateHandler
}

// AddTemplateWebhook registers the dedicated ConstraintTemplate admission endpoint.
func AddTemplateWebhook(mgr manager.Manager, deps Dependencies) error {
	if !operations.IsAssigned(operations.Webhook) {
		return nil
	}
	handler := sharedTemplateAdmissionHandler(deps.OpaClient)
	mgr.GetWebhookServer().Register(templateEndpointPath, &admission.Webhook{Handler: handler})
	return mgr.Add(&templateWebhookConfigChecker{
		reader: mgr.GetAPIReader(),
		name:   *VwhName,
		log:    log.WithName("template-webhook-config-check"),
	})
}

// Handle implements admission.Handler.
// nolint:gocritic // Must accept admission.Request as a struct to satisfy Handler interface.
func (h *templateAdmissionHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	if !isAllowedTemplateRequest(&req) {
		err := errors.New("only templates.gatekeeper.sh/ConstraintTemplate CREATE and UPDATE requests are served by " + templateWebhookName)
		resp := admission.Errored(http.StatusBadRequest, err)
		resp.UID = req.UID
		resp.Result.Status = metav1.StatusFailure
		resp.Result.Reason = metav1.StatusReasonBadRequest
		return resp
	}

	resp, _ := h.review(ctx, req)
	return resp
}

func isAllowedTemplateRequest(req *admission.Request) bool {
	return req.Kind.Group == constraintTemplateGroup &&
		req.Kind.Kind == "ConstraintTemplate" &&
		(req.Operation == admissionv1Create || req.Operation == admissionv1Update)
}

const (
	admissionv1Create = "CREATE"
	admissionv1Update = "UPDATE"
)

type templateReviewOutcome struct {
	response admission.Response
	failure  *TemplateValidationFailure
}

func (h *templateAdmissionHandler) ensureDefaults() {
	h.initOnce.Do(func() {
		if h.pool == nil {
			h.pool = newTemplateCompilePool()
		}
		if h.cache == nil {
			h.cache = newTemplateResultCache(templateResultCacheLimit)
		}
		if h.clock != nil {
			h.cache.clock = h.clock
		}
		if h.now == nil && h.clock == nil {
			h.now = time.Now
		}
	})
}

func (h *templateAdmissionHandler) currentTime() time.Time {
	if h.clock != nil {
		return h.clock.Now()
	}
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

// review performs cached, singleflight-deduplicated validation. The returned response already
// has the request UID populated.
//
//nolint:gocritic // admission.Request follows controller-runtime's by-value Handler convention.
func (h *templateAdmissionHandler) review(ctx context.Context, req admission.Request) (resp admission.Response, failure *TemplateValidationFailure) {
	var generation int64
	defer func() {
		h.record(&req, generation, failure)
	}()
	if h == nil {
		failure := unavailableTemplateFailure(TemplateBackendUnavailable, errors.New("template validation handler is not initialized"))
		return templateFailureResponse(req.UID, failure), failure
	}
	h.ensureDefaults()

	ct, decodeFailure := decodeTemplateRequest(&req)
	if decodeFailure != nil {
		failure = decodeFailure
		resp = templateFailureResponse(req.UID, failure)
		return resp, failure
	}
	generation = ct.GetGeneration()

	key, err := templateCacheKey(req.Operation, firstNonEmpty(req.Name, ct.Name), req.Object.Raw)
	if err != nil {
		failure = invalidTemplateFailure(TemplateMalformed, "", err)
		resp = templateFailureResponse(req.UID, failure)
		return resp, failure
	}

	if cached, class, ok := h.cache.get(key, ct.GetGeneration()); ok {
		cached.UID = req.UID
		if class == TemplateFailureClassInvalid || class == TemplateFailureClassUnavailable {
			code := TemplateInvalidRego
			if annotations := cached.AuditAnnotations; annotations != nil {
				if value := annotations[templateValidationAnnotation]; value != "" {
					_, codeValue, found := splitTemplateAnnotation(value)
					if found {
						code = codeValue
					}
				}
			}
			failure = &TemplateValidationFailure{Class: class, Code: code}
			if cached.Result != nil {
				failure.Message = cached.Result.Message
			}
		}
		resp = cached
		return resp, failure
	}

	resultCh := h.group.DoChan(key, func() (any, error) {
		// Intentionally detached from all callers: abandoning the wait must never cancel
		// the compile that concurrent identical requests are sharing.
		return h.compute(context.WithoutCancel(ctx), key, &req, ct), nil
	})

	select {
	case <-ctx.Done():
		failure := unavailableTemplateFailure(TemplateCanceled, ctx.Err())
		resp := templateFailureResponse(req.UID, failure)
		return resp, failure
	case result := <-resultCh:
		outcome, ok := result.Val.(*templateReviewOutcome)
		if !ok {
			failure := unavailableTemplateFailure(TemplateBackendUnavailable, errors.New("unexpected template singleflight result"))
			return templateFailureResponse(req.UID, failure), failure
		}
		resp := outcome.response
		resp.UID = req.UID
		return resp, outcome.failure
	}
}

func splitTemplateAnnotation(value string) (TemplateFailureClass, TemplateFailureCode, bool) {
	for i := 0; i < len(value); i++ {
		if value[i] == '/' {
			return TemplateFailureClass(value[:i]), TemplateFailureCode(value[i+1:]), true
		}
	}
	return "", "", false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (h *templateAdmissionHandler) compute(ctx context.Context, key string, req *admission.Request, ct *templates.ConstraintTemplate) *templateReviewOutcome {
	// Another caller may have populated a terminal result while this call was queued.
	if cached, _, ok := h.cache.get(key, ct.GetGeneration()); ok {
		return &templateReviewOutcome{response: cached}
	}

	if failure := validateTemplateShape(ct); failure != nil {
		return h.cacheOutcome(key, ct, &templateReviewOutcome{
			response: templateFailureResponse(req.UID, failure),
			failure:  failure,
		})
	}

	h.crdMu.RLock()
	crdGenerator := h.crdGenerator
	opaClient := h.opa
	h.crdMu.RUnlock()
	if crdGenerator == nil && opaClient != nil {
		crdGenerator = opaClient
	}
	if crdGenerator == nil {
		var err error
		crdGenerator, err = newStaticTemplateCRDGenerator()
		if err != nil {
			failure := unavailableTemplateFailure(TemplateBackendUnavailable, err)
			return &templateReviewOutcome{response: templateFailureResponse(req.UID, failure), failure: failure}
		}
		h.crdMu.Lock()
		if h.crdGenerator == nil {
			h.crdGenerator = crdGenerator
		} else {
			crdGenerator = h.crdGenerator
		}
		h.crdMu.Unlock()
	}
	if failure := validateTemplateCRD(ctx, ct, crdGenerator); failure != nil {
		return h.cacheOutcome(key, ct, &templateReviewOutcome{
			response: templateFailureResponse(req.UID, failure),
			failure:  failure,
		})
	}

	regoField := regoFieldPathFromRaw(req.Object.Raw, ct)
	if failure := h.compileIsolated(ctx, ct, regoField); failure != nil {
		return h.cacheOutcome(key, ct, &templateReviewOutcome{
			response: templateFailureResponse(req.UID, failure),
			failure:  failure,
		})
	}

	resp := templateFailureResponse(req.UID, nil)
	return h.cacheOutcome(key, ct, &templateReviewOutcome{response: resp})
}

func (h *templateAdmissionHandler) cacheOutcome(key string, ct *templates.ConstraintTemplate, outcome *templateReviewOutcome) *templateReviewOutcome {
	if outcome.failure == nil {
		h.cache.set(key, &templateResultCacheEntry{
			response:   outcome.response,
			expiresAt:  h.currentTime().Add(successTemplateResultTTL),
			class:      "",
			generation: ct.GetGeneration(),
		})
		return outcome
	}
	if outcome.failure.Class == TemplateFailureClassInvalid {
		h.cache.set(key, &templateResultCacheEntry{
			response:   outcome.response,
			expiresAt:  h.currentTime().Add(invalidTemplateResultTTL),
			class:      TemplateFailureClassInvalid,
			generation: ct.GetGeneration(),
		})
	}
	return outcome
}

func (h *templateAdmissionHandler) record(req *admission.Request, generation int64, failure *TemplateValidationFailure) {
	class := TemplateFailureClass("")
	code := TemplateFailureCode("success")
	retryable := false
	var cause error
	if failure != nil {
		class = failure.Class
		code = failure.Code
		retryable = failure.Retryable
		cause = failure.Cause
	}
	templateValidationTotal.WithLabelValues(string(class), string(code)).Inc()

	logger := h.log
	if logger.GetSink() == nil {
		logger = log
	}
	logger = logger.WithValues(
		"template_name", firstNonEmpty(req.Name, string(req.UID)),
		"template_uid", req.UID,
		"generation", generation,
		"failure_class", class,
		"failure_code", code,
		"retryable", retryable,
	)
	if failure != nil {
		logger.Error(cause, "ConstraintTemplate validation failed")
		return
	}
	logger.V(1).Info("ConstraintTemplate validation succeeded")
}

type templateWebhookConfigChecker struct {
	reader client.Reader
	name   string
	log    logr.Logger
}

var _ manager.Runnable = &templateWebhookConfigChecker{}

// Start runs the startup configuration check and then blocks until manager shutdown.
func (c *templateWebhookConfigChecker) Start(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.CheckOnce(checkCtx); err != nil {
		c.log.Error(err, "unable to verify dedicated ConstraintTemplate webhook configuration")
		templateAdmissionFailOpen.Set(1)
	}
	<-ctx.Done()
	return nil
}

// CheckOnce verifies that the configured ValidatingWebhookConfiguration contains the dedicated entry.
func (c *templateWebhookConfigChecker) CheckOnce(ctx context.Context) error {
	if c.reader == nil {
		templateAdmissionFailOpen.Set(1)
		return errors.New("webhook config reader is not configured")
	}
	if c.name == "" {
		templateAdmissionFailOpen.Set(1)
		c.log.Error(nil, "dedicated ConstraintTemplate webhook is missing: validating webhook configuration name is empty",
			"webhook_name", templateWebhookName, "path", templateEndpointPath)
		return errors.New("validating webhook configuration name is empty")
	}
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := c.reader.Get(ctx, client.ObjectKey{Name: c.name}, vwc); err != nil {
		if apierrors.IsNotFound(err) {
			templateAdmissionFailOpen.Set(1)
			c.log.Error(err, "dedicated ConstraintTemplate webhook is missing",
				"configuration", c.name, "webhook_name", templateWebhookName, "path", templateEndpointPath)
		} else {
			templateAdmissionFailOpen.Set(1)
			c.log.Error(err, "unable to read ValidatingWebhookConfiguration", "configuration", c.name)
		}
		return err
	}
	for i := range vwc.Webhooks {
		if vwc.Webhooks[i].Name == templateWebhookName {
			templateAdmissionFailOpen.Set(0)
			return nil
		}
	}
	templateAdmissionFailOpen.Set(1)
	c.log.Error(nil, "dedicated ConstraintTemplate webhook entry is missing",
		"configuration", c.name, "webhook_name", templateWebhookName, "path", templateEndpointPath)
	return errors.New("dedicated ConstraintTemplate webhook entry is missing")
}

func newStaticTemplateCRDGenerator() (templateCRDGenerator, error) {
	return constraintclient.NewClient(
		constraintclient.Targets(&target.K8sValidationTarget{}),
		constraintclient.EnforcementPoints(util.WebhookEnforcementPoint),
	)
}
