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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	regoSchema "github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	celDriver "github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel"
	celSchema "github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel/schema"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel/transform"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TemplateFailureClass is the broad retryability/response class of a template failure.
type TemplateFailureClass string

const (
	// TemplateFailureClassInvalid marks a terminal template error.
	TemplateFailureClassInvalid TemplateFailureClass = "Invalid"
	// TemplateFailureClassUnavailable marks a retryable validation backend error.
	TemplateFailureClassUnavailable TemplateFailureClass = "Unavailable"

	// InvalidTemplateFailureClass is an alias for callers that prefer the adjective-first form.
	InvalidTemplateFailureClass = TemplateFailureClassInvalid
	// UnavailableTemplateFailureClass is an alias for callers that prefer the adjective-first form.
	UnavailableTemplateFailureClass = TemplateFailureClassUnavailable
)

// TemplateFailureCode is the stable machine-readable code for a template failure.
type TemplateFailureCode string

const (
	TemplateInvalidRego        TemplateFailureCode = "TemplateInvalidRego"
	TemplateInvalidCRD         TemplateFailureCode = "TemplateInvalidCRD"
	TemplateMalformed          TemplateFailureCode = "TemplateMalformed"
	TemplateInvalidTarget      TemplateFailureCode = "TemplateInvalidTarget"
	TemplateInvalidOperations  TemplateFailureCode = "TemplateInvalidOperations"
	TemplateInvalidCEL         TemplateFailureCode = "TemplateInvalidCEL"
	TemplateBackendUnavailable TemplateFailureCode = "TemplateBackendUnavailable"
	TemplateCanceled           TemplateFailureCode = "TemplateCanceled"
)

const (
	templateValidationAnnotation       = "gatekeeper.sh/template-validation"
	templateRetryAfterSeconds    int32 = 2
	templateCompilePermitWait          = 2 * time.Second
	templateCleanupTimeout             = time.Second

	invalidTemplateResultTTL = 30 * time.Second
	successTemplateResultTTL = 5 * time.Second
	templateResultCacheLimit = 1024

	templateEndpointPath = "/v1/admit-template"
	templateWebhookName  = "constrainttemplate-validation.gatekeeper.sh"
)

// TemplateValidationFailure is the unified failure carried by template admission responses,
// logs, metrics, and controller status prefixes.
type TemplateValidationFailure struct {
	Class     TemplateFailureClass
	Code      TemplateFailureCode
	Field     string
	Message   string
	Retryable bool
	Cause     error
}

func (f *TemplateValidationFailure) Error() string {
	if f == nil {
		return ""
	}
	if f.Message != "" {
		return fmt.Sprintf("[%s/%s] %s", f.Class, f.Code, f.Message)
	}
	if f.Cause != nil {
		return fmt.Sprintf("[%s/%s] %v", f.Class, f.Code, f.Cause)
	}
	return fmt.Sprintf("[%s/%s]", f.Class, f.Code)
}

// Unwrap exposes the underlying cause for errors.Is/errors.As.
func (f *TemplateValidationFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Cause
}

func invalidTemplateFailure(code TemplateFailureCode, field string, err error) *TemplateValidationFailure {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return &TemplateValidationFailure{
		Class:     TemplateFailureClassInvalid,
		Code:      code,
		Field:     field,
		Message:   message,
		Retryable: false,
		Cause:     err,
	}
}

func unavailableTemplateFailure(code TemplateFailureCode, err error) *TemplateValidationFailure {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return &TemplateValidationFailure{
		Class:     TemplateFailureClassUnavailable,
		Code:      code,
		Message:   message,
		Retryable: true,
		Cause:     err,
	}
}

// IsRetryableTemplateError classifies infrastructure errors without matching error strings.
func IsRetryableTemplateError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err)
}

var (
	templateValidationTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "gatekeeper_template_validation_total",
		Help: "Total ConstraintTemplate admission validations by class and code.",
	}, []string{"class", "code"})

	templateCompileDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gatekeeper_template_compile_duration_seconds",
		Help:    "ConstraintTemplate isolated compilation duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"engine"})

	templateCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "gatekeeper_template_validation_cache_hits_total",
		Help: "Total ConstraintTemplate validation result cache hits.",
	})

	templateAdmissionFailOpen = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "gatekeeper_template_admission_fail_open",
		Help: "Whether the dedicated ConstraintTemplate webhook configuration is missing.",
	})
)

func init() {
	prometheus.MustRegister(
		templateValidationTotal,
		templateCompileDuration,
		templateCacheHits,
		templateAdmissionFailOpen,
	)
}

// templateCRDGenerator is the CreateCRD surface used by admission validation.
type templateCRDGenerator interface {
	CreateCRD(context.Context, *templates.ConstraintTemplate) (*apiextensionsinternal.CustomResourceDefinition, error)
}

// templateCompilerInstance is the cleanup surface shared by isolated engine drivers.
type templateCompilerInstance interface {
	AddTemplate(context.Context, *templates.ConstraintTemplate) error
	RemoveTemplate(context.Context, *templates.ConstraintTemplate) error
}

type templateCompilePool struct {
	permit         chan struct{}
	acquireTimeout time.Duration

	mu      sync.Mutex
	rego    templateCompilerInstance
	cel     templateCompilerInstance
	newRego func() (templateCompilerInstance, error)
	newCEL  func() (templateCompilerInstance, error)
}

func newTemplateCompilePool() *templateCompilePool {
	p := &templateCompilePool{
		permit:         make(chan struct{}, 1),
		acquireTimeout: templateCompilePermitWait,
	}
	p.newRego = func() (templateCompilerInstance, error) {
		return rego.New(rego.Tracing(false))
	}
	p.newCEL = func() (templateCompilerInstance, error) {
		return celDriver.New()
	}
	return p
}

// acquire waits for the single compilation permit without polling.
func (p *templateCompilePool) acquire(ctx context.Context) *TemplateValidationFailure {
	if p == nil || p.permit == nil {
		return unavailableTemplateFailure(TemplateBackendUnavailable, errors.New("template compile pool is not initialized"))
	}
	timeout := p.acquireTimeout
	if timeout <= 0 {
		timeout = templateCompilePermitWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case p.permit <- struct{}{}:
		return nil
	case <-waitCtx.Done():
		if errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return unavailableTemplateFailure(TemplateBackendUnavailable, fmt.Errorf("timed out after %s waiting for template compiler", timeout))
		}
		return unavailableTemplateFailure(TemplateCanceled, waitCtx.Err())
	case <-ctx.Done():
		return unavailableTemplateFailure(TemplateCanceled, ctx.Err())
	}
}

func (p *templateCompilePool) release() {
	select {
	case <-p.permit:
	default:
	}
}

func (p *templateCompilePool) regoInstance() (templateCompilerInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rego != nil {
		return p.rego, nil
	}
	d, err := p.newRego()
	if err != nil {
		return nil, err
	}
	p.rego = d
	return p.rego, nil
}

func (p *templateCompilePool) celInstance() (templateCompilerInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cel != nil {
		return p.cel, nil
	}
	d, err := p.newCEL()
	if err != nil {
		return nil, err
	}
	p.cel = d
	return p.cel, nil
}

func (p *templateCompilePool) discard(instance templateCompilerInstance) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rego == instance {
		p.rego = nil
	}
	if p.cel == instance {
		p.cel = nil
	}
}

func (p *templateCompilePool) cleanup(instance templateCompilerInstance, ct *templates.ConstraintTemplate) {
	if instance == nil || ct == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), templateCleanupTimeout)
	defer cancel()
	if err := instance.RemoveTemplate(ctx, ct); err != nil {
		p.discard(instance)
	}
}

type templateResultCacheEntry struct {
	response  admission.Response
	expiresAt time.Time
	class     TemplateFailureClass
	// generation is a defensive guard for callers that change generation without changing spec.
	generation int64
}

type templateResultCache struct {
	mu      sync.RWMutex
	entries map[string]templateResultCacheEntry
	max     int
	clock   clock.Clock
	now     func() time.Time
}

func newTemplateResultCache(maxEntries int) *templateResultCache {
	if maxEntries <= 0 {
		maxEntries = templateResultCacheLimit
	}
	return &templateResultCache{
		entries: make(map[string]templateResultCacheEntry),
		max:     maxEntries,
		now:     time.Now,
	}
}

func (c *templateResultCache) currentTime() time.Time {
	if c.clock != nil {
		return c.clock.Now()
	}
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *templateResultCache) get(key string, generation int64) (admission.Response, TemplateFailureClass, bool) {
	if c == nil {
		return admission.Response{}, "", false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return admission.Response{}, "", false
	}
	now := c.currentTime()
	if !now.Before(entry.expiresAt) {
		c.mu.Lock()
		// Re-check under the write lock; another goroutine may have replaced the entry.
		current, ok := c.entries[key]
		if ok && !c.currentTime().Before(current.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return admission.Response{}, "", false
	}
	if entry.generation != generation {
		return admission.Response{}, "", false
	}
	templateCacheHits.Inc()
	return entry.response, entry.class, true
}

func (c *templateResultCache) set(key string, entry *templateResultCacheEntry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]templateResultCacheEntry)
	}
	if len(c.entries) >= c.max {
		// Map iteration chooses an arbitrary expired/old candidate. Cache capacity is
		// bounded; exact eviction policy is not part of the admission contract.
		for evictKey := range c.entries {
			delete(c.entries, evictKey)
			break
		}
	}
	c.entries[key] = *entry
}

func (c *templateResultCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// canonicalTemplateSpecJSON returns spec JSON with sorted object keys while preserving
// number literals and array order.
func canonicalTemplateSpecJSON(rawObject []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rawObject, &envelope); err != nil {
		return nil, err
	}
	rawSpec, ok := envelope["spec"]
	if !ok || bytes.Equal(bytes.TrimSpace(rawSpec), []byte("null")) {
		return []byte("null"), nil
	}

	dec := json.NewDecoder(bytes.NewReader(rawSpec))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(canonicalJSONValue(value)); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func canonicalJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(keys))
		for _, key := range keys {
			out[key] = canonicalJSONValue(typed[key])
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = canonicalJSONValue(typed[i])
		}
		return out
	default:
		// json.Number is preserved and marshals as its original numeric literal.
		return value
	}
}

func templateCacheKey(operation admissionv1.Operation, name string, rawObject []byte) (string, error) {
	spec, err := canonicalTemplateSpecJSON(rawObject)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(operation))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(spec)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func templateCacheKeyFromCanonicalSpec(operation admissionv1.Operation, name string, spec []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(operation))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(spec)
	return hex.EncodeToString(h.Sum(nil))
}

func decodeTemplateRequest(req *admission.Request) (*templates.ConstraintTemplate, *TemplateValidationFailure) {
	raw := req.Object.Raw
	if req.Operation == admissionv1.Delete {
		raw = req.OldObject.Raw
	}
	if len(raw) == 0 {
		return nil, invalidTemplateFailure(TemplateMalformed, "", errors.New("request object is empty"))
	}
	obj, _, err := deserializer.Decode(raw, nil, nil)
	if err != nil {
		return nil, invalidTemplateFailure(TemplateMalformed, "", err)
	}
	unversioned := &templates.ConstraintTemplate{}
	if err := runtimeScheme.Convert(obj, unversioned, nil); err != nil {
		return nil, invalidTemplateFailure(TemplateMalformed, "", err)
	}
	return unversioned, nil
}

func validateTemplateShape(ct *templates.ConstraintTemplate) *TemplateValidationFailure {
	if ct == nil {
		return invalidTemplateFailure(TemplateMalformed, "", errors.New("nil ConstraintTemplate"))
	}
	if len(ct.Spec.Targets) != 1 {
		return invalidTemplateFailure(
			TemplateInvalidTarget,
			"spec.targets",
			fmt.Errorf("must declare exactly one target, got %d", len(ct.Spec.Targets)),
		)
	}
	t := ct.Spec.Targets[0]
	if strings.TrimSpace(t.Target) == "" {
		return invalidTemplateFailure(TemplateInvalidTarget, "spec.targets[0].target", errors.New("target name must not be empty"))
	}
	if t.Target != target.Name {
		return invalidTemplateFailure(
			TemplateInvalidTarget,
			"spec.targets[0].target",
			fmt.Errorf("target %q is not supported; must be %q", t.Target, target.Name),
		)
	}

	allowedOperations := map[admissionregistrationv1.OperationType]struct{}{
		admissionregistrationv1.Create:             {},
		admissionregistrationv1.Update:             {},
		admissionregistrationv1.Delete:             {},
		admissionregistrationv1.Connect:            {},
		admissionregistrationv1.OperationType("*"): {},
	}
	for i, targetSpec := range ct.Spec.Targets {
		if targetSpec.Operations == nil {
			continue
		}
		hasWildcard := false
		for _, op := range targetSpec.Operations {
			if op == "*" {
				hasWildcard = true
			}
			if _, ok := allowedOperations[op]; !ok {
				return invalidTemplateFailure(
					TemplateInvalidOperations,
					fmt.Sprintf("spec.targets[%d].operations", i),
					fmt.Errorf("operation %q is not one of CREATE, UPDATE, DELETE, CONNECT, *", op),
				)
			}
		}
		if hasWildcard && len(targetSpec.Operations) > 1 {
			return invalidTemplateFailure(
				TemplateInvalidOperations,
				fmt.Sprintf("spec.targets[%d].operations", i),
				errors.New("if '*' is present, it must be the only operation"),
			)
		}
	}

	kind := ct.Spec.CRD.Spec.Names.Kind
	if kind == "" {
		return invalidTemplateFailure(TemplateInvalidCRD, "spec.crd.spec", errors.New("CRD Kind must not be empty"))
	}
	if !strings.EqualFold(ct.Name, kind) {
		return invalidTemplateFailure(
			TemplateInvalidCRD,
			"spec.crd.spec",
			fmt.Errorf("ConstraintTemplate name %q must equal CRD Kind %q case-insensitively", ct.Name, kind),
		)
	}
	return nil
}

func validateTemplateCRD(ctx context.Context, ct *templates.ConstraintTemplate, crdClient templateCRDGenerator) *TemplateValidationFailure {
	if crdClient == nil {
		return unavailableTemplateFailure(TemplateBackendUnavailable, errors.New("template CRD generator is not configured"))
	}
	if _, err := crdClient.CreateCRD(ctx, ct); err != nil {
		if IsRetryableTemplateError(err) {
			return unavailableTemplateFailure(TemplateBackendUnavailable, err)
		}
		return invalidTemplateFailure(TemplateInvalidCRD, "spec.crd.spec", err)
	}
	return nil
}

func regoFieldPathFromRaw(raw []byte, ct *templates.ConstraintTemplate) string {
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err == nil {
		if spec, ok := object["spec"].(map[string]any); ok {
			if rawTargets, ok := spec["targets"].([]any); ok && len(rawTargets) > 0 {
				if target, ok := rawTargets[0].(map[string]any); ok {
					if rawCodes, ok := target["code"].([]any); ok {
						for i, rawCode := range rawCodes {
							code, ok := rawCode.(map[string]any)
							if !ok {
								continue
							}
							engine, _ := code["engine"].(string)
							if engine != "" && engine != regoSchema.Name && !strings.EqualFold(engine, regoSchema.Name) {
								continue
							}
							if source, ok := code["source"].(map[string]any); ok {
								if _, hasRego := source["rego"]; hasRego {
									return fmt.Sprintf("spec.targets[0].code[%d].source.rego", i)
								}
							}
						}
					}
					if rego, ok := target["rego"].(string); ok && strings.TrimSpace(rego) != "" {
						return "spec.targets[0].rego"
					}
				}
			}
		}
	}
	field, _ := regoSourceLocation(ct)
	return field
}

func regoSourceLocation(ct *templates.ConstraintTemplate) (field string, found bool) {
	if ct == nil || len(ct.Spec.Targets) == 0 {
		return "spec.targets[0].code[0].source.rego", false
	}
	t := ct.Spec.Targets[0]
	for i, code := range t.Code {
		if code.Engine != regoSchema.Name && !strings.EqualFold(code.Engine, regoSchema.Name) {
			continue
		}
		if code.Source != nil {
			if source, ok := code.Source.Value.(map[string]any); ok {
				if _, hasRego := source["rego"]; hasRego {
					return fmt.Sprintf("spec.targets[0].code[%d].source.rego", i), true
				}
			}
			return fmt.Sprintf("spec.targets[0].code[%d].source.rego", i), true
		}
	}
	if strings.TrimSpace(t.Rego) != "" {
		return "spec.targets[0].rego", true
	}
	return "spec.targets[0].code[0].source.rego", false
}

// normalizeRegoForIsolatedCompile ensures legacy target.rego is compiled exactly once by
// the current Rego driver's Code-based path.
func normalizeRegoForIsolatedCompile(ct *templates.ConstraintTemplate) *templates.ConstraintTemplate {
	copyCT := ct.DeepCopy()
	t := &copyCT.Spec.Targets[0]
	for _, code := range t.Code {
		if code.Engine == regoSchema.Name || strings.EqualFold(code.Engine, regoSchema.Name) {
			return copyCT
		}
	}
	if strings.TrimSpace(t.Rego) != "" {
		t.Code = append(t.Code, templates.Code{
			Engine: regoSchema.Name,
			Source: &templates.Anything{Value: map[string]any{"rego": t.Rego}},
		})
	}
	return copyCT
}

func (h *templateAdmissionHandler) compileIsolated(ctx context.Context, ct *templates.ConstraintTemplate, regoFieldOverride ...string) (failure *TemplateValidationFailure) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			failure = unavailableTemplateFailure(TemplateBackendUnavailable, fmt.Errorf("template compiler panic: %v", r))
		}
		engine := "all"
		if failure != nil && failure.Code == TemplateInvalidCEL {
			engine = celSchema.Name
		} else if failure != nil && failure.Code == TemplateInvalidRego {
			engine = regoSchema.Name
		}
		templateCompileDuration.WithLabelValues(engine).Observe(time.Since(start).Seconds())
	}()

	if err := h.pool.acquire(ctx); err != nil {
		return err
	}
	defer h.pool.release()

	// Use a detached compilation context so a singleflight waiter going away cannot
	// cancel the compile shared by all concurrent requests.
	compileCtx := context.WithoutCancel(ctx)

	regoField, hasRego := regoSourceLocation(ct)
	if len(regoFieldOverride) > 0 && regoFieldOverride[0] != "" {
		regoField = regoFieldOverride[0]
	}
	if hasRego || hasRegoCode(ct) {
		instance, err := h.pool.regoInstance()
		if err != nil {
			return unavailableTemplateFailure(TemplateBackendUnavailable, err)
		}
		compileCT := normalizeRegoForIsolatedCompile(ct)
		defer h.pool.cleanup(instance, compileCT)
		if err := instance.AddTemplate(compileCtx, compileCT); err != nil {
			if IsRetryableTemplateError(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return unavailableTemplateFailure(TemplateBackendUnavailable, err)
			}
			return invalidTemplateFailure(TemplateInvalidRego, regoField, err)
		}
	}

	if celSchema.HasCELEngine(ct) {
		instance, err := h.pool.celInstance()
		if err != nil {
			return unavailableTemplateFailure(TemplateBackendUnavailable, err)
		}
		defer h.pool.cleanup(instance, ct)
		if err := instance.AddTemplate(compileCtx, ct); err != nil && IsRetryableTemplateError(err) {
			return unavailableTemplateFailure(TemplateBackendUnavailable, err)
		}
		if err := compileCELExplicitly(compileCtx, ct); err != nil {
			var templateFailure *TemplateValidationFailure
			if errors.As(err, &templateFailure) {
				return templateFailure
			}
			if IsRetryableTemplateError(err) {
				return unavailableTemplateFailure(TemplateBackendUnavailable, err)
			}
			return invalidTemplateFailure(TemplateInvalidCEL, "spec.targets[0].code[0].source", err)
		}
	}

	return nil
}

func hasRegoCode(ct *templates.ConstraintTemplate) bool {
	if ct == nil || len(ct.Spec.Targets) == 0 {
		return false
	}
	for _, code := range ct.Spec.Targets[0].Code {
		if code.Engine == regoSchema.Name || strings.EqualFold(code.Engine, regoSchema.Name) {
			return true
		}
	}
	return false
}

func compileCELExplicitly(_ context.Context, ct *templates.ConstraintTemplate) error {
	if ct == nil || len(ct.Spec.Targets) != 1 {
		return nil
	}
	t := ct.Spec.Targets[0]
	for codeIndex, code := range t.Code {
		if code.Engine != celSchema.Name && !strings.EqualFold(code.Engine, celSchema.Name) {
			continue
		}
		source, err := celSchema.GetSource(code)
		if err != nil {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), err)
		}

		envSet := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
		compiler, err := cel.NewCompositedCompiler(envSet)
		if err != nil {
			return unavailableTemplateFailure(TemplateBackendUnavailable, err)
		}

		// Compile built-in object/params variables exactly as the runtime driver does.
		compiler.CompileAndStoreVariables(transform.AllVariablesCEL(), cel.OptionalVariableDeclarations{HasParams: true}, environment.StoredExpressions)

		variables, err := source.GetVariables()
		if err != nil {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), err)
		}
		for _, variable := range variables {
			result := compiler.CompileAndStoreVariable(variable, cel.OptionalVariableDeclarations{HasParams: true}, environment.StoredExpressions)
			if result.Error != nil {
				return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), result.Error)
			}
		}

		matchAccessors, err := source.GetMatchConditions()
		if err != nil {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), err)
		}
		matchEvaluator := compiler.CompileCondition(matchAccessors, cel.OptionalVariableDeclarations{}, environment.StoredExpressions)
		if errs := matchEvaluator.CompilationErrors(); len(errs) > 0 {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), errors.Join(errs...))
		}

		validationAccessors, err := source.GetValidations()
		if err != nil {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), err)
		}
		validationEvaluator := compiler.CompileCondition(validationAccessors, cel.OptionalVariableDeclarations{}, environment.StoredExpressions)
		if errs := validationEvaluator.CompilationErrors(); len(errs) > 0 {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), errors.Join(errs...))
		}

		messageAccessors, err := source.GetMessageExpressions()
		if err != nil {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), err)
		}
		nonNilMessages := make([]cel.ExpressionAccessor, 0, len(messageAccessors))
		for _, accessor := range messageAccessors {
			if accessor != nil {
				nonNilMessages = append(nonNilMessages, accessor)
			}
		}
		messageEvaluator := compiler.CompileCondition(nonNilMessages, cel.OptionalVariableDeclarations{}, environment.StoredExpressions)
		if errs := messageEvaluator.CompilationErrors(); len(errs) > 0 {
			return invalidTemplateFailure(TemplateInvalidCEL, celFieldPath(codeIndex), errors.Join(errs...))
		}
	}
	return nil
}

func celFieldPath(codeIndex int) string {
	return fmt.Sprintf("spec.targets[0].code[%d].source", codeIndex)
}

func templateFailureResponse(uid types.UID, failure *TemplateValidationFailure) admission.Response {
	if failure == nil {
		resp := admission.Allowed("ConstraintTemplate validation succeeded")
		resp.UID = uid
		return resp
	}

	code := int32(http.StatusUnprocessableEntity)
	reason := metav1.StatusReasonInvalid
	if failure.Class == TemplateFailureClassUnavailable {
		code = http.StatusServiceUnavailable
		reason = metav1.StatusReasonServiceUnavailable
	}

	status := &metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    code,
		Reason:  reason,
		Message: failure.Error(),
	}
	if failure.Class == TemplateFailureClassInvalid {
		field := failure.Field
		status.Details = &metav1.StatusDetails{
			Causes: []metav1.StatusCause{{
				Type:    metav1.CauseTypeFieldValueInvalid,
				Message: failure.Message,
				Field:   field,
			}},
		}
		sort.Slice(status.Details.Causes, func(i, j int) bool {
			return status.Details.Causes[i].Field < status.Details.Causes[j].Field
		})
	} else {
		status.Details = &metav1.StatusDetails{RetryAfterSeconds: templateRetryAfterSeconds}
	}

	resp := admission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Result:  status,
			AuditAnnotations: map[string]string{
				templateValidationAnnotation: fmt.Sprintf("%s/%s", failure.Class, failure.Code),
			},
		},
	}
	return resp
}
