package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/util"
)

const (
	PluginName = "authzen"

	defaultPath     = "authzen"
	defaultDecision = "allow"

	// maxRequestBodyBytes is the maximum allowed size for an API request body.
	// This protects against denial-of-service attacks via excessively large
	// payloads (Section 11.7 of the AuthZEN specification).
	maxRequestBodyBytes = 1 << 20 // 1 MB

	// maxBatchSize is the maximum number of evaluations allowed in a single
	// batch request. This protects against resource exhaustion from requests
	// containing an excessive number of evaluation items (Section 11.7).
	maxBatchSize = 100

	// defaultSearchMaxLimit caps the per-page result size for Search APIs
	// (Section 8.5) when the operator does not override it via config.
	defaultSearchMaxLimit = 1000
)

// searchKind identifies which AuthZEN Search API a request targets (Section 8).
type searchKind int

const (
	searchSubject searchKind = iota
	searchResource
	searchAction
)

// Config represents the plugin configuration.
type Config struct {
	Path     string       `json:"path"`
	Decision string       `json:"decision"`
	Search   SearchConfig `json:"search"`
}

// SearchConfig configures the optional Search APIs (Section 8 of the AuthZEN
// specification). Each field names a Rego rule (within the package given by
// Config.Path) that returns the set of permitted entities. Leaving a field
// empty disables the corresponding endpoint, which responds with 501.
type SearchConfig struct {
	Subject  string `json:"subject,omitempty"`
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
	// MaxLimit caps the per-page result size requested by clients. A value of
	// 0 selects the default (defaultSearchMaxLimit).
	MaxLimit int `json:"max_limit,omitempty"`
}

// Validate parses and validates the plugin configuration.
func Validate(_ *plugins.Manager, bs []byte) (*Config, error) {
	cfg := Config{
		Path:     defaultPath,
		Decision: defaultDecision,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	if cfg.Search.MaxLimit < 0 {
		return nil, fmt.Errorf("search.max_limit must be non-negative")
	}

	return &cfg, nil
}

// AuthZenPlugin implements the AuthZEN Authorization API on top of OPA.
type AuthZenPlugin struct {
	manager *plugins.Manager
	cfg     Config
	mu      sync.RWMutex
	started bool
	stopped bool
	logger  logging.Logger
}

// New creates a new AuthZenPlugin.
func New(m *plugins.Manager, cfg *Config) *AuthZenPlugin {
	return &AuthZenPlugin{
		manager: m,
		cfg:     *cfg,
		logger:  m.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
}

// Start registers the AuthZEN routes on OPA's HTTP server via ExtraRoute.
func (p *AuthZenPlugin) Start(_ context.Context) error {
	p.mu.Lock()
	alreadyStarted := p.started
	p.started = true
	p.stopped = false
	p.mu.Unlock()

	if !alreadyStarted {
		p.logger.Info("Starting AuthZEN plugin")
		p.manager.ExtraRoute("POST /access/v1/evaluation", "authzen/evaluation", p.handleEvaluation)
		p.manager.ExtraRoute("POST /access/v1/evaluations", "authzen/evaluations", p.handleEvaluations)
		p.manager.ExtraRoute("POST /access/v1/search/subject", "authzen/search-subject", p.handleSubjectSearch)
		p.manager.ExtraRoute("POST /access/v1/search/resource", "authzen/search-resource", p.handleResourceSearch)
		p.manager.ExtraRoute("POST /access/v1/search/action", "authzen/search-action", p.handleActionSearch)
		p.manager.ExtraRoute("GET /.well-known/authzen-configuration", "authzen/well-known", p.handleWellKnown)
	}

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	return nil
}

// Stop marks the plugin as not ready and rejects new requests. Routes
// registered via ExtraRoute persist for the lifetime of the OPA process.
func (p *AuthZenPlugin) Stop(_ context.Context) {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

// Reconfigure updates the plugin configuration.
func (p *AuthZenPlugin) Reconfigure(_ context.Context, config any) {
	cfg, ok := config.(*Config)
	if !ok || cfg == nil {
		p.logger.WithFields(map[string]any{"config_type": fmt.Sprintf("%T", config)}).Error("AuthZEN reconfigure: unexpected or nil config type")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = *cfg
}

// AuthZEN Access Evaluation API request.
type evaluationRequest struct {
	Subject  json.RawMessage `json:"subject,omitempty"`
	Resource json.RawMessage `json:"resource,omitempty"`
	Action   json.RawMessage `json:"action,omitempty"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// AuthZEN Access Evaluation API response.
type evaluationResponse struct {
	Decision bool            `json:"decision"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// evaluationSemantic controls batch execution behavior (Section 7.1.2.1).
type evaluationSemantic string

const (
	semanticExecuteAll          evaluationSemantic = "execute_all"
	semanticDenyOnFirstDeny     evaluationSemantic = "deny_on_first_deny"
	semanticPermitOnFirstPermit evaluationSemantic = "permit_on_first_permit"
)

// evaluationsOptions holds the options for batch evaluations (Section 7.1.2).
type evaluationsOptions struct {
	EvaluationsSemantic evaluationSemantic `json:"evaluations_semantic,omitempty"`
}

// evaluationsRequest is the batch request body for POST /access/v1/evaluations (Section 7.1).
type evaluationsRequest struct {
	Subject     json.RawMessage     `json:"subject,omitempty"`
	Resource    json.RawMessage     `json:"resource,omitempty"`
	Action      json.RawMessage     `json:"action,omitempty"`
	Context     json.RawMessage     `json:"context,omitempty"`
	Evaluations []evaluationRequest `json:"evaluations,omitempty"`
	Options     *evaluationsOptions `json:"options,omitempty"`
}

// evaluationsResponse is the batch response body (Section 7.2).
type evaluationsResponse struct {
	Evaluations []evaluationResponse `json:"evaluations"`
}

// pdpMetadata is the PDP metadata response body (Section 9).
type pdpMetadata struct {
	PolicyDecisionPoint       string   `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string   `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string   `json:"access_evaluations_endpoint"`
	SearchSubjectEndpoint     string   `json:"search_subject_endpoint,omitempty"`
	SearchResourceEndpoint    string   `json:"search_resource_endpoint,omitempty"`
	SearchActionEndpoint      string   `json:"search_action_endpoint,omitempty"`
	Capabilities              []string `json:"capabilities,omitempty"`
}

// AuthZEN Search API request (Section 8.1/8.2/8.3).
type searchRequest struct {
	Subject  json.RawMessage `json:"subject,omitempty"`
	Resource json.RawMessage `json:"resource,omitempty"`
	Action   json.RawMessage `json:"action,omitempty"`
	Context  json.RawMessage `json:"context,omitempty"`
	Page     *pageRequest    `json:"page,omitempty"`
}

// pageRequest is the AuthZEN paginated request page object (Section 8.5.1).
type pageRequest struct {
	Token      string          `json:"token,omitempty"`
	Limit      *int            `json:"limit,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// AuthZEN Search API response (Section 8.4).
type searchResponse struct {
	Page    *pageResponse   `json:"page,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	Results []any           `json:"results"`
}

// pageResponse is the AuthZEN paginated response page object (Section 8.5.2).
type pageResponse struct {
	NextToken string `json:"next_token"`
	Count     *int   `json:"count,omitempty"`
	Total     *int   `json:"total,omitempty"`
}

// pageToken is the decoded form of an opaque pagination token. The hash binds
// a token to the request that produced it, so callers cannot mutate query
// entities between pages (Section 8.5: PDP SHOULD return an error in that
// case).
type pageToken struct {
	Offset int    `json:"o"`
	Hash   string `json:"h"`
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func unmarshalJSONObject(raw json.RawMessage) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	return obj, obj != nil
}

func hasStringField(obj map[string]any, field string) bool {
	value, ok := obj[field]
	if !ok {
		return false
	}
	_, ok = value.(string)
	return ok
}

// normalizePropertiesField enforces that, when an entity's optional
// `properties` member is present, it is a JSON object (Section 5 of the
// AuthZEN spec defines `properties` as OPTIONAL with an object value).
// JSON null is normalized away — it is deleted from obj in place so
// downstream code sees the field as absent (Section 11.5 recommends
// senders omit nulls; we accept and normalize them for forward
// compatibility). Returns an empty string on success, or a validation
// error message when `properties` is present but not an object. The
// function mutates obj; callers pass it by reference deliberately.
func normalizePropertiesField(obj map[string]any, name string) string {
	value, ok := obj["properties"]
	if !ok {
		return ""
	}
	if value == nil {
		// JSON null. The spec recommends omitting nulls
		// (Section 11.5) but accepting them is forward-compatible.
		delete(obj, "properties")
		return ""
	}
	if _, ok := value.(map[string]any); !ok {
		return fmt.Sprintf("%s.properties must be a JSON object", name)
	}
	return ""
}

// isJSONNull returns true if raw represents a JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 4 && string(raw) == "null"
}

// validateObject unmarshals raw JSON and checks it is a non-null JSON object.
// Returns the parsed map and an empty string on success, or nil and an error
// message describing why validation failed.
func validateObject(raw json.RawMessage, name string) (map[string]any, string) {
	obj, ok := unmarshalJSONObject(raw)
	if !ok {
		return nil, fmt.Sprintf("%s must be a JSON object", name)
	}
	return obj, ""
}

// buildInput unmarshals the raw JSON fields into a map suitable for OPA input.
// It validates the information model constraints from the AuthZEN specification
// (Section 5): subject requires string "type" and "id", action requires string
// "name", resource requires string "type" and "id", and context (if present and
// non-null) must be a JSON object.
func buildInput(subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}

	subjectVal, errMsg := validateObject(subject, "subject")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(subjectVal, "type") {
		return nil, "subject.type is required and must be a string"
	}
	if !hasStringField(subjectVal, "id") {
		return nil, "subject.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(subjectVal, "subject"); errMsg != "" {
		return nil, errMsg
	}
	input["subject"] = subjectVal

	actionVal, errMsg := validateObject(action, "action")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(actionVal, "name") {
		return nil, "action.name is required and must be a string"
	}
	if errMsg := normalizePropertiesField(actionVal, "action"); errMsg != "" {
		return nil, errMsg
	}
	input["action"] = actionVal

	resourceVal, errMsg := validateObject(resource, "resource")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(resourceVal, "type") {
		return nil, "resource.type is required and must be a string"
	}
	if !hasStringField(resourceVal, "id") {
		return nil, "resource.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(resourceVal, "resource"); errMsg != "" {
		return nil, errMsg
	}
	input["resource"] = resourceVal

	// context is OPTIONAL (Section 5). JSON null is treated as absent.
	if ctx != nil && !isJSONNull(ctx) {
		ctxVal, errMsg := validateObject(ctx, "context")
		if errMsg != "" {
			return nil, errMsg
		}
		input["context"] = ctxVal
	}

	return input, ""
}

// buildSearchInput assembles the OPA input map for a Search API request
// (Section 8). The kind selects which entity is the search target: that
// entity requires only "type" (or "name" for Action) and may omit the
// identifier; the remaining entities are validated as for Access Evaluation.
func buildSearchInput(kind searchKind, subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}

	// Subject: required for Resource/Action Search (full), partial for Subject Search.
	if subject == nil || isJSONNull(subject) {
		return nil, "subject is required"
	}
	subjectVal, errMsg := validateObject(subject, "subject")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(subjectVal, "type") {
		return nil, "subject.type is required and must be a string"
	}
	if kind == searchSubject {
		// Spec Section 8.1: subject.id SHOULD be omitted, and if present MUST be ignored.
		delete(subjectVal, "id")
	} else if !hasStringField(subjectVal, "id") {
		return nil, "subject.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(subjectVal, "subject"); errMsg != "" {
		return nil, errMsg
	}
	input["subject"] = subjectVal

	// Action: required for Subject/Resource Search; omitted for Action Search.
	if kind != searchAction {
		if action == nil || isJSONNull(action) {
			return nil, "action is required"
		}
		actionVal, errMsg := validateObject(action, "action")
		if errMsg != "" {
			return nil, errMsg
		}
		if !hasStringField(actionVal, "name") {
			return nil, "action.name is required and must be a string"
		}
		if errMsg := normalizePropertiesField(actionVal, "action"); errMsg != "" {
			return nil, errMsg
		}
		input["action"] = actionVal
	}
	// Section 10.1.2 requires receivers to ignore unknown fields; a stray
	// "action" key in an Action Search request is silently discarded.

	// Resource: required for Subject/Action Search (full), partial for Resource Search.
	if resource == nil || isJSONNull(resource) {
		return nil, "resource is required"
	}
	resourceVal, errMsg := validateObject(resource, "resource")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(resourceVal, "type") {
		return nil, "resource.type is required and must be a string"
	}
	if kind == searchResource {
		// Spec Section 8.2: resource.id SHOULD be omitted, and if present MUST be ignored.
		delete(resourceVal, "id")
	} else if !hasStringField(resourceVal, "id") {
		return nil, "resource.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(resourceVal, "resource"); errMsg != "" {
		return nil, errMsg
	}
	input["resource"] = resourceVal

	if ctx != nil && !isJSONNull(ctx) {
		ctxVal, errMsg := validateObject(ctx, "context")
		if errMsg != "" {
			return nil, errMsg
		}
		input["context"] = ctxVal
	}

	return input, ""
}

// mergeField returns the override if present and non-null, otherwise the default (Section 7.1.1).
// A JSON `null` value is treated as absent. If both are null, nil is returned
// so that the required-field check catches the missing value.
func mergeField(deflt, override json.RawMessage) json.RawMessage {
	if len(override) > 0 && !isJSONNull(override) {
		return override
	}
	if len(deflt) > 0 && !isJSONNull(deflt) {
		return deflt
	}
	return nil
}

// evalErrorResponse builds a per-evaluation error response (Section 7.2.1).
func evalErrorResponse(status int, message string) evaluationResponse {
	errCtx, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"status":  status,
			"message": message,
		},
	})
	return evaluationResponse{Decision: false, Context: errCtx}
}

func (p *AuthZenPlugin) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	// Echo X-Request-ID if present (Section 10.1.3). Must be set before
	// any early return so it appears even on error responses.
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	p.mu.RLock()
	stopped := p.stopped
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}

	// Content-Type: application/json is required (Section 10.1).
	if ct := r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	// Limit request body size to protect against DoS (Section 11.7).
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req evaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// subject, action, resource are required (Section 6.1).
	// A JSON null value is treated the same as absent.
	if req.Subject == nil || isJSONNull(req.Subject) ||
		req.Action == nil || isJSONNull(req.Action) ||
		req.Resource == nil || isJSONNull(req.Resource) {
		jsonError(w, "subject, action, and resource are required", http.StatusBadRequest)
		return
	}

	input, errMsg := buildInput(req.Subject, req.Action, req.Resource, req.Context)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	decision, path, decisionRule, err := p.eval(r.Context(), input)
	if err != nil {
		p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "error": err}).Error("AuthZEN evaluation error")
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}

	p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "decision": decision, "input": input}).Debug("AuthZEN evaluation")

	resp := evaluationResponse{
		Decision: decision,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("AuthZEN evaluation: failed to encode response: %v", err)
	}
}

func (p *AuthZenPlugin) eval(ctx context.Context, input map[string]any) (bool, string, string, error) {
	return p.evalWithTxn(ctx, nil, input)
}

// evalWithTxn evaluates a policy query with an optional existing transaction.
func (p *AuthZenPlugin) evalWithTxn(ctx context.Context, txn storage.Transaction, input map[string]any) (bool, string, string, error) {
	p.mu.RLock()
	path := p.cfg.Path
	decisionRule := p.cfg.Decision
	p.mu.RUnlock()

	val, err := p.evalRuleWithTxn(ctx, txn, input, path, decisionRule)
	if err != nil {
		return false, path, decisionRule, err
	}
	decision, _ := val.(bool)
	return decision, path, decisionRule, nil
}

// evalRuleWithTxn evaluates an arbitrary rule under the configured package
// path and returns the raw value. Used by both the Access Evaluation and
// Search handlers. An optional existing transaction may be passed; if nil,
// a fresh one is created and aborted on return.
func (p *AuthZenPlugin) evalRuleWithTxn(ctx context.Context, txn storage.Transaction, input map[string]any, path, rule string) (any, error) {
	var err error
	if txn == nil {
		txn, err = p.manager.Store.NewTransaction(ctx, storage.TransactionParams{})
		if err != nil {
			return nil, fmt.Errorf("creating transaction: %w", err)
		}
		defer p.manager.Store.Abort(ctx, txn)
	}

	queryPath := fmt.Sprintf("data.%s.%s", strings.ReplaceAll(path, "/", "."), rule)

	r := rego.New(
		rego.Compiler(p.manager.GetCompiler()),
		rego.Store(p.manager.Store),
		rego.Transaction(txn),
		rego.Input(input),
		rego.Query(queryPath),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	return rs[0].Expressions[0].Value, nil
}

// Access Evaluations API handler (Section 7).
func (p *AuthZenPlugin) handleEvaluations(w http.ResponseWriter, r *http.Request) {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	p.mu.RLock()
	stopped := p.stopped
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	// Limit request body size to protect against DoS (Section 11.7).
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req evaluationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Backward compatibility (Section 7.1): if evaluations is absent or empty,
	// behave as a single evaluation.
	if len(req.Evaluations) == 0 {
		if req.Subject == nil || isJSONNull(req.Subject) ||
			req.Action == nil || isJSONNull(req.Action) ||
			req.Resource == nil || isJSONNull(req.Resource) {
			jsonError(w, "subject, action, and resource are required", http.StatusBadRequest)
			return
		}
		input, errMsg := buildInput(req.Subject, req.Action, req.Resource, req.Context)
		if errMsg != "" {
			jsonError(w, errMsg, http.StatusBadRequest)
			return
		}
		decision, path, decisionRule, err := p.eval(r.Context(), input)
		if err != nil {
			p.logger.Error("AuthZEN evaluation error: path=%s.%s error=%v", path, decisionRule, err)
			jsonError(w, "evaluation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(evaluationsResponse{Evaluations: []evaluationResponse{{Decision: decision}}}); err != nil {
			p.logger.Error("AuthZEN evaluations: failed to encode response: %v", err)
		}
		return
	}

	// Limit the number of evaluations to protect against resource
	// exhaustion (Section 11.7).
	if len(req.Evaluations) > maxBatchSize {
		jsonError(w, fmt.Sprintf("evaluations array exceeds maximum size of %d", maxBatchSize), http.StatusRequestEntityTooLarge)
		return
	}

	// Determine evaluation semantic (Section 7.1.2.1).
	semantic := semanticExecuteAll
	if req.Options != nil && req.Options.EvaluationsSemantic != "" {
		switch req.Options.EvaluationsSemantic {
		case semanticExecuteAll, semanticDenyOnFirstDeny, semanticPermitOnFirstPermit:
			semantic = req.Options.EvaluationsSemantic
		default:
			jsonError(w, "unsupported evaluations_semantic", http.StatusBadRequest)
			return
		}
	}

	// Create a single transaction for the entire batch.
	txn, err := p.manager.Store.NewTransaction(r.Context(), storage.TransactionParams{})
	if err != nil {
		p.logger.Error("AuthZEN batch evaluation: failed to create transaction: %v", err)
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}
	defer p.manager.Store.Abort(r.Context(), txn)

	results := make([]evaluationResponse, 0, len(req.Evaluations))

	for _, item := range req.Evaluations {
		merged := evaluationRequest{
			Subject:  mergeField(req.Subject, item.Subject),
			Resource: mergeField(req.Resource, item.Resource),
			Action:   mergeField(req.Action, item.Action),
			Context:  mergeField(req.Context, item.Context),
		}

		if merged.Subject == nil || merged.Action == nil || merged.Resource == nil {
			results = append(results, evalErrorResponse(400, "subject, action, and resource are required"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		input, errMsg := buildInput(merged.Subject, merged.Action, merged.Resource, merged.Context)
		if errMsg != "" {
			results = append(results, evalErrorResponse(400, errMsg))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		decision, path, decisionRule, err := p.evalWithTxn(r.Context(), txn, input)
		if err != nil {
			p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "error": err}).Error("AuthZEN batch evaluation error")
			results = append(results, evalErrorResponse(500, "evaluation failed"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "decision": decision}).Debug("AuthZEN batch evaluation")

		if semantic == semanticDenyOnFirstDeny && !decision {
			// Short-circuit: include reason in context (Section 7.1.2.1).
			results = append(results, evaluationResponse{
				Decision: false,
				Context:  json.RawMessage(`{"code":"200","reason":"deny_on_first_deny"}`),
			})
			break
		}
		if semantic == semanticPermitOnFirstPermit && decision {
			results = append(results, evaluationResponse{
				Decision: true,
				Context:  json.RawMessage(`{"code":"200","reason":"permit_on_first_permit"}`),
			})
			break
		}

		results = append(results, evaluationResponse{Decision: decision})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(evaluationsResponse{Evaluations: results}); err != nil {
		p.logger.Error("AuthZEN evaluations: failed to encode response: %v", err)
	}
}

// PDP Metadata endpoint (Section 9).
func (p *AuthZenPlugin) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	// Echo X-Request-ID if present (Section 10.1.3).
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	p.mu.RLock()
	stopped := p.stopped
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}

	// Determine the scheme and host for constructing the base URL.
	// NOTE: The Host header and X-Forwarded-* headers are trusted here.
	// In production, this endpoint should be behind a reverse proxy that
	// overrides or sanitizes these headers. If exposed directly, a client
	// could spoof these values to influence the metadata response.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	}
	host := r.Host
	if host == "" {
		host = r.Header.Get("X-Forwarded-Host")
	}
	if host == "" {
		host = "localhost"
	}
	base := fmt.Sprintf("%s://%s", scheme, host)
	metadata := pdpMetadata{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpoint: base + "/access/v1/evaluations",
	}

	// Spec Section 9: omit search_*_endpoint when the corresponding rule is
	// unconfigured. Absence is the PEP's signal that the PDP is not capable.
	p.mu.RLock()
	search := p.cfg.Search
	p.mu.RUnlock()
	if search.Subject != "" {
		metadata.SearchSubjectEndpoint = base + "/access/v1/search/subject"
	}
	if search.Resource != "" {
		metadata.SearchResourceEndpoint = base + "/access/v1/search/resource"
	}
	if search.Action != "" {
		metadata.SearchActionEndpoint = base + "/access/v1/search/action"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		p.logger.Error("AuthZEN well-known: failed to encode response: %v", err)
	}
}

// handleSubjectSearch serves POST /access/v1/search/subject (Section 8.1).
func (p *AuthZenPlugin) handleSubjectSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchSubject)
}

// handleResourceSearch serves POST /access/v1/search/resource (Section 8.2).
func (p *AuthZenPlugin) handleResourceSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchResource)
}

// handleActionSearch serves POST /access/v1/search/action (Section 8.3).
func (p *AuthZenPlugin) handleActionSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchAction)
}

// handleSearch implements the shared lifecycle for all three Search APIs:
// request validation (Section 8), single Rego evaluation, deterministic
// ordering, and stateless pagination over the resulting entity list
// (Section 8.5). The kind selects per-endpoint rules and the configured
// target rule.
func (p *AuthZenPlugin) handleSearch(w http.ResponseWriter, r *http.Request, kind searchKind) {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	p.mu.RLock()
	stopped := p.stopped
	path := p.cfg.Path
	search := p.cfg.Search
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}

	ruleName := searchRuleName(search, kind)
	if ruleName == "" {
		jsonError(w, "search endpoint not configured", http.StatusNotImplemented)
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req searchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	input, errMsg := buildSearchInput(kind, req.Subject, req.Action, req.Resource, req.Context)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	limit, errMsg := resolveSearchLimit(req.Page, search.MaxLimit)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	// Bind subsequent pages to the normalized search input (Section 8.5).
	// Using the post-buildSearchInput map ensures that fields the spec says
	// MUST be ignored (e.g. subject.id on Subject Search) cannot break a
	// follow-up page just because the client did or didn't echo them back.
	reqHash := searchRequestHash(input, limit)
	offset := 0
	if req.Page != nil && req.Page.Token != "" {
		tok, err := decodePageToken(req.Page.Token)
		if err != nil {
			jsonError(w, "invalid page token", http.StatusBadRequest)
			return
		}
		if tok.Hash != reqHash {
			jsonError(w, "page token does not match request", http.StatusBadRequest)
			return
		}
		offset = tok.Offset
	}

	raw, err := p.evalRuleWithTxn(r.Context(), nil, input, path, ruleName)
	if err != nil {
		p.logger.WithFields(map[string]any{"path": path, "rule": ruleName, "error": err}).Error("AuthZEN search error")
		jsonError(w, "search evaluation failed", http.StatusInternalServerError)
		return
	}

	entities, errMsg := normaliseSearchResults(raw, kind)
	if errMsg != "" {
		p.logger.WithFields(map[string]any{"path": path, "rule": ruleName, "error": errMsg}).Error("AuthZEN search: invalid policy result")
		jsonError(w, "search evaluation failed", http.StatusInternalServerError)
		return
	}

	total := len(entities)
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	page := entities[offset:end]
	pageCount := len(page)

	resp := searchResponse{Results: page}
	// next_token is REQUIRED whenever the response does not contain the
	// entire result set (Section 8.5.2). Always emit a page object so
	// pagination state is unambiguous.
	nextToken := ""
	if end < total {
		nextToken = encodePageToken(pageToken{Offset: end, Hash: reqHash})
	}
	totalCopy := total
	countCopy := pageCount
	resp.Page = &pageResponse{
		NextToken: nextToken,
		Count:     &countCopy,
		Total:     &totalCopy,
	}

	p.logger.WithFields(map[string]any{
		"path":     path,
		"rule":     ruleName,
		"kind":     kind,
		"total":    total,
		"returned": pageCount,
		"offset":   offset,
	}).Debug("AuthZEN search")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("AuthZEN search: failed to encode response: %v", err)
	}
}

// searchRuleName returns the configured Rego rule for the given search kind,
// or the empty string if the endpoint is disabled.
func searchRuleName(s SearchConfig, kind searchKind) string {
	switch kind {
	case searchSubject:
		return s.Subject
	case searchResource:
		return s.Resource
	case searchAction:
		return s.Action
	}
	return ""
}

// resolveSearchLimit applies request and configuration bounds to the page
// limit. A negative limit is rejected; an unset limit means "no per-page
// cap" beyond the configured maximum.
func resolveSearchLimit(page *pageRequest, configMax int) (int, string) {
	maxLimit := configMax
	if maxLimit <= 0 {
		maxLimit = defaultSearchMaxLimit
	}
	if page == nil || page.Limit == nil {
		return maxLimit, ""
	}
	if *page.Limit < 0 {
		return 0, "page.limit must be non-negative"
	}
	if *page.Limit == 0 || *page.Limit > maxLimit {
		return maxLimit, ""
	}
	return *page.Limit, ""
}

// normaliseSearchResults coerces the Rego query result to a JSON-serializable
// list of entity objects. The plugin accepts either an array or a set; each
// element must itself be a JSON object so callers can rely on the AuthZEN
// information model (Section 5). Each entity is further required to carry
// the identifying field for the searched-for type (Section 8.4: results
// MUST contain only entities of the type being searched for): `type` for
// Subject/Resource Search and `name` for Action Search. Results are sorted
// by a stable identifier key so pagination is deterministic.
func normaliseSearchResults(raw any, kind searchKind) ([]any, string) {
	if raw == nil {
		return []any{}, ""
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Sprintf("search rule must return an array; got %T", raw)
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Sprintf("search rule must return objects; got %T", item)
		}
		if errMsg := validateSearchEntity(obj, kind); errMsg != "" {
			return nil, errMsg
		}
		out = append(out, obj)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return searchEntityKey(out[i].(map[string]any), kind) < searchEntityKey(out[j].(map[string]any), kind)
	})
	return out, ""
}

// validateSearchEntity enforces Section 8.4 ("results MUST contain only
// entities of the type being searched for") together with the entity
// shape requirements from Section 5 of the Information Model:
//
//   - Subject: REQUIRED `type` and `id`, both strings.
//   - Resource: REQUIRED `type` and `id`, both strings.
//   - Action: REQUIRED `name`, string. (Action has no `id`.)
//
// A policy that omits one of these fields would return an entity that the
// PEP could not feed back into Access Evaluation (since `id`/`name` is
// also required there), so we reject it as a policy-authoring error.
func validateSearchEntity(entity map[string]any, kind searchKind) string {
	if kind == searchAction {
		if !hasStringField(entity, "name") {
			return "action search rule must return entities with a string `name` field"
		}
		return ""
	}
	prefix := "subject"
	if kind == searchResource {
		prefix = "resource"
	}
	if !hasStringField(entity, "type") {
		return prefix + " search rule must return entities with a string `type` field"
	}
	if !hasStringField(entity, "id") {
		return prefix + " search rule must return entities with a string `id` field"
	}
	return ""
}

// searchEntityKey extracts a stable string key for an entity, used solely
// for ordering between pages. Falls back to the JSON encoding when the
// natural identifier is absent.
func searchEntityKey(entity map[string]any, kind searchKind) string {
	if kind == searchAction {
		if name, ok := entity["name"].(string); ok {
			return name
		}
	} else {
		t, _ := entity["type"].(string)
		id, _ := entity["id"].(string)
		if t != "" || id != "" {
			return t + "\x00" + id
		}
	}
	b, _ := json.Marshal(entity)
	return string(b)
}

// searchRequestHash binds a pagination token to the normalized search input
// and effective page limit. Hashing the post-validation input (rather than
// the raw request body) keeps the hash stable across spec-ignored fields
// such as subject.id on Subject Search, while still detecting changes to
// any field that affects the query semantics. Section 8.5 requires the PDP
// to detect when callers change parameters mid-pagination.
func searchRequestHash(input map[string]any, limit int) string {
	h := sha256.New()
	// json.Marshal sorts map keys alphabetically, so equivalent inputs
	// always produce the same byte sequence regardless of YAML/Rego order.
	canon, _ := json.Marshal(input)
	_, _ = h.Write(canon)
	_, _ = fmt.Fprintf(h, "\x00limit\x00%d\x00", limit)
	return hex.EncodeToString(h.Sum(nil))
}

// encodePageToken returns a URL-safe base64 representation of the page
// token. The token is opaque to clients (Section 8.5).
func encodePageToken(t pageToken) string {
	b, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodePageToken reverses encodePageToken, returning an error if the token
// is not a valid base64-encoded pageToken JSON object.
func decodePageToken(s string) (pageToken, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageToken{}, err
	}
	var t pageToken
	if err := json.Unmarshal(b, &t); err != nil {
		return pageToken{}, err
	}
	if t.Offset < 0 {
		return pageToken{}, fmt.Errorf("negative offset")
	}
	return t, nil
}
