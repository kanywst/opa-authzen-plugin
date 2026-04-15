package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
)

// Config represents the plugin configuration.
type Config struct {
	Path     string `json:"path"`
	Decision string `json:"decision"`
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
		p.logger.Error("AuthZEN reconfigure: unexpected or nil config type %T", config)
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
	SupportedCapabilities     []string `json:"supported_capabilities,omitempty"`
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// buildInput unmarshals the raw JSON fields into a map suitable for OPA input.
func buildInput(subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}

	var subjectVal any
	if err := json.Unmarshal(subject, &subjectVal); err != nil {
		return nil, "invalid subject"
	}
	input["subject"] = subjectVal

	var actionVal any
	if err := json.Unmarshal(action, &actionVal); err != nil {
		return nil, "invalid action"
	}
	input["action"] = actionVal

	var resourceVal any
	if err := json.Unmarshal(resource, &resourceVal); err != nil {
		return nil, "invalid resource"
	}
	input["resource"] = resourceVal

	if ctx != nil {
		var ctxVal any
		if err := json.Unmarshal(ctx, &ctxVal); err != nil {
			return nil, "invalid context"
		}
		input["context"] = ctxVal
	}

	return input, ""
}

// mergeField returns the override if present and non-null, otherwise the default (Section 7.1.1).
// A JSON `null` value is treated as absent. If both are null, nil is returned
// so that the required-field check catches the missing value.
func mergeField(deflt, override json.RawMessage) json.RawMessage {
	if len(override) > 0 && string(override) != "null" {
		return override
	}
	if len(deflt) > 0 && string(deflt) != "null" {
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
	if req.Subject == nil || req.Action == nil || req.Resource == nil {
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

	p.logger.Debug("AuthZEN evaluation: path=%s.%s decision=%v input=%v", path, decisionRule, decision, input)

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

	var err error
	if txn == nil {
		txn, err = p.manager.Store.NewTransaction(ctx, storage.TransactionParams{})
		if err != nil {
			return false, path, decisionRule, fmt.Errorf("creating transaction: %w", err)
		}
		defer p.manager.Store.Abort(ctx, txn)
	}

	queryPath := fmt.Sprintf("data.%s.%s", strings.ReplaceAll(path, "/", "."), decisionRule)

	r := rego.New(
		rego.Compiler(p.manager.GetCompiler()),
		rego.Store(p.manager.Store),
		rego.Transaction(txn),
		rego.Input(input),
		rego.Query(queryPath),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return false, path, decisionRule, fmt.Errorf("evaluating policy: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, path, decisionRule, nil
	}

	decision, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, path, decisionRule, nil
	}

	return decision, path, decisionRule, nil
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
		if req.Subject == nil || req.Action == nil || req.Resource == nil {
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
			p.logger.Error("AuthZEN batch evaluation error: path=%s.%s error=%v", path, decisionRule, err)
			results = append(results, evalErrorResponse(500, "evaluation failed"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		p.logger.Debug("AuthZEN batch evaluation: path=%s.%s decision=%v", path, decisionRule, decision)

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
		SupportedCapabilities:     []string{},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		p.logger.Error("AuthZEN well-known: failed to encode response: %v", err)
	}
}
