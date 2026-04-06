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
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = *config.(*Config)
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

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// buildInput unmarshals the raw JSON fields into a map suitable for OPA input.
func buildInput(subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}
	var v any
	if err := json.Unmarshal(subject, &v); err != nil {
		return nil, "invalid subject"
	}
	input["subject"] = v
	if err := json.Unmarshal(action, &v); err != nil {
		return nil, "invalid action"
	}
	input["action"] = v
	if err := json.Unmarshal(resource, &v); err != nil {
		return nil, "invalid resource"
	}
	input["resource"] = v
	if ctx != nil {
		if err := json.Unmarshal(ctx, &v); err != nil {
			return nil, "invalid context"
		}
		input["context"] = v
	}
	return input, ""
}

// mergeField returns the override if non-nil, otherwise the default (Section 7.1.1).
func mergeField(deflt, override json.RawMessage) json.RawMessage {
	if override != nil {
		return override
	}
	return deflt
}

// evalErrorResponse builds a per-evaluation error response (Section 7.2.1).
// Per Section 10.2, error objects must contain "code" and "message" fields.
func evalErrorResponse(code string, message string) evaluationResponse {
	errCtx, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    code,
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
	json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(evaluationResponse{Decision: decision})
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
			results = append(results, evalErrorResponse("invalid_request", "subject, action, and resource are required"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		input, errMsg := buildInput(merged.Subject, merged.Action, merged.Resource, merged.Context)
		if errMsg != "" {
			results = append(results, evalErrorResponse("invalid_request", errMsg))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		decision, path, decisionRule, err := p.evalWithTxn(r.Context(), txn, input)
		if err != nil {
			p.logger.Error("AuthZEN batch evaluation error: path=%s.%s error=%v", path, decisionRule, err)
			results = append(results, evalErrorResponse("evaluation_error", "evaluation failed"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		p.logger.Debug("AuthZEN batch evaluation: path=%s.%s decision=%v", path, decisionRule, decision)
		results = append(results, evaluationResponse{Decision: decision})

		if semantic == semanticDenyOnFirstDeny && !decision {
			break
		}
		if semantic == semanticPermitOnFirstPermit && decision {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evaluationsResponse{Evaluations: results})
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
	metadata := map[string]string{
		"policy_decision_point":       base,
		"access_evaluation_endpoint":  base + "/access/v1/evaluation",
		"access_evaluations_endpoint": base + "/access/v1/evaluations",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
