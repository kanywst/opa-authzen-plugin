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
	Subject  json.RawMessage `json:"subject"`
	Resource json.RawMessage `json:"resource"`
	Action   json.RawMessage `json:"action"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// AuthZEN Access Evaluation API response.
type evaluationResponse struct {
	Decision bool            `json:"decision"`
	Context  json.RawMessage `json:"context,omitempty"`
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

	var req evaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Build the input for OPA from the AuthZEN request.
	input := map[string]any{}
	if req.Subject != nil {
		var v any
		if err := json.Unmarshal(req.Subject, &v); err != nil {
			jsonError(w, "invalid subject", http.StatusBadRequest)
			return
		}
		input["subject"] = v
	}
	if req.Resource != nil {
		var v any
		if err := json.Unmarshal(req.Resource, &v); err != nil {
			jsonError(w, "invalid resource", http.StatusBadRequest)
			return
		}
		input["resource"] = v
	}
	if req.Action != nil {
		var v any
		if err := json.Unmarshal(req.Action, &v); err != nil {
			jsonError(w, "invalid action", http.StatusBadRequest)
			return
		}
		input["action"] = v
	}
	if req.Context != nil {
		var v any
		if err := json.Unmarshal(req.Context, &v); err != nil {
			jsonError(w, "invalid context", http.StatusBadRequest)
			return
		}
		input["context"] = v
	}

	decision, err := p.eval(r.Context(), input)
	if err != nil {
		p.logger.Error("Evaluation error: %v", err)
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}

	// Log the decision.
	p.logDecision(r.Context(), input, decision)

	resp := evaluationResponse{
		Decision: decision,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *AuthZenPlugin) eval(ctx context.Context, input map[string]any) (bool, error) {
	p.mu.RLock()
	path := p.cfg.Path
	decisionRule := p.cfg.Decision
	p.mu.RUnlock()

	txn, err := p.manager.Store.NewTransaction(ctx, storage.TransactionParams{})
	if err != nil {
		return false, fmt.Errorf("creating transaction: %w", err)
	}
	defer p.manager.Store.Abort(ctx, txn)

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
		return false, fmt.Errorf("evaluating policy: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, nil
	}

	decision, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil
	}

	return decision, nil
}

func (p *AuthZenPlugin) logDecision(_ context.Context, input map[string]any, decision bool) {
	p.mu.RLock()
	path := p.cfg.Path
	dec := p.cfg.Decision
	p.mu.RUnlock()
	p.logger.Debug("AuthZEN evaluation: path=%s.%s decision=%v input=%v", path, dec, decision, input)
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
		"policy_decision_point":      base,
		"access_evaluation_endpoint": base + "/access/v1/evaluation",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
