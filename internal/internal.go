package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

	defaultAddr     = ":9292"
	defaultPath     = "authzen"
	defaultDecision = "allow"
)

// Config represents the plugin configuration.
type Config struct {
	Addr     string `json:"addr"`
	Path     string `json:"path"`
	Decision string `json:"decision"`
}

// Validate parses and validates the plugin configuration.
func Validate(_ *plugins.Manager, bs []byte) (*Config, error) {
	cfg := Config{
		Addr:     defaultAddr,
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
	manager  *plugins.Manager
	cfg      Config
	server   *http.Server
	mu       sync.Mutex
	logger   logging.Logger
	started  bool
}

// New creates a new AuthZenPlugin.
func New(m *plugins.Manager, cfg *Config) *AuthZenPlugin {
	return &AuthZenPlugin{
		manager: m,
		cfg:     *cfg,
		logger:  m.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
}

// Start starts the AuthZEN HTTP server.
func (p *AuthZenPlugin) Start(ctx context.Context) error {
	p.logger.Info("Starting AuthZEN plugin on %s", p.cfg.Addr)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", p.handleEvaluation)
	mux.HandleFunc("GET /.well-known/authzen-configuration", p.handleWellKnown)

	p.server = &http.Server{
		Handler: mux,
	}

	ln, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.started = true
	p.mu.Unlock()

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	go func() {
		if err := p.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger.Error("AuthZEN server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the AuthZEN HTTP server.
func (p *AuthZenPlugin) Stop(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server != nil {
		p.server.Shutdown(ctx)
	}
	p.started = false
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

func (p *AuthZenPlugin) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	// Echo X-Request-ID if present (Section 10.1.3).
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	var req evaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Build the input for OPA from the AuthZEN request.
	input := map[string]any{}
	if req.Subject != nil {
		var v any
		json.Unmarshal(req.Subject, &v)
		input["subject"] = v
	}
	if req.Resource != nil {
		var v any
		json.Unmarshal(req.Resource, &v)
		input["resource"] = v
	}
	if req.Action != nil {
		var v any
		json.Unmarshal(req.Action, &v)
		input["action"] = v
	}
	if req.Context != nil {
		var v any
		json.Unmarshal(req.Context, &v)
		input["context"] = v
	}

	decision, err := p.eval(r.Context(), input)
	if err != nil {
		p.logger.Error("Evaluation error: %v", err)
		http.Error(w, `{"error":"evaluation failed"}`, http.StatusInternalServerError)
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
	txn, err := p.manager.Store.NewTransaction(ctx, storage.TransactionParams{})
	if err != nil {
		return false, fmt.Errorf("creating transaction: %w", err)
	}
	defer p.manager.Store.Abort(ctx, txn)

	queryPath := fmt.Sprintf("data.%s.%s", strings.ReplaceAll(p.cfg.Path, "/", "."), p.cfg.Decision)

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
	p.logger.Debug("AuthZEN evaluation: path=%s.%s decision=%v input=%v", p.cfg.Path, p.cfg.Decision, decision, input)
}

// PDP Metadata endpoint (Section 9).
func (p *AuthZenPlugin) handleWellKnown(w http.ResponseWriter, _ *http.Request) {
	base := fmt.Sprintf("http://%s", p.cfg.Addr)
	metadata := map[string]string{
		"policy_decision_point":      base,
		"access_evaluation_endpoint": base + "/access/v1/evaluation",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
