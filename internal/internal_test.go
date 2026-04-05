package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func testPlugin(t *testing.T, module string) *AuthZenPlugin {
	t.Helper()

	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	if err := store.UpsertPolicy(ctx, txn, "test.rego", []byte(module)); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, txn); err != nil {
		t.Fatal(err)
	}

	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Path:     defaultPath,
		Decision: defaultDecision,
	}

	return New(m, cfg)
}

func TestEvaluationAllow(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice@example.com"
	`)

	body := `{
		"subject": {"type": "user", "id": "alice@example.com"},
		"resource": {"type": "account", "id": "123"},
		"action": {"name": "can_read"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true")
	}
}

func TestEvaluationDeny(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice@example.com"
	`)

	body := `{
		"subject": {"type": "user", "id": "bob@example.com"},
		"resource": {"type": "account", "id": "123"},
		"action": {"name": "can_read"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false")
	}
}

func TestEvaluationWithContext(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if {
			input.subject.id == "alice@example.com"
			input.context.time == "2026-03-30T12:00:00Z"
		}
	`)

	body := `{
		"subject": {"type": "user", "id": "alice@example.com"},
		"resource": {"type": "account", "id": "123"},
		"action": {"name": "can_read"},
		"context": {"time": "2026-03-30T12:00:00Z"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true")
	}
}

func TestEvaluationDispatchByResourceAction(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if {
			input.resource.type == "todolist"
			input.action.name == "create"
			input.subject.properties.role == "editor"
		}
	`)

	body := `{
		"subject": {"type": "user", "id": "alice", "properties": {"role": "editor"}},
		"resource": {"type": "todolist", "id": "1"},
		"action": {"name": "create"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true")
	}
}

func TestWellKnown(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata["policy_decision_point"] != "http://localhost:8181" {
		t.Fatalf("unexpected pdp: %s", metadata["policy_decision_point"])
	}
	if metadata["access_evaluation_endpoint"] != "http://localhost:8181/access/v1/evaluation" {
		t.Fatalf("unexpected endpoint: %s", metadata["access_evaluation_endpoint"])
	}
}

func TestXRequestIDEcho(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	body := `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-req-123")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "test-req-123" {
		t.Fatalf("expected X-Request-ID=test-req-123, got %q", got)
	}
}

func TestInvalidBody(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMissingRequiredFields(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	tests := []struct {
		name string
		body string
	}{
		{"missing subject", `{"action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`},
		{"missing action", `{"subject": {"type": "user", "id": "bob"}, "resource": {"type": "doc", "id": "1"}}`},
		{"missing resource", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}}`},
		{"all missing", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.handleEvaluation(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestContentTypeValidation(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	body := `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`

	tests := []struct {
		name        string
		contentType string
		wantCode    int
	}{
		{"text/plain rejected", "text/plain", http.StatusBadRequest},
		{"empty rejected", "", http.StatusBadRequest},
		{"application/json accepted", "application/json", http.StatusOK},
		{"application/json charset accepted", "application/json; charset=utf-8", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			p.handleEvaluation(w, req)

			if w.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestStoppedPluginRejectsEvaluation(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	p.Stop(context.Background())

	body := `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("X-Request-ID", "stopped-req-456")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	// X-Request-ID must be echoed even on 503 (AuthZEN Section 10.1.3).
	if got := w.Header().Get("X-Request-ID"); got != "stopped-req-456" {
		t.Fatalf("expected X-Request-ID=stopped-req-456, got %q", got)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestStoppedPluginRejectsWellKnown(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	p.Stop(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestWellKnownXForwardedHost(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = ""
	req.Header.Set("X-Forwarded-Host", "pdp.example.com")
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata["policy_decision_point"] != "http://pdp.example.com" {
		t.Fatalf("unexpected pdp: %s", metadata["policy_decision_point"])
	}
}

func TestWellKnownXForwardedProto(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "pdp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata["policy_decision_point"] != "https://pdp.example.com" {
		t.Fatalf("unexpected pdp: %s", metadata["policy_decision_point"])
	}
}

func TestWellKnownXForwardedProtoInvalid(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "pdp.example.com"
	req.Header.Set("X-Forwarded-Proto", "javascript")
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata["policy_decision_point"] != "http://pdp.example.com" {
		t.Fatalf("expected invalid proto to be ignored, got pdp: %s", metadata["policy_decision_point"])
	}
}

func TestWellKnownEmptyHostFallback(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = ""
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata["policy_decision_point"] != "http://localhost" {
		t.Fatalf("unexpected pdp: %s", metadata["policy_decision_point"])
	}
}

func TestErrorResponseContentType(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestStartRegistersExtraRoutes(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	status := p.manager.PluginStatus()
	ps, ok := status[PluginName]
	if !ok {
		t.Fatal("expected plugin status to be registered")
	}
	if ps.State != plugins.StateOK {
		t.Fatalf("expected StateOK, got %v", ps.State)
	}
}

func TestDoubleStartDoesNotPanic(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	// Second Start must not panic from duplicate ExtraRoute registration.
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("second Start failed: %v", err)
	}
}

func TestStartAfterStopResetsState(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.Stop(context.Background())

	// After Stop, requests should be rejected.
	body := `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after Stop, got %d", w.Code)
	}

	// After Start again, requests should be accepted.
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	p.handleEvaluation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after restart, got %d", w.Code)
	}
}
