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
	json.Unmarshal(w.Body.Bytes(), &resp)
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
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Decision {
		t.Fatal("expected decision=true")
	}
}

func TestWellKnown(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	p.cfg.Addr = "localhost:9292"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metadata map[string]string
	json.Unmarshal(w.Body.Bytes(), &metadata)

	if metadata["policy_decision_point"] != "http://localhost:9292" {
		t.Fatalf("unexpected pdp: %s", metadata["policy_decision_point"])
	}
	if metadata["access_evaluation_endpoint"] != "http://localhost:9292/access/v1/evaluation" {
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
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
