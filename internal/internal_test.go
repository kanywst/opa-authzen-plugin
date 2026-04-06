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
		{"json-patch rejected", "application/json-patch+json", http.StatusBadRequest},
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

// Batch Evaluations

func postEvaluations(p *AuthZenPlugin, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluations(w, req)
	return w
}

func decodeBatchResp(t *testing.T, w *httptest.ResponseRecorder) evaluationsResponse {
	t.Helper()
	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode batch response: %v\nbody: %s", err, w.Body.String())
	}
	return resp
}

func TestEvaluationsBatchAllAllow(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}},
			{"resource": {"type": "doc", "id": "2"}}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 evaluations, got %d", len(resp.Evaluations))
	}
	for i, e := range resp.Evaluations {
		if !e.Decision {
			t.Fatalf("evaluation[%d]: expected true", i)
		}
	}
}

func TestEvaluationsBatchAllDeny(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "bob"},
		"action": {"name": "read"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}},
			{"resource": {"type": "doc", "id": "2"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	for i, e := range resp.Evaluations {
		if e.Decision {
			t.Fatalf("evaluation[%d]: expected false", i)
		}
	}
}

func TestEvaluationsBatchMixed(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "bob"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false")
	}
}

func TestEvaluationsDefaultSubject(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"evaluations": [
			{"action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}},
			{"action": {"name": "write"}, "resource": {"type": "doc", "id": "2"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2, got %d", len(resp.Evaluations))
	}
	for i, e := range resp.Evaluations {
		if !e.Decision {
			t.Fatalf("evaluation[%d]: expected true (subject inherited)", i)
		}
	}
}

func TestEvaluationsOverrideSubject(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{},
			{"subject": {"type": "user", "id": "bob"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true (inherited alice)")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false (overridden to bob)")
	}
}

func TestEvaluationsDefaultContext(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.context.env == "prod"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"context": {"env": "prod"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}},
			{"resource": {"type": "doc", "id": "2"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	for i, e := range resp.Evaluations {
		if !e.Decision {
			t.Fatalf("evaluation[%d]: expected true (context inherited)", i)
		}
	}
}

func TestEvaluationsOverrideContext(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.context.env == "prod"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"context": {"env": "prod"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}},
			{"resource": {"type": "doc", "id": "2"}, "context": {"env": "staging"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true (inherited prod)")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false (overridden to staging)")
	}
}

func TestEvaluationsMissingRequiredFieldPerEval(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	// No top-level subject, second eval has no subject -> per-eval error
	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false (missing subject)")
	}
	if resp.Evaluations[1].Context == nil {
		t.Fatal("evaluation[1]: expected context with error")
	}
	var ctx map[string]any
	json.Unmarshal(resp.Evaluations[1].Context, &ctx)
	if ctx["error"] == nil {
		t.Fatal("evaluation[1]: expected context.error")
	}
}

func TestEvaluationsTopLevelDefaultSatisfiesRequired(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{},
			{}
		]
	}`)

	resp := decodeBatchResp(t, w)
	for i, e := range resp.Evaluations {
		if !e.Decision {
			t.Fatalf("evaluation[%d]: expected true (all defaults from top-level)", i)
		}
	}
}

func TestEvaluationsExecuteAll(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "execute_all"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "carol"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 3 {
		t.Fatalf("execute_all: expected 3 results, got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected false")
	}
	if !resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected true")
	}
	if resp.Evaluations[2].Decision {
		t.Fatal("evaluation[2]: expected false")
	}
}

func TestEvaluationsDenyOnFirstDeny(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("deny_on_first_deny: expected 2 results (short-circuit), got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false (first deny)")
	}
}

func TestEvaluationsDenyOnFirstDenyAllPermit(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected all 2 results (no short-circuit), got %d", len(resp.Evaluations))
	}
}

func TestEvaluationsPermitOnFirstPermit(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "permit_on_first_permit"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "carol"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("permit_on_first_permit: expected 2 results (short-circuit), got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected false")
	}
	if !resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected true (first permit)")
	}
}

func TestEvaluationsPermitOnFirstPermitAllDeny(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "permit_on_first_permit"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "carol"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected all 2 results (no short-circuit), got %d", len(resp.Evaluations))
	}
}

func TestEvaluationsInvalidSemantic(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"options": {"evaluations_semantic": "invalid_value"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}}
		]
	}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid semantic, got %d", w.Code)
	}
}

func TestEvaluationsBackwardCompatEmptyArray(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": []
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Plural endpoint returns batch response format even for single evaluation
	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation in batch, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("expected decision=true in backward-compat mode")
	}
}

func TestEvaluationsBackwardCompatNoArray(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"}
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Plural endpoint returns batch response format even for single evaluation
	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation in batch, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("expected decision=true in backward-compat mode")
	}
}

func TestEvaluationsBackwardCompatMissingRequired(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"}
	}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEvaluationsContentType(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	body := `{"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	p.handleEvaluations(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEvaluationsStoppedPlugin(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	p.Stop(context.Background())

	w := postEvaluations(p, `{"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestEvaluationsXRequestID(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	body := `{"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "batch-123")
	w := httptest.NewRecorder()
	p.handleEvaluations(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "batch-123" {
		t.Fatalf("expected X-Request-ID=batch-123, got %q", got)
	}
}

func TestEvaluationsInvalidBody(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluations(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEvaluationsResponseOmitsTopLevelDecision(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"evaluations": [
			{"resource": {"type": "doc", "id": "1"}}
		]
	}`)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["decision"]; ok {
		t.Fatal("batch response should not contain top-level 'decision' key")
	}
	if _, ok := raw["evaluations"]; !ok {
		t.Fatal("batch response must contain 'evaluations' key")
	}
}

func TestEvaluationsShortCircuitOnError(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	// deny_on_first_deny: second eval has missing subject (error = decision false) -> short-circuit
	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{},
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 results (short-circuit on error), got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("evaluation[0]: expected true")
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("evaluation[1]: expected false (error)")
	}
}

func TestWellKnownIncludesEvaluationsEndpoint(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	var metadata map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	expected := "http://localhost:8181/access/v1/evaluations"
	if metadata["access_evaluations_endpoint"] != expected {
		t.Fatalf("expected access_evaluations_endpoint=%s, got %s", expected, metadata["access_evaluations_endpoint"])
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
