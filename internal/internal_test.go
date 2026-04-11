package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

const module = `
	package authzen
	default allow = false
	allow if input.subject.properties.role == "admin"
	allow if input.action.name == "read" {
		input.subject.id != ""
	}
`

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
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q", ct)
	}

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata.PolicyDecisionPoint != "http://localhost:8181" {
		t.Fatalf("unexpected pdp: %s", metadata.PolicyDecisionPoint)
	}
	if metadata.AccessEvaluationEndpoint != "http://localhost:8181/access/v1/evaluation" {
		t.Fatalf("unexpected endpoint: %s", metadata.AccessEvaluationEndpoint)
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

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata.PolicyDecisionPoint != "http://pdp.example.com" {
		t.Fatalf("unexpected pdp: %s", metadata.PolicyDecisionPoint)
	}
}

func TestWellKnownXForwardedProto(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "pdp.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata.PolicyDecisionPoint != "https://pdp.example.com" {
		t.Fatalf("unexpected pdp: %s", metadata.PolicyDecisionPoint)
	}
}

func TestWellKnownXForwardedProtoInvalid(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "pdp.example.com"
	req.Header.Set("X-Forwarded-Proto", "javascript")
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata.PolicyDecisionPoint != "http://pdp.example.com" {
		t.Fatalf("expected invalid proto to be ignored, got pdp: %s", metadata.PolicyDecisionPoint)
	}
}

func TestWellKnownEmptyHostFallback(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = ""
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	if metadata.PolicyDecisionPoint != "http://localhost" {
		t.Fatalf("unexpected pdp: %s", metadata.PolicyDecisionPoint)
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
	if err := json.Unmarshal(resp.Evaluations[1].Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context: %v", err)
	}
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
	// Verify reason context is included on the short-circuit deny (Section 7.1.2.1).
	if resp.Evaluations[1].Context == nil {
		t.Fatal("evaluation[1]: expected context with reason on short-circuit deny")
	}
	var ctx map[string]any
	if err := json.Unmarshal(resp.Evaluations[1].Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context: %v", err)
	}
	if ctx["reason"] != "deny_on_first_deny" {
		t.Fatalf("evaluation[1]: expected reason=deny_on_first_deny, got %v", ctx["reason"])
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
	// Verify reason context is included on the short-circuit permit (Section 7.1.2.1).
	if resp.Evaluations[1].Context == nil {
		t.Fatal("evaluation[1]: expected context with reason on short-circuit permit")
	}
	var ctx map[string]any
	if err := json.Unmarshal(resp.Evaluations[1].Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context: %v", err)
	}
	if ctx["reason"] != "permit_on_first_permit" {
		t.Fatalf("evaluation[1]: expected reason=permit_on_first_permit, got %v", ctx["reason"])
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

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	expected := "http://localhost:8181/access/v1/evaluations"
	if metadata.AccessEvaluationsEndpoint != expected {
		t.Fatalf("expected access_evaluations_endpoint=%s, got %s", expected, metadata.AccessEvaluationsEndpoint)
	}
}

func TestWellKnownIncludesSupportedCapabilities(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.SupportedCapabilities == nil {
		t.Fatal("expected supported_capabilities in metadata")
	}
	// Currently no capabilities are declared, so the array should be empty.
	if len(metadata.SupportedCapabilities) != 0 {
		t.Fatalf("expected empty supported_capabilities, got %v", metadata.SupportedCapabilities)
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

// Tests for meaningful edge cases and error conditions

// TestDecisionNonBooleanReturnsDecisionFalse verifies that when a policy rule
// returns a non-boolean value (string, number, object, etc.), the implementation
// correctly returns decision=false. This is a key behavioral requirement.
func TestDecisionNonBooleanReturnsDecisionFalse(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		allow = "maybe"
	`)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "test"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "123"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	// Implementation should return 200 with decision=false (not error)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for non-boolean result, got %d", w.Code)
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Decision != false {
		t.Errorf("expected decision=false for non-boolean result, got %v", resp.Decision)
	}
}

// TestDecisionRuleDoesNotExistReturnsDecisionFalse verifies that when a decision
// rule doesn't exist in the policy, the system gracefully returns decision=false.
// This prevents errors from being surfaced when a rule simply doesn't define a result.
func TestDecisionRuleDoesNotExistReturnsDecisionFalse(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		other_rule = true
	`)
	p.cfg.Decision = "allow" // Rule doesn't exist
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "test"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "123"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when rule doesn't exist, got %d", w.Code)
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Decision != false {
		t.Errorf("expected decision=false when rule doesn't exist, got %v", resp.Decision)
	}
}

// TestBuildInputWithSpecialCharactersInProperties tests that the buildInput function
// correctly handles special characters, Unicode, and complex nested structures.
// This prevents JSON marshaling bugs and injection vulnerabilities.
func TestBuildInputWithSpecialCharactersInProperties(t *testing.T) {
	p := testPlugin(t, module)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	// Input with special characters, Unicode, quotes, backslashes
	body := `{
		"subject": {
			"type": "user",
			"id": "alice@example.com",
			"properties": {
				"department": "Sales & Marketing",
				"name": "Alice \"Ace\" O'Brien",
				"location": "Tokyo, 日本",
				"path": "C:\\Users\\alice\\Documents"
			}
		},
		"action": {"name": "read"},
		"resource": {"type": "document", "id": "doc-123"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	// Must succeed - special chars should be handled
	if w.Code != http.StatusOK {
		t.Fatalf("failed with special characters: %d, body: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Special characters should be handled; policy allows read action with non-empty subject.id
	if !resp.Decision {
		t.Errorf("expected decision=true for input with special characters, got %v", resp.Decision)
	}
}

// TestBuildInputWithNullPropertiesInSubjectAndResource tests that null values in
// properties are preserved correctly. AuthZEN allows objects to have optional properties.
func TestBuildInputWithNullPropertiesInSubjectAndResource(t *testing.T) {
	p := testPlugin(t, module)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	// Properties field is null in subject
	body := `{
		"subject": {"type": "user", "id": "alice", "properties": null},
		"action": {"name": "read"},
		"resource": {"type": "document", "id": "doc-123", "properties": null}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	// Must handle null properties gracefully
	if w.Code != http.StatusOK {
		t.Fatalf("failed with null properties: %d, body: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Null properties should be handled gracefully; alice with read action should be allowed
	if !resp.Decision {
		t.Errorf("expected decision=true when handling null properties, got %v", resp.Decision)
	}
}

// TestBatchEvaluationsWithNullFieldsUsesDefaults tests that when an individual
// evaluation has null fields, they are replaced with defaults from the top level.
// This tests the merge semantics from Section 7.1.
func TestBatchEvaluationsWithNullFieldsUsesDefaults(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		allow if input.subject.id == "default-id"
	`)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	// Batch with defaults; individual evaluation overrides subject but not others
	body := `{
		"subject": {"type": "default-user", "id": "default-id"},
		"action": {"name": "default-action"},
		"resource": {"type": "default-type", "id": "default-id"},
		"evaluations": [
			{
				"subject": {"type": "user", "id": "alice"},
				"action": null,
				"resource": null
			}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluations(w, req)

	// Should merge: alice + default action/resource
	// Policy checks subject.id == "default-id", but input subject is alice, so deny
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for merge test, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation result, got %d", len(resp.Evaluations))
	}

	// alice.id != default-id, so decision should be false
	if resp.Evaluations[0].Decision != false {
		t.Errorf("expected decision=false (alice != default-id), got %v", resp.Evaluations[0].Decision)
	}
}

// TestBatchEvaluationsPreservesOrderAndCorrectness tests that batch evaluations
// process all items, preserve order, and that each gets correct decision based on
// its specific context (not mixed up).
func TestBatchEvaluationsPreservesOrderAndCorrectness(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		allow if input.subject.id == "admin"
		allow if input.resource.id == "public"
	`)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	body := `{
		"evaluations": [
			{
				"subject": {"type": "user", "id": "admin"},
				"action": {"name": "read"},
				"resource": {"type": "doc", "id": "private"}
			},
			{
				"subject": {"type": "user", "id": "alice"},
				"action": {"name": "read"},
				"resource": {"type": "doc", "id": "public"}
			},
			{
				"subject": {"type": "user", "id": "bob"},
				"action": {"name": "read"},
				"resource": {"type": "doc", "id": "private"}
			}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("batch evaluation failed: %d, body: %s", w.Code, w.Body.String())
	}

	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify: evaluations array has 3 items in same order
	if len(resp.Evaluations) != 3 {
		t.Errorf("expected 3 evaluations, got %d", len(resp.Evaluations))
	}

	// Verify order: [allow=true, allow=true, allow=false]
	expectedDecisions := []bool{true, true, false}
	for i, expected := range expectedDecisions {
		if resp.Evaluations[i].Decision != expected {
			t.Errorf("evaluation[%d]: expected %v, got %v", i, expected, resp.Evaluations[i].Decision)
		}
	}
}

// TestEvaluationsBackwardCompatibilityWithoutEvaluationsArray tests that when
// evaluations array is absent, the request is treated as single evaluation using
// top-level subject/action/resource (Section 7.1 backward compatibility).
func TestEvaluationsBackwardCompatibilityWithoutEvaluationsArray(t *testing.T) {
	p := testPlugin(t, module)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	// No "evaluations" array - only top-level subject/action/resource
	body := `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "document", "id": "doc-123"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("backward compatibility failed: %d, body: %s", w.Code, w.Body.String())
	}

	var resp evaluationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Should return evaluations-style response (array with 1 item)
	if len(resp.Evaluations) != 1 {
		t.Errorf("expected 1 evaluation for backward compat, got %d", len(resp.Evaluations))
	}

	if resp.Evaluations[0].Decision != true {
		t.Errorf("expected decision=true for alice, got %v", resp.Evaluations[0].Decision)
	}
}

// Section 11.7: Request payload size limits

func TestEvaluationRejectsOversizedBody(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	// Build a body larger than maxRequestBodyBytes (1 MB).
	padding := strings.Repeat("x", maxRequestBodyBytes+1)
	body := `{"subject":{"type":"user","id":"` + padding + `"},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
}

func TestEvaluationsRejectsOversizedBody(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	padding := strings.Repeat("x", maxRequestBodyBytes+1)
	body := `{"subject":{"type":"user","id":"` + padding + `"},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluations(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
}

func TestEvaluationsRejectsExcessiveBatchSize(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	// Build evaluations array with maxBatchSize+1 items.
	var evals []string
	for i := 0; i < maxBatchSize+1; i++ {
		evals = append(evals, fmt.Sprintf(`{"resource":{"type":"doc","id":"%d"}}`, i))
	}
	body := fmt.Sprintf(`{
		"subject":{"type":"user","id":"alice"},
		"action":{"name":"read"},
		"evaluations":[%s]
	}`, strings.Join(evals, ","))

	w := postEvaluations(p, body)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for batch size %d, got %d", maxBatchSize+1, w.Code)
	}
}

func TestEvaluationsAcceptsMaxBatchSize(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	// Build evaluations array with exactly maxBatchSize items.
	var evals []string
	for i := 0; i < maxBatchSize; i++ {
		evals = append(evals, fmt.Sprintf(`{"resource":{"type":"doc","id":"%d"}}`, i))
	}
	body := fmt.Sprintf(`{
		"subject":{"type":"user","id":"alice"},
		"action":{"name":"read"},
		"evaluations":[%s]
	}`, strings.Join(evals, ","))

	w := postEvaluations(p, body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for batch size %d, got %d: %s", maxBatchSize, w.Code, w.Body.String())
	}

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != maxBatchSize {
		t.Fatalf("expected %d evaluations, got %d", maxBatchSize, len(resp.Evaluations))
	}
}

func TestReconfigureWithInvalidType(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	// Reconfigure with wrong type should not panic.
	p.Reconfigure(context.Background(), "not a *Config")

	// Reconfigure with nil pointer should not panic.
	p.Reconfigure(context.Background(), (*Config)(nil))

	// Plugin should still work with original config.
	body := `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after invalid reconfigure, got %d", w.Code)
	}
}
