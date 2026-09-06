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

func testPlugin(tb testing.TB, module string) *AuthZenPlugin {
	tb.Helper()

	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	if err := store.UpsertPolicy(ctx, txn, "test.rego", []byte(module)); err != nil {
		tb.Fatal(err)
	}
	if err := store.Commit(ctx, txn); err != nil {
		tb.Fatal(err)
	}

	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		tb.Fatal(err)
	}

	if err := m.Start(ctx); err != nil {
		tb.Fatal(err)
	}

	cfg := &Config{
		Path:     defaultPath,
		Decision: defaultDecision,
	}

	return New(m, cfg)
}

// testSearchPlugin builds a plugin with the Search APIs enabled using the
// fixed rule names "subject_search", "resource_search", "action_search".
func testSearchPlugin(tb testing.TB, module string) *AuthZenPlugin {
	tb.Helper()
	p := testPlugin(tb, module)
	p.cfg.Search = SearchConfig{
		Subject:  "subject_search",
		Resource: "resource_search",
		Action:   "action_search",
	}
	return p
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

// TestWellKnownCacheControl verifies that the PDP metadata response
// advertises Cache-Control + Vary so PEPs and shared caches can store
// the discovery document without serving cross-tenant responses
// (Section 11.9 of the AuthZEN spec; RFC 9111 §4.1 for the Vary
// requirement on header-dependent payloads).
func TestWellKnownCacheControl(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()

	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("expected Cache-Control=\"public, max-age=3600\", got %q", got)
	}
	if got := w.Header().Get("Vary"); got != "X-Forwarded-Proto, X-Forwarded-Host" {
		t.Fatalf("expected Vary=\"X-Forwarded-Proto, X-Forwarded-Host\", got %q", got)
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

func TestRejectsInvalidInformationModel(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
	`)

	tests := []struct {
		name    string
		body    string
		wantErr string // substring expected in the error response (optional)
	}{
		// subject validation
		{"subject missing type", `{"subject": {"id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.type"},
		{"subject missing id", `{"subject": {"type": "user"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.id"},
		{"subject is number", `{"subject": 123, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject must be a JSON object"},
		{"subject is string", `{"subject": "alice", "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject must be a JSON object"},
		{"subject is array", `{"subject": [1,2], "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject must be a JSON object"},
		{"subject is null", `{"subject": null, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject"},
		{"subject.type is number", `{"subject": {"type": 123, "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.type"},
		{"subject.type is bool", `{"subject": {"type": true, "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.type"},
		{"subject.id is number", `{"subject": {"type": "user", "id": 42}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.id"},
		// action validation
		{"action missing name", `{"subject": {"type": "user", "id": "bob"}, "action": {}, "resource": {"type": "doc", "id": "1"}}`, "action.name"},
		{"action is array", `{"subject": {"type": "user", "id": "bob"}, "action": ["read"], "resource": {"type": "doc", "id": "1"}}`, "action must be a JSON object"},
		{"action.name is number", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": 42}, "resource": {"type": "doc", "id": "1"}}`, "action.name"},
		{"action.name is array", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": ["r","w"]}, "resource": {"type": "doc", "id": "1"}}`, "action.name"},
		// resource validation
		{"resource missing type", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"id": "1"}}`, "resource.type"},
		{"resource missing id", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc"}}`, "resource.id"},
		{"resource is string", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": "doc-1"}`, "resource must be a JSON object"},
		{"resource.type is bool", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": true, "id": "1"}}`, "resource.type"},
		{"resource.id is object", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": {"nested": 1}}}`, "resource.id"},
		// context validation
		{"context is string", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}, "context": "prod"}`, "context must be a JSON object"},
		{"context is array", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}, "context": [1,2]}`, "context must be a JSON object"},
		{"context is number", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}, "context": 42}`, "context must be a JSON object"},
		{"context is bool", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}, "context": true}`, "context must be a JSON object"},
		// properties validation (Section 5: properties MUST be an object when present)
		{"subject.properties is string", `{"subject": {"type": "user", "id": "bob", "properties": "x"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.properties must be a JSON object"},
		{"subject.properties is array", `{"subject": {"type": "user", "id": "bob", "properties": [1]}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`, "subject.properties must be a JSON object"},
		{"action.properties is number", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read", "properties": 1}, "resource": {"type": "doc", "id": "1"}}`, "action.properties must be a JSON object"},
		{"resource.properties is bool", `{"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1", "properties": true}}`, "resource.properties must be a JSON object"},
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
			if tt.wantErr != "" {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if !strings.Contains(resp["error"], tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, resp["error"])
				}
			}
		})
	}
}

// TestPropertiesAccepted verifies that valid object-valued `properties`
// (Section 5: OPTIONAL, object) flow through to OPA input and are
// available to the policy.
func TestPropertiesAccepted(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if {
			input.subject.properties.role == "admin"
			input.action.properties.method == "GET"
			input.resource.properties.tier == "premium"
		}
	`)
	body := `{
		"subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
		"action": {"name": "read", "properties": {"method": "GET"}},
		"resource": {"type": "doc", "id": "1", "properties": {"tier": "premium"}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp evaluationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true, body=%s", w.Body.String())
	}
}

// TestPropertiesNullTreatedAsAbsent verifies that JSON null `properties`
// is silently dropped rather than rejected. Section 11.5 recommends that
// senders omit null values, so accepting them is the forward-compatible
// behaviour.
func TestPropertiesNullTreatedAsAbsent(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)
	body := `{
		"subject": {"type": "user", "id": "alice", "properties": null},
		"action": {"name": "read", "properties": null},
		"resource": {"type": "doc", "id": "1", "properties": null}
	}`
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestContextNullIsTreatedAsAbsent verifies that a JSON null context is
// treated as absent rather than rejected (Section 5: context is OPTIONAL).
func TestContextNullIsTreatedAsAbsent(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	body := `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"context": null
	}`

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.handleEvaluation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true")
	}
}

// TestBatchContextNullIsTreatedAsAbsent verifies null-context handling
// works for batch evaluations (Section 7).
func TestBatchContextNullIsTreatedAsAbsent(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`)

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"context": null,
		"evaluations": [
			{},
			{"context": null}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2, got %d", len(resp.Evaluations))
	}
	for i, e := range resp.Evaluations {
		if !e.Decision {
			t.Fatalf("evaluation[%d]: expected true", i)
		}
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

// decodeSingleResp decodes the singular Access Evaluation shape and asserts the
// batch envelope is absent. The Section 7.1 backward-compatibility branch of
// the evaluations endpoint must answer in this shape, not wrap the lone
// decision in an `evaluations` array (certification scenario c-3-4-2/c-3-4-3).
func decodeSingleResp(t *testing.T, w *httptest.ResponseRecorder) evaluationResponse {
	t.Helper()
	if body := w.Body.String(); strings.Contains(body, `"evaluations"`) {
		t.Fatalf("expected singular Access Evaluation response, got batch envelope: %s", body)
	}
	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode evaluation response: %v\nbody: %s", err, w.Body.String())
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

func TestEvaluationsInvalidInformationModelPerEval(t *testing.T) {
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
			{"subject": {"id": "bob"}}
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
		t.Fatal("evaluation[1]: expected false (invalid subject)")
	}
	if resp.Evaluations[1].Context == nil {
		t.Fatal("evaluation[1]: expected context with error")
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

	// Plural endpoint answers in the singular Access Evaluation shape when the
	// evaluations array is absent or empty (Section 7.1 / certification c-3-4-2).
	resp := decodeSingleResp(t, w)
	if !resp.Decision {
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

	// Plural endpoint answers in the singular Access Evaluation shape when the
	// evaluations array is absent or empty (Section 7.1 / certification c-3-4-2).
	resp := decodeSingleResp(t, w)
	if !resp.Decision {
		t.Fatal("expected decision=true in backward-compat mode")
	}
}

// TestEvaluationsBackwardCompatResponseShape pins the exact wire format of the
// Section 7.1 backward-compatibility branch. The AuthZEN certification scenario
// validates the response *structure* of c-3-4-2 (no evaluations array) and
// c-3-4-3 (empty evaluations array) against the singular Access Evaluation
// response, so a batch envelope here is a certification failure.
func TestEvaluationsBackwardCompatResponseShape(t *testing.T) {
	module := `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
	`
	for _, tc := range []struct{ name, body string }{
		{"c-3-4-2 no evaluations array", `{
			"subject": {"type": "user", "id": "alice"},
			"action": {"name": "read"},
			"resource": {"type": "record", "id": "record-1"}
		}`},
		{"c-3-4-3 empty evaluations array", `{
			"subject": {"type": "user", "id": "alice"},
			"action": {"name": "read"},
			"resource": {"type": "record", "id": "record-1"},
			"evaluations": []
		}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postEvaluations(testPlugin(t, module), tc.body)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			if got := strings.TrimSpace(w.Body.String()); got != `{"decision":true}` {
				t.Fatalf(`expected {"decision":true}, got %s`, got)
			}
		})
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

func TestEvaluationsBackwardCompatRejectsInvalidInformationModel(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	w := postEvaluations(p, `{
		"subject": {"id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"}
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

func TestWellKnownOmitsEmptyCapabilities(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Section 9.2.2: "Parameters that have no values MUST be omitted from the response."
	// With omitempty, an empty capabilities should not appear in the JSON output.
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["capabilities"]; exists {
		t.Fatal("expected capabilities to be omitted when empty (Section 9.2.2 MUST)")
	}
}

func TestWellKnownAdvertisesCapabilities(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	p.cfg.Capabilities = []string{
		"urn:openid:authzen:capability:access-request",
		"urn:example:authzen:capability:custom",
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Capabilities) != 2 ||
		metadata.Capabilities[0] != "urn:openid:authzen:capability:access-request" ||
		metadata.Capabilities[1] != "urn:example:authzen:capability:custom" {
		t.Fatalf("unexpected capabilities: %v", metadata.Capabilities)
	}
}

func TestWellKnownEchoesXRequestID(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	req.Header.Set("X-Request-ID", "wk-req-42")
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Section 10.1.3: PDP MUST echo X-Request-ID when present.
	if got := w.Header().Get("X-Request-ID"); got != "wk-req-42" {
		t.Fatalf("expected X-Request-ID 'wk-req-42', got %q", got)
	}
}

func TestWellKnownOmitsXRequestIDWhenAbsent(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Request-ID"); got != "" {
		t.Fatalf("expected no X-Request-ID header, got %q", got)
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

// TestBatchEvaluationsNullFieldsFallBackToDefaults verifies that explicit JSON null
// in an evaluation item falls back to the top-level default (Section 7.1.1).
func TestBatchEvaluationsNullFieldsFallBackToDefaults(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		allow if input.subject.id == "default-id"
	`)

	// action and resource are explicitly null -> should use top-level defaults.
	// subject is also null -> should use top-level default ("default-id") -> allow.
	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "default-id"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{
				"subject": null,
				"action": null,
				"resource": null
			}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision {
		t.Fatal("expected decision=true (null fields should fall back to top-level defaults)")
	}
}

// TestBatchEvaluationsNullDefaultAndNullOverrideReturnsError verifies that when
// both the top-level default and the per-evaluation override are JSON null,
// the required-field validation catches it as a per-evaluation error.
func TestBatchEvaluationsNullDefaultAndNullOverrideReturnsError(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		default allow = false
	`)

	w := postEvaluations(p, `{
		"subject": null,
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{"subject": null}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision {
		t.Fatal("expected decision=false for null subject (both default and override)")
	}
	if resp.Evaluations[0].Context == nil {
		t.Fatal("expected context with error for missing required field")
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

	// Should return the singular Access Evaluation shape, not the batch envelope.
	resp := decodeSingleResp(t, w)
	if resp.Decision != true {
		t.Errorf("expected decision=true for alice, got %v", resp.Decision)
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

// TestReconfigureChangesPathAndDecision verifies that after Reconfigure with a
// new path and decision rule, evaluations use the updated configuration.
func TestReconfigureChangesPathAndDecision(t *testing.T) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	// Two packages: "authzen" (default) and "custom".
	if err := store.UpsertPolicy(ctx, txn, "default.rego", []byte(`
		package authzen
		default allow = false
	`)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPolicy(ctx, txn, "custom.rego", []byte(`
		package custom
		default permit = false
		permit if input.subject.id == "alice"
	`)); err != nil {
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

	cfg := &Config{Path: defaultPath, Decision: defaultDecision}
	p := New(m, cfg)

	body := `{"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}}`

	// Before reconfigure: default path "authzen" with rule "allow" -> deny for alice.
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false before reconfigure")
	}

	// Reconfigure to use "custom" package with "permit" rule.
	p.Reconfigure(ctx, &Config{Path: "custom", Decision: "permit"})

	// After reconfigure: path "custom" with rule "permit" -> allow for alice.
	req = httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	p.handleEvaluation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true after reconfigure to custom/permit")
	}
}

const searchModule = `
	package authzen

	users := ["alice", "bob", "carol", "dave"]
	accounts := ["100", "200", "300"]
	verbs := ["can_read", "can_write", "can_delete"]

	subject_search contains {"type": "user", "id": u} if {
		some u in users
		input.action.name == "can_read"
		input.resource.type == "account"
	}

	resource_search contains {"type": "account", "id": a} if {
		some a in accounts
		input.subject.type == "user"
		input.action.name == "can_read"
	}

	action_search contains {"name": v} if {
		some v in verbs
		input.subject.type == "user"
		input.resource.type == "account"
	}
`

func doSearch(t *testing.T, p *AuthZenPlugin, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	switch path {
	case "/access/v1/search/subject":
		p.handleSubjectSearch(w, req)
	case "/access/v1/search/resource":
		p.handleResourceSearch(w, req)
	case "/access/v1/search/action":
		p.handleActionSearch(w, req)
	default:
		t.Fatalf("unknown path %q", path)
	}
	return w
}

func TestSubjectSearch_NotConfigured(t *testing.T) {
	p := testPlugin(t, searchModule) // no Search config
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubjectSearch_OK(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 4 {
		t.Fatalf("expected 4 subjects, got %d: %v", len(resp.Results), resp.Results)
	}
	first, _ := resp.Results[0].(map[string]any)
	if first["type"] != "user" || first["id"] != "alice" {
		t.Fatalf("expected first user alice, got %v", first)
	}
	if resp.Page == nil || resp.Page.NextToken != "" {
		t.Fatalf("expected empty next_token, got %+v", resp.Page)
	}
	if resp.Page.Total == nil || *resp.Page.Total != 4 {
		t.Fatalf("expected total=4, got %+v", resp.Page.Total)
	}
}

func TestSubjectSearch_IgnoresSubjectID(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user", "id": "this-should-be-ignored"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 4 {
		t.Fatalf("subject.id should be ignored; got %d results", len(resp.Results))
	}
}

func TestSubjectSearch_MissingActionName(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestResourceSearch_OK(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resp.Results))
	}
}

func TestResourceSearch_IgnoresResourceID(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "must-be-ignored"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestActionSearch_OK(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/action", `{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 actions, got %d: %v", len(resp.Results), resp.Results)
	}
}

func TestActionSearch_IgnoresActionKey(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	// Spec Section 8.6.1 omits the "action" key, but unknown/extra fields
	// MUST be ignored (Section 10.1.1).
	w := doSearch(t, p, "/access/v1/search/action", `{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "account", "id": "100"},
		"action": {"name": "garbage"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSearch_PaginationFollowToken(t *testing.T) {
	p := testSearchPlugin(t, searchModule)

	// First page: limit 2 of 4 users.
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 2}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var first searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Results) != 2 {
		t.Fatalf("page 1: expected 2 results, got %d", len(first.Results))
	}
	if first.Page == nil || first.Page.NextToken == "" {
		t.Fatal("page 1: expected non-empty next_token")
	}

	// Second page using token; entities and limit MUST match.
	body := fmt.Sprintf(`{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 2, "token": %q}
	}`, first.Page.NextToken)
	w = doSearch(t, p, "/access/v1/search/subject", body)
	if w.Code != http.StatusOK {
		t.Fatalf("page 2: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var second searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Results) != 2 {
		t.Fatalf("page 2: expected 2 results, got %d", len(second.Results))
	}
	if second.Page == nil || second.Page.NextToken != "" {
		t.Fatalf("page 2: expected empty next_token, got %+v", second.Page)
	}
	// Pages must not repeat entities.
	seen := map[string]bool{}
	for _, r := range append(first.Results, second.Results...) {
		obj := r.(map[string]any)
		key := obj["id"].(string)
		if seen[key] {
			t.Fatalf("duplicate result across pages: %s", key)
		}
		seen[key] = true
	}
	if len(seen) != 4 {
		t.Fatalf("expected 4 unique results across pages, got %d", len(seen))
	}
}

func TestSearch_PaginationTokenMismatch(t *testing.T) {
	p := testSearchPlugin(t, searchModule)

	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 2}
	}`)
	var first searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Page == nil || first.Page.NextToken == "" {
		t.Fatal("expected token from first page")
	}

	// Replay with the same token but a different resource id.
	body := fmt.Sprintf(`{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "999"},
		"page": {"limit": 2, "token": %q}
	}`, first.Page.NextToken)
	w = doSearch(t, p, "/access/v1/search/subject", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on tampered token, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearch_PaginationIgnoresSpecIgnoredFields verifies that pagination
// tokens are bound to the normalized search input, not the raw request
// body. A Subject Search where the client echoes back `subject.id` on a
// follow-up page must succeed because that field is spec-ignored
// (Section 8.4.1) and does not affect the actual evaluation.
func TestSearch_PaginationIgnoresSpecIgnoredFields(t *testing.T) {
	p := testSearchPlugin(t, searchModule)

	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 2}
	}`)
	var first searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Page == nil || first.Page.NextToken == "" {
		t.Fatal("expected token from first page")
	}

	// Same logical query, but with subject.id present this time. Per
	// Section 8.4.1 the id is ignored, so pagination must continue.
	body := fmt.Sprintf(`{
		"subject": {"type": "user", "id": "ignored-by-spec"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 2, "token": %q}
	}`, first.Page.NextToken)
	w = doSearch(t, p, "/access/v1/search/subject", body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when only spec-ignored fields differ, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSearch_PaginationInvalidToken(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"token": "!!!not-base64!!!"}
	}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSearch_LimitClamp(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	p.cfg.Search.MaxLimit = 2

	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": 999}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected results clamped to MaxLimit=2, got %d", len(resp.Results))
	}
}

func TestSearch_NegativeLimit(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"},
		"page": {"limit": -1}
	}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSearch_RequestIDEcho(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	req := httptest.NewRequest(http.MethodPost, "/access/v1/search/subject", bytes.NewBufferString(`{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "search-req-77")
	w := httptest.NewRecorder()
	p.handleSubjectSearch(w, req)
	if got := w.Header().Get("X-Request-ID"); got != "search-req-77" {
		t.Fatalf("expected X-Request-ID echoed, got %q", got)
	}
}

func TestSearch_ContentTypeRequired(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	req := httptest.NewRequest(http.MethodPost, "/access/v1/search/subject", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	p.handleSubjectSearch(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing Content-Type, got %d", w.Code)
	}
}

func TestSearch_InvalidBody(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	w := doSearch(t, p, "/access/v1/search/subject", "not json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSearch_EmptyResults(t *testing.T) {
	// Rule that returns nothing for non-matching input.
	p := testSearchPlugin(t, `
		package authzen
		subject_search contains {"type": "user", "id": u} if {
			some u in []
		}
	`)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 0 {
		t.Fatalf("expected empty results, got %d", len(resp.Results))
	}
	if resp.Page == nil || resp.Page.NextToken != "" {
		t.Fatalf("expected next_token=\"\" on final/empty page, got %+v", resp.Page)
	}
}

// TestSearch_RejectsMistypedSubjectResults verifies Section 8.3:
// `results` MUST contain only entities of the type being searched for.
// A Subject Search rule that returns objects without a `type` field is a
// policy authoring error and surfaces as 500.
func TestSearch_RejectsMistypedSubjectResults(t *testing.T) {
	p := testSearchPlugin(t, `
		package authzen
		# action-shaped entity (only "name") returned from subject_search.
		subject_search contains {"name": "wrong_kind"} if true
	`)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearch_RejectsMistypedResourceResults: see above, for resources.
func TestSearch_RejectsMistypedResourceResults(t *testing.T) {
	p := testSearchPlugin(t, `
		package authzen
		resource_search contains {"name": "wrong_kind"} if true
	`)
	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account"}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearch_RejectsMistypedActionResults: Action Search results MUST
// expose a string `name` field.
func TestSearch_RejectsMistypedActionResults(t *testing.T) {
	p := testSearchPlugin(t, `
		package authzen
		# subject-shaped entity (type+id) returned from action_search.
		action_search contains {"type": "user", "id": "wrong_kind"} if true
	`)
	w := doSearch(t, p, "/access/v1/search/action", `{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearch_RejectsSubjectResultsMissingID: Section 5 makes `id` REQUIRED
// on Subject entities. A subject_search rule that emits only `type` would
// hand back an entity the PEP cannot re-evaluate, so reject it as a
// policy-authoring error.
func TestSearch_RejectsSubjectResultsMissingID(t *testing.T) {
	p := testSearchPlugin(t, `
		package authzen
		subject_search contains {"type": "user"} if true
	`)
	w := doSearch(t, p, "/access/v1/search/subject", `{
		"subject": {"type": "user"},
		"action": {"name": "can_read"},
		"resource": {"type": "account", "id": "100"}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearch_RejectsResourceResultsMissingID: same as above, for resources.
func TestSearch_RejectsResourceResultsMissingID(t *testing.T) {
	p := testSearchPlugin(t, `
		package authzen
		resource_search contains {"type": "account"} if true
	`)
	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account"}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWellKnown_NoSearchEndpointsByDefault(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	// Decode into a generic map so we can assert keys are absent.
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"search_subject_endpoint", "search_resource_endpoint", "search_action_endpoint"} {
		if _, present := raw[key]; present {
			t.Fatalf("expected %q to be absent when search is not configured", key)
		}
	}
}

func TestWellKnown_AdvertisesConfiguredSearchEndpoints(t *testing.T) {
	p := testSearchPlugin(t, `package authzen`)
	// Disable action search to verify selective advertisement.
	p.cfg.Search.Action = ""

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "pdp.example.com"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	var md pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md.SearchSubjectEndpoint != "http://pdp.example.com/access/v1/search/subject" {
		t.Fatalf("unexpected subject endpoint: %q", md.SearchSubjectEndpoint)
	}
	if md.SearchResourceEndpoint != "http://pdp.example.com/access/v1/search/resource" {
		t.Fatalf("unexpected resource endpoint: %q", md.SearchResourceEndpoint)
	}
	if md.SearchActionEndpoint != "" {
		t.Fatalf("expected action endpoint to be omitted, got %q", md.SearchActionEndpoint)
	}
}

// --- Decision context (Section 5.5.1) -------------------------------------

const decisionContextModule = `
	package authzen
	default allow = false
	allow if input.subject.id == "alice"
	reason := {"reason_admin": {"en": "matched id rule"}} if allow
	reason := {"reason_admin": {"en": "no matching rule"}} if not allow
`

// testContextPlugin enables the decision-context rule named "reason".
func testContextPlugin(tb testing.TB, module string) *AuthZenPlugin {
	tb.Helper()
	p := testPlugin(tb, module)
	p.cfg.DecisionContext = "reason"
	return p
}

func postEvaluation(p *AuthZenPlugin, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	return w
}

const singleEvalBody = `{
	"subject": {"type": "user", "id": "alice"},
	"resource": {"type": "doc", "id": "1"},
	"action": {"name": "read"}
}`

func TestEvaluationSurfacesDecisionContext(t *testing.T) {
	p := testContextPlugin(t, decisionContextModule)

	w := postEvaluation(p, singleEvalBody)
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
	if resp.Context == nil {
		t.Fatal("expected decision context to be present")
	}
	var ctx map[string]any
	if err := json.Unmarshal(resp.Context, &ctx); err != nil {
		t.Fatalf("context is not a JSON object: %v", err)
	}
	admin, ok := ctx["reason_admin"].(map[string]any)
	if !ok || admin["en"] != "matched id rule" {
		t.Fatalf("unexpected context: %s", resp.Context)
	}
}

func TestEvaluationDefaultOmitsDecisionContext(t *testing.T) {
	// No decision_context configured: behaves exactly as before (no context).
	p := testPlugin(t, decisionContextModule)

	w := postEvaluation(p, singleEvalBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "context") {
		t.Fatalf("expected no context in response, got: %s", w.Body.String())
	}
}

func TestEvaluationDecisionContextOmittedWhenUndefined(t *testing.T) {
	// The rule is undefined for this input, so context must be omitted.
	p := testContextPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
		reason := {"reason_admin": {"en": "only when bob"}} if input.subject.id == "bob"
	`)

	w := postEvaluation(p, singleEvalBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "context") {
		t.Fatalf("expected no context, got: %s", w.Body.String())
	}
}

func TestEvaluationDecisionContextOmittedWhenEmptyObject(t *testing.T) {
	// An empty object conveys nothing, so it is omitted.
	p := testContextPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
		reason := {} if true
	`)

	w := postEvaluation(p, singleEvalBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "context") {
		t.Fatalf("expected no context, got: %s", w.Body.String())
	}
}

func TestEvaluationDecisionContextNonObjectFails(t *testing.T) {
	// Section 5.5.1 requires context to be an object; a non-object result is a
	// policy-authoring error and must fail the request.
	p := testContextPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
		reason := "not an object" if true
	`)

	w := postEvaluation(p, singleEvalBody)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for non-object context, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEvaluationsBatchSurfacesDecisionContext(t *testing.T) {
	p := testContextPlugin(t, decisionContextModule)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "execute_all"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Evaluations))
	}
	for i, e := range resp.Evaluations {
		if e.Context == nil {
			t.Fatalf("evaluation[%d]: expected decision context", i)
		}
	}
	var denied map[string]any
	if err := json.Unmarshal(resp.Evaluations[0].Context, &denied); err != nil {
		t.Fatal(err)
	}
	admin := denied["reason_admin"].(map[string]any)
	if admin["en"] != "no matching rule" {
		t.Fatalf("evaluation[0]: unexpected context: %s", resp.Evaluations[0].Context)
	}
}

func TestEvaluationsBatchDecisionContextErrorFailsClosed(t *testing.T) {
	// A non-object context rule in a batch must fail that evaluation closed:
	// decision=false with an error context, not a leaked 500 for the whole
	// batch (which still returns 200).
	p := testContextPlugin(t, `
		package authzen
		default allow = false
		allow if input.subject.id == "alice"
		reason := "not an object" if true
	`)

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "execute_all"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("batch endpoint should return 200, got %d", w.Code)
	}
	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Evaluations))
	}
	if resp.Evaluations[0].Decision {
		t.Fatal("expected fail-closed decision=false on context error")
	}
	if resp.Evaluations[0].Context == nil {
		t.Fatal("expected an error context on the failed evaluation")
	}
}

func TestEvaluationsBackwardCompatSurfacesDecisionContext(t *testing.T) {
	// Single evaluation via the evaluations endpoint (no evaluations array).
	p := testContextPlugin(t, decisionContextModule)

	w := postEvaluations(p, singleEvalBody)
	resp := decodeSingleResp(t, w)
	if resp.Context == nil {
		t.Fatal("expected decision context in backward-compat response")
	}
}

// --- Obligations Profile 1.0 ----------------------------------------------

// obligationEchoModule reflects what the policy saw back through the Decision
// context. The rule is undefined — so the response carries no context — when
// the member never reached the policy.
const obligationEchoModule = `
	package authzen
	default allow = false
	allow if input.subject.id == "alice"
	echo := {"seen": input.context.supported_obligations}
`

func testObligationsPlugin(tb testing.TB, advertised ...string) *AuthZenPlugin {
	tb.Helper()
	p := testPlugin(tb, obligationEchoModule)
	p.cfg.DecisionContext = "echo"
	p.cfg.SupportedObligations = advertised
	return p
}

func obligationBody(ctx string) string {
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "doc", "id": "1"},
		"action": {"name": "read"},
		"context": %s
	}`, ctx)
}

// seenObligations reads the echoed set out of a Decision context. The bool
// distinguishes a filtered-to-empty array from a removed member.
func seenObligations(t *testing.T, raw json.RawMessage) ([]string, bool) {
	t.Helper()
	if raw == nil {
		return nil, false
	}
	var ctx struct {
		Seen *[]string `json:"seen"`
	}
	if err := json.Unmarshal(raw, &ctx); err != nil {
		t.Fatalf("decision context has unexpected shape: %v (%s)", err, raw)
	}
	if ctx.Seen == nil {
		return nil, false
	}
	return *ctx.Seen, true
}

func assertSeenObligations(t *testing.T, raw json.RawMessage, want []string) {
	t.Helper()
	got, ok := seenObligations(t, raw)
	if !ok {
		t.Fatalf("expected supported_obligations to reach the policy, got context %s", raw)
	}
	if len(got) != len(want) {
		t.Fatalf("policy saw %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("policy saw %v, want %v", got, want)
		}
	}
}

func TestEvaluationFiltersUnadvertisedObligations(t *testing.T) {
	p := testObligationsPlugin(t, "step-up", "notification")

	w := postEvaluation(p, obligationBody(`{"supported_obligations": ["notification", "session_termination", "step-up"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Request order is preserved; only the unadvertised entry drops out.
	assertSeenObligations(t, resp.Context, []string{"notification", "step-up"})
}

func TestEvaluationKeepsEmptyObligationSetWhenNothingMatches(t *testing.T) {
	p := testObligationsPlugin(t, "step-up")

	w := postEvaluation(p, obligationBody(`{"supported_obligations": ["session_termination"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	assertSeenObligations(t, resp.Context, []string{})
}

func TestEvaluationDropsNonStringDeclaredObligations(t *testing.T) {
	p := testObligationsPlugin(t, "step-up")

	w := postEvaluation(p, obligationBody(`{"supported_obligations": ["step-up", 42, null, {"type": "step-up"}]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	assertSeenObligations(t, resp.Context, []string{"step-up"})
}

func TestEvaluationRemovesNonArrayDeclaredObligations(t *testing.T) {
	p := testObligationsPlugin(t, "step-up")

	w := postEvaluation(p, obligationBody(`{"supported_obligations": "step-up", "keep": true}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := seenObligations(t, resp.Context); ok {
		t.Fatalf("expected the malformed member to be removed, got context %s", resp.Context)
	}
}

func TestEvaluationPassesContextThroughWhenProfileUnconfigured(t *testing.T) {
	// Nothing advertised: the PDP is not bound by the rule and sends the
	// context on as-is.
	p := testObligationsPlugin(t)

	w := postEvaluation(p, obligationBody(`{"supported_obligations": ["session_termination"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp evaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	assertSeenObligations(t, resp.Context, []string{"session_termination"})
}

func TestEvaluationsBatchFiltersDeclaredObligations(t *testing.T) {
	// Filtered per evaluation, after the Section 7.1.1 default merge.
	p := testObligationsPlugin(t, "notification")

	w := postEvaluations(p, `{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "doc", "id": "1"},
		"action": {"name": "read"},
		"context": {"supported_obligations": ["notification", "step-up"]},
		"evaluations": [
			{},
			{"context": {"supported_obligations": ["step-up"]}}
		]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeBatchResp(t, w)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Evaluations))
	}
	assertSeenObligations(t, resp.Evaluations[0].Context, []string{"notification"})
	assertSeenObligations(t, resp.Evaluations[1].Context, []string{})
}

func TestEvaluationsBackwardCompatFiltersDeclaredObligations(t *testing.T) {
	// No evaluations array: a separate branch with its own input build.
	p := testObligationsPlugin(t, "step-up")

	w := postEvaluations(p, obligationBody(`{"supported_obligations": ["step-up", "session_termination"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeSingleResp(t, w)
	assertSeenObligations(t, resp.Context, []string{"step-up"})
}

// obligationSearchModule turns the negotiated set into search results, making
// the filter observable through the Search response.
const obligationSearchModule = `
	package authzen
	resource_search contains {"type": "doc", "id": o} if {
		some o in input.context.supported_obligations
	}
`

func testObligationSearchPlugin(tb testing.TB, advertised ...string) *AuthZenPlugin {
	tb.Helper()
	p := testSearchPlugin(tb, obligationSearchModule)
	p.cfg.SupportedObligations = advertised
	return p
}

func searchResultIDs(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp searchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode search response: %v\nbody: %s", err, w.Body.String())
	}
	ids := make([]string, 0, len(resp.Results))
	for _, r := range resp.Results {
		obj, _ := r.(map[string]any)
		id, _ := obj["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func TestSearchFiltersDeclaredObligations(t *testing.T) {
	p := testObligationSearchPlugin(t, "notification")

	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc"},
		"context": {"supported_obligations": ["notification", "session_termination"]}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ids := searchResultIDs(t, w)
	if len(ids) != 1 || ids[0] != "notification" {
		t.Fatalf("expected only the advertised type to reach the policy, got %v", ids)
	}
}

func TestSearchPageTokenIgnoresUnadvertisedObligations(t *testing.T) {
	// The filter runs before the pagination hash, so values the PDP must
	// ignore cannot invalidate a follow-up token.
	p := testObligationSearchPlugin(t, "notification", "session_termination", "step-up")

	first := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc"},
		"context": {"supported_obligations": ["notification", "session_termination", "step-up", "custom"]},
		"page": {"limit": 2}
	}`)
	if first.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", first.Code, first.Body.String())
	}
	if ids := searchResultIDs(t, first); len(ids) != 2 || ids[0] != "notification" || ids[1] != "session_termination" {
		t.Fatalf("unexpected first page: %v", ids)
	}

	var firstResp searchResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResp); err != nil {
		t.Fatal(err)
	}
	if firstResp.Page == nil || firstResp.Page.NextToken == "" {
		t.Fatalf("expected a next_token, got %+v", firstResp.Page)
	}

	// A different unadvertised type on page 2 reduces to the same negotiated
	// set, so the token must still match.
	second := doSearch(t, p, "/access/v1/search/resource", fmt.Sprintf(`{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc"},
		"context": {"supported_obligations": ["notification", "session_termination", "step-up", "urn:example:other"]},
		"page": {"limit": 2, "token": %q}
	}`, firstResp.Page.NextToken))
	if second.Code != http.StatusOK {
		t.Fatalf("expected 200 on the follow-up page, got %d: %s", second.Code, second.Body.String())
	}
	if ids := searchResultIDs(t, second); len(ids) != 1 || ids[0] != "step-up" {
		t.Fatalf("unexpected second page: %v", ids)
	}
}

func TestWellKnownOmitsUnsetSupportedObligations(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["supported_obligations"]; exists {
		t.Fatal("expected supported_obligations to be omitted when unconfigured")
	}
}

func TestWellKnownAdvertisesSupportedObligations(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	p.cfg.SupportedObligations = []string{"step-up", "notification", "custom"}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	want := []string{"step-up", "notification", "custom"}
	if len(metadata.SupportedObligations) != len(want) {
		t.Fatalf("unexpected supported_obligations: %v", metadata.SupportedObligations)
	}
	for i := range want {
		if metadata.SupportedObligations[i] != want[i] {
			t.Fatalf("unexpected supported_obligations: %v", metadata.SupportedObligations)
		}
	}
}

func TestWellKnownOmitsUnsetAccessRequestMetadata(t *testing.T) {
	p := testPlugin(t, `package authzen`)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"access_request_endpoint", "jwks_uri"} {
		if _, exists := raw[field]; exists {
			t.Errorf("expected %s to be omitted when unconfigured", field)
		}
	}
}

func TestWellKnownAdvertisesAccessRequestMetadata(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	p.cfg.AccessRequestEndpoint = "https://requests.example.com/access/v1/requests"
	p.cfg.JWKSURI = "https://pdp.example.com/access/v1/jwks"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var metadata pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	// The endpoint is advertised verbatim, not derived from the request host,
	// because the profile lets a service other than the PDP host it.
	if got, want := metadata.AccessRequestEndpoint, "https://requests.example.com/access/v1/requests"; got != want {
		t.Errorf("access_request_endpoint = %q, want %q", got, want)
	}
	if got, want := metadata.JWKSURI, "https://pdp.example.com/access/v1/jwks"; got != want {
		t.Errorf("jwks_uri = %q, want %q", got, want)
	}
	// The rest of the document is unchanged by the profile.
	if got, want := metadata.AccessEvaluationEndpoint, "http://localhost:8181/access/v1/evaluation"; got != want {
		t.Errorf("access_evaluation_endpoint = %q, want %q", got, want)
	}
}

func TestWellKnownAdvertisesAccessRequestEndpointWithoutJWKS(t *testing.T) {
	// jwks_uri is only required of a deployment that issues signed values, so
	// the endpoint must be advertisable on its own.
	p := testPlugin(t, `package authzen`)
	p.cfg.AccessRequestEndpoint = "https://requests.example.com/access/v1/requests"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = "localhost:8181"
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["access_request_endpoint"] != "https://requests.example.com/access/v1/requests" {
		t.Errorf("unexpected access_request_endpoint: %v", raw["access_request_endpoint"])
	}
	if _, exists := raw["jwks_uri"]; exists {
		t.Error("expected jwks_uri to be omitted when unconfigured")
	}
}
