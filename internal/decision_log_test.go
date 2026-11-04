package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/storage"
)

// decisionSink is a decision log backend (decision_logs.plugin) that keeps
// every event it is handed, after OPA's decision logger masked and dropped.
type decisionSink struct {
	mu     sync.Mutex
	events []logs.EventV1
}

func (*decisionSink) Start(context.Context) error      { return nil }
func (*decisionSink) Stop(context.Context)             {}
func (*decisionSink) Reconfigure(context.Context, any) {}

func (s *decisionSink) Log(_ context.Context, event logs.EventV1) error { //nolint:gocritic // logs.Logger takes the event by value
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *decisionSink) logged() []logs.EventV1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

const decisionSinkName = "test_decision_sink"

// withDecisionLogs configures OPA's decision logger on the plugin's manager,
// as `decision_logs: {plugin: test_decision_sink, ...}` would. extra holds
// further decision_logs keys as JSON object members, or is empty.
func withDecisionLogs(tb testing.TB, p *AuthZenPlugin, extra string) *decisionSink {
	tb.Helper()
	sink := &decisionSink{}
	p.manager.Register(decisionSinkName, sink)
	raw := `{"plugin": "` + decisionSinkName + `"`
	if extra != "" {
		raw += ", " + extra
	}
	raw += "}"
	cfg, err := logs.ParseConfig([]byte(raw), nil, []string{decisionSinkName})
	if err != nil {
		tb.Fatal(err)
	}
	p.manager.Register(logs.Name, logs.New(cfg, p.manager))
	return sink
}

// upsertPolicy adds a module to the plugin's store; the manager recompiles.
func upsertPolicy(tb testing.TB, p *AuthZenPlugin, id, module string) {
	tb.Helper()
	ctx := context.Background()
	txn := storage.NewTransactionOrDie(ctx, p.manager.Store, storage.WriteParams)
	if err := p.manager.Store.UpsertPolicy(ctx, txn, id, []byte(module)); err != nil {
		tb.Fatal(err)
	}
	if err := p.manager.Store.Commit(ctx, txn); err != nil {
		tb.Fatal(err)
	}
}

func postEvaluationWithHeader(p *AuthZenPlugin, body string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	p.handleEvaluation(w, req)
	return w
}

// assertJSON compares a logged value with the JSON it should encode to.
func assertJSON(t *testing.T, name string, got *any, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: not logged, want %s", name, want)
	}
	gotJSON, err := json.Marshal(*got)
	if err != nil {
		t.Fatal(err)
	}
	var w any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("%s: bad expectation: %v", name, err)
	}
	wantJSON, _ := json.Marshal(w)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("%s:\n got  %s\n want %s", name, gotJSON, wantJSON)
	}
}

const decisionLogModule = `
	package authzen
	default allow = false
	allow if input.subject.id == "alice"
	reasons := {"reason": "alice may"} if allow
`

const decisionLogRequest = `{
	"subject": {"type": "user", "id": "alice"},
	"action": {"name": "read"},
	"resource": {"type": "doc", "id": "1"},
	"context": {"ip": "10.0.0.1"}
}`

func TestDecisionLogEvaluation(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	p.cfg.DecisionContext = "reasons"
	sink := withDecisionLogs(t, p, `"request_context": {"http": {"headers": ["X-Request-ID"]}}`)

	w := postEvaluationWithHeader(p, decisionLogRequest, http.Header{"X-Request-Id": {"req-1"}})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event, got %d", len(events))
	}
	e := events[0]
	if e.Path != "authzen/allow" {
		t.Errorf("path: got %q, want %q", e.Path, "authzen/allow")
	}
	if e.DecisionID == "" {
		t.Error("decision_id is empty")
	}
	if e.BatchDecisionID != "" {
		t.Errorf("batch_decision_id: got %q, want none for a single evaluation", e.BatchDecisionID)
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
	if e.RequestedBy != "192.0.2.1:1234" {
		t.Errorf("requested_by: got %q", e.RequestedBy)
	}
	if e.Error != nil {
		t.Errorf("unexpected error: %v", e.Error)
	}
	assertJSON(t, "input", e.Input, decisionLogRequest)
	assertJSON(t, "result", e.Result, `{"decision": true, "context": {"reason": "alice may"}}`)
	if e.RequestContext == nil || e.RequestContext.HTTPRequest == nil ||
		!slices.Equal(e.RequestContext.HTTPRequest.Headers["X-Request-ID"], []string{"req-1"}) {
		t.Errorf("request_context: got %+v, want X-Request-ID req-1", e.RequestContext)
	}
}

// The decision log only observes: the response is the same byte for byte.
func TestDecisionLogLeavesResponseUnchanged(t *testing.T) {
	plain := testPlugin(t, decisionLogModule)
	logged := testPlugin(t, decisionLogModule)
	sink := withDecisionLogs(t, logged, "")

	header := http.Header{"X-Request-Id": {"req-1"}}
	want := postEvaluationWithHeader(plain, decisionLogRequest, header)
	got := postEvaluationWithHeader(logged, decisionLogRequest, header)

	if got.Code != want.Code || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
		t.Fatalf("response changed:\n got  %d %s\n want %d %s", got.Code, got.Body, want.Code, want.Body)
	}
	for _, h := range []string{"Content-Type", "X-Request-ID"} {
		if got.Header().Get(h) != want.Header().Get(h) {
			t.Errorf("header %s: got %q, want %q", h, got.Header().Get(h), want.Header().Get(h))
		}
	}
	if len(got.Header()) != len(want.Header()) {
		t.Errorf("headers: got %v, want %v", got.Header(), want.Header())
	}
	if n := len(sink.logged()); n != 1 {
		t.Fatalf("expected 1 decision log event, got %d", n)
	}
}

// Without decision_logs nothing is logged, as for the Data API.
func TestDecisionLogDisabled(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	sink := &decisionSink{}
	p.manager.Register(decisionSinkName, sink)

	if w := postEvaluation(p, decisionLogRequest); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w := postEvaluations(p, `{"evaluations": [`+decisionLogRequest+`]}`); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if n := len(sink.logged()); n != 0 {
		t.Fatalf("expected no decision log events, got %d", n)
	}
}

// system.log mask and drop apply to AuthZEN decisions like any other.
func TestDecisionLogMaskAndDrop(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	upsertPolicy(t, p, "log.rego", `
		package system.log
		mask contains "/input/context/ip"
		mask contains {"op": "upsert", "path": "/input/subject/id", "value": "***"}
		drop if input.input.action.name == "ping"
	`)
	sink := withDecisionLogs(t, p, "")

	postEvaluation(p, decisionLogRequest)
	postEvaluation(p, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "ping"},
		"resource": {"type": "doc", "id": "1"}
	}`)

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event (ping dropped), got %d", len(events))
	}
	e := events[0]
	assertJSON(t, "input", e.Input, `{
		"subject": {"type": "user", "id": "***"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"context": {}
	}`)
	if !slices.Equal(e.Erased, []string{"/input/context/ip"}) {
		t.Errorf("erased: got %v", e.Erased)
	}
	if !slices.Equal(e.Masked, []string{"/input/subject/id"}) {
		t.Errorf("masked: got %v", e.Masked)
	}
}

// Every evaluated batch item is a decision of its own, sharing a batch ID.
// Items rejected before evaluation are not decisions and are not logged.
func TestDecisionLogEvaluationsBatch(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	sink := withDecisionLogs(t, p, "")

	w := postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user"}},
			{"subject": {"type": "user", "id": "bob"}, "resource": {"type": "doc", "id": "2"}}
		]
	}`)
	if got := len(decodeBatchResp(t, w).Evaluations); got != 3 {
		t.Fatalf("expected 3 results, got %d", got)
	}

	events := sink.logged()
	if len(events) != 2 {
		t.Fatalf("expected 2 decision log events, got %d", len(events))
	}
	if events[0].BatchDecisionID == "" || events[0].BatchDecisionID != events[1].BatchDecisionID {
		t.Errorf("batch_decision_id: got %q and %q, want one shared ID", events[0].BatchDecisionID, events[1].BatchDecisionID)
	}
	if events[0].DecisionID == events[1].DecisionID {
		t.Errorf("decision_id: both %q, want one per item", events[0].DecisionID)
	}
	assertJSON(t, "input[0]", events[0].Input, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"}
	}`)
	assertJSON(t, "result[0]", events[0].Result, `{"decision": true}`)
	assertJSON(t, "input[1]", events[1].Input, `{
		"subject": {"type": "user", "id": "bob"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "2"}
	}`)
	assertJSON(t, "result[1]", events[1].Result, `{"decision": false}`)

	// A short-circuited item is logged with the result the PEP received.
	sink.mu.Lock()
	sink.events = nil
	sink.mu.Unlock()
	postEvaluations(p, `{
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "1"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}}
		]
	}`)
	events = sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event after short-circuit, got %d", len(events))
	}
	assertJSON(t, "short-circuit result", events[0].Result,
		`{"decision": false, "context": {"code": "200", "reason": "deny_on_first_deny"}}`)
}

// A request without an `evaluations` array is a single evaluation (Section
// 7.1) and is logged as one.
func TestDecisionLogEvaluationsWithoutArray(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	sink := withDecisionLogs(t, p, "")

	postEvaluations(p, decisionLogRequest)

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event, got %d", len(events))
	}
	if events[0].BatchDecisionID != "" {
		t.Errorf("batch_decision_id: got %q, want none", events[0].BatchDecisionID)
	}
	assertJSON(t, "input", events[0].Input, decisionLogRequest)
	assertJSON(t, "result", events[0].Result, `{"decision": true}`)
}

// An evaluation error is logged with the error and no result, as the Data API
// logs one; the 500 response is unchanged.
func TestDecisionLogEvaluationError(t *testing.T) {
	p := testPlugin(t, `
		package authzen
		allow = true if input.subject.id == "alice"
		allow = false if input.action.name == "read"
	`)
	sink := withDecisionLogs(t, p, "")

	w := postEvaluation(p, decisionLogRequest)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event, got %d", len(events))
	}
	if events[0].Error == nil {
		t.Error("expected the evaluation error to be logged")
	}
	if events[0].Result != nil {
		t.Errorf("expected no result, got %v", *events[0].Result)
	}
	assertJSON(t, "input", events[0].Input, decisionLogRequest)
}

func TestDecisionLogSearch(t *testing.T) {
	p := testSearchPlugin(t, searchModule)
	sink := withDecisionLogs(t, p, "")

	w := doSearch(t, p, "/access/v1/search/resource", `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account"},
		"page": {"limit": 2}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event, got %d", len(events))
	}
	e := events[0]
	if e.Path != "authzen/resource_search" {
		t.Errorf("path: got %q, want %q", e.Path, "authzen/resource_search")
	}
	assertJSON(t, "input", e.Input, `{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "can_read"},
		"resource": {"type": "account"}
	}`)
	// The logged result is the page the PEP received.
	assertJSON(t, "result", e.Result, w.Body.String())
}

func TestDecisionLogBundleRevisions(t *testing.T) {
	p := testPlugin(t, decisionLogModule)
	ctx := context.Background()
	txn := storage.NewTransactionOrDie(ctx, p.manager.Store, storage.WriteParams)
	if err := bundle.WriteManifestToStore(ctx, p.manager.Store, txn, "authz", bundle.Manifest{Revision: "rev-42"}); err != nil {
		t.Fatal(err)
	}
	if err := p.manager.Store.Commit(ctx, txn); err != nil {
		t.Fatal(err)
	}
	sink := withDecisionLogs(t, p, "")

	postEvaluation(p, decisionLogRequest)

	events := sink.logged()
	if len(events) != 1 {
		t.Fatalf("expected 1 decision log event, got %d", len(events))
	}
	if got := events[0].Bundles["authz"].Revision; got != "rev-42" {
		t.Errorf("bundle revision: got %q, want %q (bundles %v)", got, "rev-42", events[0].Bundles)
	}
}

func TestDecisionLogPath(t *testing.T) {
	tests := []struct {
		path, rule, want string
	}{
		{"authzen", "allow", "authzen/allow"},
		{"tcs/brp", "allow", "tcs/brp/allow"},
		{"tcs.brp", "allow", "tcs/brp/allow"},
		{"/authzen/", "subject_search", "authzen/subject_search"},
	}
	for _, tt := range tests {
		if got := decisionLogPath(tt.path, tt.rule); got != tt.want {
			t.Errorf("decisionLogPath(%q, %q) = %q, want %q", tt.path, tt.rule, got, tt.want)
		}
	}
}
