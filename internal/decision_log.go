package internal

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/server"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/util"
	"go.opentelemetry.io/otel/trace"
)

// decisionLog records the decisions of one AuthZEN request in OPA's decision
// log. The AuthZEN routes are served via ExtraRoute and evaluate their rules
// themselves, so OPA's server never logs them the way it logs the Data API;
// this does it in their place. A nil *decisionLog logs nothing, which is what
// newDecisionLog returns when the `decision_logs` plugin is not configured.
type decisionLog struct {
	logs    *logs.Plugin
	r       *http.Request
	txn     storage.Transaction
	path    string
	bundles map[string]server.BundleInfo
	batchID string
	logger  logging.Logger
}

// newDecisionLog returns the decision log for a request that evaluates rule
// in the package at path, or nil when OPA has no decision logger. txn is the
// transaction the rule is evaluated under: bundle revisions are read from it
// and the mask and drop policies (system.log) run under it, as for the Data
// API.
func (p *AuthZenPlugin) newDecisionLog(r *http.Request, txn storage.Transaction, path, rule string) *decisionLog {
	plugin := logs.Lookup(p.manager)
	if plugin == nil {
		return nil
	}
	return &decisionLog{
		logs:    plugin,
		r:       r,
		txn:     txn,
		path:    decisionLogPath(path, rule),
		bundles: bundleRevisions(r.Context(), p.manager.Store, txn),
		logger:  p.logger,
	}
}

// forBatch makes every decision logged from here on carry one shared
// batch_decision_id, so the items of a batch evaluation (Section 7) can be
// told apart from single evaluations and correlated with each other.
func (l *decisionLog) forBatch() *decisionLog {
	if l != nil {
		l.batchID = uuid.NewString()
	}
	return l
}

// log records one decision: the input the rule was evaluated with and the
// result returned to the PEP for it, or the evaluation error. It never fails
// the request; a decision log error is reported in OPA's own log.
func (l *decisionLog) log(input map[string]any, result any, evalErr error) {
	if l == nil {
		return
	}
	ctx := l.r.Context()

	info := &server.Info{
		Txn:             l.txn,
		Bundles:         l.bundles,
		DecisionID:      uuid.NewString(),
		BatchDecisionID: l.batchID,
		RemoteAddr:      l.r.RemoteAddr,
		Path:            l.path,
		Timestamp:       time.Now().UTC(),
		Error:           evalErr,
	}

	// OPA's HTTP server puts the request headers on the context of every
	// request, extra routes included; decision_logs.request_context selects
	// which of them are logged.
	if hctx, ok := logging.HTTPRequestContextFromContext(ctx); ok && hctx != nil {
		info.HTTPRequestContext = *hctx
	} else {
		info.HTTPRequestContext = logging.HTTPRequestContext{Header: l.r.Header.Clone()}
	}
	if rctx, ok := logging.FromContext(ctx); ok && rctx != nil {
		info.RequestID = rctx.ReqID
	}
	if sctx := trace.SpanContextFromContext(ctx); sctx.IsValid() {
		info.TraceID = sctx.TraceID().String()
		info.SpanID = sctx.SpanID().String()
	}

	// Log copies in their JSON form: the mask policy edits the event in place,
	// and the result is logged as the PEP received it.
	var in any = input
	if err := util.RoundTrip(&in); err != nil {
		l.logger.Error("AuthZEN decision log: encoding input: %v", err)
		return
	}
	info.Input = &in
	if evalErr == nil {
		out := result
		if err := util.RoundTrip(&out); err != nil {
			l.logger.Error("AuthZEN decision log: encoding result: %v", err)
			return
		}
		info.Results = &out
	}

	if err := l.logs.Log(ctx, info); err != nil {
		l.logger.Error("AuthZEN decision log: %v", err)
	}
}

// decisionLogPath names a decision the way the Data API's decision log does:
// the rule's path below `data`, slash-separated (`authzen/allow`).
func decisionLogPath(path, rule string) string {
	return strings.Trim(strings.ReplaceAll(path, ".", "/"), "/") + "/" + rule
}

// bundleRevisions reads the revision of every activated bundle, which the
// decision log records so a decision can be traced to the policy that made it.
// Revisions that cannot be read are left out rather than failing the request.
func bundleRevisions(ctx context.Context, store storage.Store, txn storage.Transaction) map[string]server.BundleInfo {
	names, err := bundle.ReadBundleNamesFromStore(ctx, store, txn)
	if err != nil || len(names) == 0 {
		return nil
	}
	revisions := make(map[string]server.BundleInfo, len(names))
	for _, name := range names {
		if rev, err := bundle.ReadBundleRevisionFromStore(ctx, store, txn, name); err == nil {
			revisions[name] = server.BundleInfo{Revision: rev}
		}
	}
	return revisions
}
