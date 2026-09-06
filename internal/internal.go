package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
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

	// maxRequestBodyBytes is the maximum allowed size for an API request body.
	// This protects against denial-of-service attacks via excessively large
	// payloads (Section 11.7 of the AuthZEN specification).
	maxRequestBodyBytes = 1 << 20 // 1 MB

	// maxBatchSize is the maximum number of evaluations allowed in a single
	// batch request. This protects against resource exhaustion from requests
	// containing an excessive number of evaluation items (Section 11.7).
	maxBatchSize = 100

	// defaultSearchMaxLimit caps the per-page result size for Search APIs
	// (Section 8.2.1) when the operator does not override it via config.
	defaultSearchMaxLimit = 1000

	// metadataCacheControl is the Cache-Control directive returned with the
	// PDP metadata document. Section 11.9 ("Metadata Caching") recommends
	// using Cache-Control with a max-age so PEPs can cache the discovery
	// response. 1 hour is short enough that operators can roll changes
	// without intervention but long enough to offload re-discovery traffic.
	metadataCacheControl = "public, max-age=3600"

	// metadataVary lists request headers that vary the metadata response
	// body. The endpoint URLs are constructed from X-Forwarded-Proto and
	// X-Forwarded-Host (or Host), so a shared cache MUST key cached entries
	// by those headers or it will hand a response generated for one tenant
	// to another. RFC 9111 §4.1 makes this explicit when Cache-Control is
	// public.
	//
	// X-Request-ID is deliberately excluded: a cache entry per unique ID
	// would disable shared caching on this idempotent endpoint.
	metadataVary = "X-Forwarded-Proto, X-Forwarded-Host"
)

// searchKind identifies which AuthZEN Search API a request targets (Section 8).
type searchKind int

const (
	searchSubject searchKind = iota
	searchResource
	searchAction
)

// Config represents the plugin configuration.
type Config struct {
	Path     string `json:"path"`
	Decision string `json:"decision"`
	// DecisionContext names a Rego rule (within the package given by
	// Config.Path) whose object value is returned as the OPTIONAL `context`
	// member of the Decision (Section 5.5.1). It lets a policy convey reasons,
	// obligations, or other metadata alongside the boolean decision. Leaving it
	// empty (the default) omits decision context from responses, preserving
	// prior behavior. The rule MUST evaluate to a JSON object; a non-object
	// result is a policy-authoring error and fails the request.
	DecisionContext string       `json:"decision_context,omitempty"`
	Search          SearchConfig `json:"search"`
	// Capabilities lists the PDP capability URNs advertised in the
	// `capabilities` array of the PDP metadata document (Section 9.1.2). The
	// AuthZEN core specification registers no capability URNs of its own — the
	// registry is populated by profiles and vendors — so this is operator-
	// supplied and omitted from the metadata when empty.
	Capabilities []string `json:"capabilities,omitempty"`
	// SupportedObligations opts into the AuthZEN Obligations Profile 1.0: the
	// listed Obligation Types are advertised in the PDP metadata document and
	// bound the PEP-declared set on each request. Empty means the profile is
	// not implemented. Obligations themselves travel in the Decision context,
	// via Config.DecisionContext.
	SupportedObligations []string `json:"supported_obligations,omitempty"`
	// AccessRequestEndpoint advertises the Access Request Endpoint of the
	// AuthZEN Access Request and Approval Profile 1.0 as
	// `access_request_endpoint` in the PDP metadata document (profile section
	// "Discovery"). The profile allows that endpoint to be hosted by the PDP
	// itself, by a service the PDP trusts, or by an independent service with
	// delegated authority, so the value is operator-supplied and this plugin
	// does not serve the endpoint. The requestable-denial hint itself
	// (`context.access_request`) travels through Config.DecisionContext, and
	// the profile's capability URN through Config.Capabilities. Empty means
	// the profile is not advertised.
	AccessRequestEndpoint string `json:"access_request_endpoint,omitempty"`
	// JWKSURI advertises `jwks_uri` in the PDP metadata document. The Access
	// Request and Approval Profile requires it of a deployment that issues or
	// verifies signed values under the profile — a JWS `binding_token` or a
	// signed `approval.state` — so an Access Request Service can resolve the
	// verification key. Empty omits it.
	JWKSURI string `json:"jwks_uri,omitempty"`
}

// SearchConfig configures the optional Search APIs (Section 8 of the AuthZEN
// specification). Each field names a Rego rule (within the package given by
// Config.Path) that returns the set of permitted entities. Leaving a field
// empty disables the corresponding endpoint, which responds with 501.
type SearchConfig struct {
	Subject  string `json:"subject,omitempty"`
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
	// MaxLimit caps the per-page result size requested by clients. A value of
	// 0 selects the default (defaultSearchMaxLimit).
	MaxLimit int `json:"max_limit,omitempty"`
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

	if cfg.Search.MaxLimit < 0 {
		return nil, fmt.Errorf("search.max_limit must be non-negative")
	}

	// Capability values are advertised verbatim in the metadata document, so
	// reject malformed entries at startup rather than emitting bad metadata.
	// Section 9.1.2 specifies these as registered IANA URNs.
	for i, c := range cfg.Capabilities {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			return nil, fmt.Errorf("capabilities[%d] must not be empty", i)
		}
		// RFC 8141 §2: the "urn:" scheme identifier is case-insensitive, so
		// accept any case and canonicalize the prefix to lowercase. The
		// remainder (NID/NSS) is left untouched.
		if !strings.HasPrefix(strings.ToLower(trimmed), "urn:") {
			return nil, fmt.Errorf("capabilities[%d] %q must be a URN (start with \"urn:\")", i, c)
		}
		cfg.Capabilities[i] = "urn:" + trimmed[4:]
	}

	// The obligation registry is extensible, so values are not checked against
	// the profile's initial registrations — only rejected when empty.
	for i, o := range cfg.SupportedObligations {
		trimmed := strings.TrimSpace(o)
		if trimmed == "" {
			return nil, fmt.Errorf("supported_obligations[%d] must not be empty", i)
		}
		cfg.SupportedObligations[i] = trimmed
	}

	// The Access Request and Approval Profile requires both of these metadata
	// members to be HTTPS URIs. They are advertised verbatim, so a bad value
	// is rejected at startup rather than published to every PEP that reads the
	// metadata document.
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"access_request_endpoint", &cfg.AccessRequestEndpoint},
		{"jwks_uri", &cfg.JWKSURI},
	} {
		trimmed := strings.TrimSpace(*field.value)
		if trimmed == "" {
			// Normalize a whitespace-only value to unset so it is omitted from
			// the metadata rather than advertised as an empty string.
			*field.value = ""
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s %q is not a valid URI: %w", field.name, *field.value, err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("%s %q must be an https:// URI with a host", field.name, *field.value)
		}
		*field.value = trimmed
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
		p.manager.ExtraRoute("POST /access/v1/search/subject", "authzen/search-subject", p.handleSubjectSearch)
		p.manager.ExtraRoute("POST /access/v1/search/resource", "authzen/search-resource", p.handleResourceSearch)
		p.manager.ExtraRoute("POST /access/v1/search/action", "authzen/search-action", p.handleActionSearch)
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
	cfg, ok := config.(*Config)
	if !ok || cfg == nil {
		p.logger.WithFields(map[string]any{"config_type": fmt.Sprintf("%T", config)}).Error("AuthZEN reconfigure: unexpected or nil config type")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = *cfg
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

// pdpMetadata is the PDP metadata response body (Section 9).
type pdpMetadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"`
	SearchSubjectEndpoint     string `json:"search_subject_endpoint,omitempty"`
	SearchResourceEndpoint    string `json:"search_resource_endpoint,omitempty"`
	SearchActionEndpoint      string `json:"search_action_endpoint,omitempty"`
	// Access Request and Approval Profile 1.0. Both are omitted unless the
	// deployment configures them; the absence of access_request_endpoint is
	// the PEP's signal that this PDP advertises no Access Request Endpoint.
	AccessRequestEndpoint string   `json:"access_request_endpoint,omitempty"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
	Capabilities          []string `json:"capabilities,omitempty"`
	// Obligations Profile 1.0. Absence is equivalent to an empty array, so a
	// PDP that supports none simply omits it.
	SupportedObligations []string `json:"supported_obligations,omitempty"`
}

// AuthZEN Search API request (Section 8.4.1/8.5.1/8.6.1).
type searchRequest struct {
	Subject  json.RawMessage `json:"subject,omitempty"`
	Resource json.RawMessage `json:"resource,omitempty"`
	Action   json.RawMessage `json:"action,omitempty"`
	Context  json.RawMessage `json:"context,omitempty"`
	Page     *pageRequest    `json:"page,omitempty"`
}

// pageRequest is the AuthZEN paginated request page object (Section 8.2.1).
type pageRequest struct {
	Token      string          `json:"token,omitempty"`
	Limit      *int            `json:"limit,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// AuthZEN Search API response (Section 8.3).
type searchResponse struct {
	Page    *pageResponse   `json:"page,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	Results []any           `json:"results"`
}

// pageResponse is the AuthZEN paginated response page object (Section 8.2.2).
type pageResponse struct {
	NextToken string `json:"next_token"`
	Count     *int   `json:"count,omitempty"`
	Total     *int   `json:"total,omitempty"`
}

// pageToken is the decoded form of an opaque pagination token. The hash binds
// a token to the request that produced it, so callers cannot mutate query
// entities between pages (Section 8.2: PDP SHOULD return an error in that
// case).
type pageToken struct {
	Offset int    `json:"o"`
	Hash   string `json:"h"`
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func unmarshalJSONObject(raw json.RawMessage) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	return obj, obj != nil
}

func hasStringField(obj map[string]any, field string) bool {
	value, ok := obj[field]
	if !ok {
		return false
	}
	_, ok = value.(string)
	return ok
}

// normalizePropertiesField enforces that, when an entity's optional
// `properties` member is present, it is a JSON object (Section 5 of the
// AuthZEN spec defines `properties` as OPTIONAL with an object value).
// JSON null is deleted from obj in place so downstream code sees the
// field as absent (Section 11.5 recommends senders omit nulls; we accept
// and normalize them for forward compatibility). Returns an empty string
// on success, or a validation error message when `properties` is present
// but not an object.
func normalizePropertiesField(obj map[string]any, name string) string {
	value, ok := obj["properties"]
	if !ok {
		return ""
	}
	if value == nil {
		delete(obj, "properties")
		return ""
	}
	if _, ok := value.(map[string]any); !ok {
		return fmt.Sprintf("%s.properties must be a JSON object", name)
	}
	return ""
}

// isJSONContentType reports whether the request carries a JSON body per
// Section 10.1 ("Content-Type: application/json"). RFC 9110 Section 8.3.1
// makes the media type and its parameter names case-insensitive and allows
// parameters such as `charset`, so the parsed media type is compared rather
// than the raw header: `Application/JSON` and `application/json; charset=utf-8`
// both name the same type. A header whose parameters do not parse falls back
// to a case-insensitive prefix match so that nothing previously accepted is
// now rejected.
func isJSONContentType(ct string) bool {
	if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
		return mediaType == "application/json"
	}
	lower := strings.ToLower(ct)
	return lower == "application/json" || strings.HasPrefix(lower, "application/json;")
}

// isJSONNull returns true if raw represents a JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 4 && string(raw) == "null"
}

// validateObject unmarshals raw JSON and checks it is a non-null JSON object.
// Returns the parsed map and an empty string on success, or nil and an error
// message describing why validation failed.
func validateObject(raw json.RawMessage, name string) (map[string]any, string) {
	obj, ok := unmarshalJSONObject(raw)
	if !ok {
		return nil, fmt.Sprintf("%s must be a JSON object", name)
	}
	return obj, ""
}

// buildInput unmarshals the raw JSON fields into a map suitable for OPA input.
// It validates the information model constraints from the AuthZEN specification
// (Section 5): subject requires string "type" and "id", action requires string
// "name", resource requires string "type" and "id", and context (if present and
// non-null) must be a JSON object.
func buildInput(subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}

	subjectVal, errMsg := validateObject(subject, "subject")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(subjectVal, "type") {
		return nil, "subject.type is required and must be a string"
	}
	if !hasStringField(subjectVal, "id") {
		return nil, "subject.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(subjectVal, "subject"); errMsg != "" {
		return nil, errMsg
	}
	input["subject"] = subjectVal

	actionVal, errMsg := validateObject(action, "action")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(actionVal, "name") {
		return nil, "action.name is required and must be a string"
	}
	if errMsg := normalizePropertiesField(actionVal, "action"); errMsg != "" {
		return nil, errMsg
	}
	input["action"] = actionVal

	resourceVal, errMsg := validateObject(resource, "resource")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(resourceVal, "type") {
		return nil, "resource.type is required and must be a string"
	}
	if !hasStringField(resourceVal, "id") {
		return nil, "resource.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(resourceVal, "resource"); errMsg != "" {
		return nil, errMsg
	}
	input["resource"] = resourceVal

	// context is OPTIONAL (Section 5). JSON null is treated as absent.
	if ctx != nil && !isJSONNull(ctx) {
		ctxVal, errMsg := validateObject(ctx, "context")
		if errMsg != "" {
			return nil, errMsg
		}
		input["context"] = ctxVal
	}

	return input, ""
}

// buildSearchInput assembles the OPA input map for a Search API request
// (Section 8). The kind selects which entity is the search target: that
// entity requires only "type" (or "name" for Action) and may omit the
// identifier; the remaining entities are validated as for Access Evaluation.
func buildSearchInput(kind searchKind, subject, action, resource, ctx json.RawMessage) (map[string]any, string) {
	input := map[string]any{}

	// Subject: required for Resource/Action Search (full), partial for Subject Search.
	if subject == nil || isJSONNull(subject) {
		return nil, "subject is required"
	}
	subjectVal, errMsg := validateObject(subject, "subject")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(subjectVal, "type") {
		return nil, "subject.type is required and must be a string"
	}
	if kind == searchSubject {
		// Spec Section 8.4.1: subject.id SHOULD be omitted, and if present MUST be ignored.
		delete(subjectVal, "id")
	} else if !hasStringField(subjectVal, "id") {
		return nil, "subject.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(subjectVal, "subject"); errMsg != "" {
		return nil, errMsg
	}
	input["subject"] = subjectVal

	// Action: required for Subject/Resource Search; omitted for Action Search.
	if kind != searchAction {
		if action == nil || isJSONNull(action) {
			return nil, "action is required"
		}
		actionVal, errMsg := validateObject(action, "action")
		if errMsg != "" {
			return nil, errMsg
		}
		if !hasStringField(actionVal, "name") {
			return nil, "action.name is required and must be a string"
		}
		if errMsg := normalizePropertiesField(actionVal, "action"); errMsg != "" {
			return nil, errMsg
		}
		input["action"] = actionVal
	}
	// Section 10.1.1 requires receivers to ignore unknown fields; a stray
	// "action" key in an Action Search request is silently discarded.

	// Resource: required for Subject/Action Search (full), partial for Resource Search.
	if resource == nil || isJSONNull(resource) {
		return nil, "resource is required"
	}
	resourceVal, errMsg := validateObject(resource, "resource")
	if errMsg != "" {
		return nil, errMsg
	}
	if !hasStringField(resourceVal, "type") {
		return nil, "resource.type is required and must be a string"
	}
	if kind == searchResource {
		// Spec Section 8.5.1: resource.id SHOULD be omitted, and if present MUST be ignored.
		delete(resourceVal, "id")
	} else if !hasStringField(resourceVal, "id") {
		return nil, "resource.id is required and must be a string"
	}
	if errMsg := normalizePropertiesField(resourceVal, "resource"); errMsg != "" {
		return nil, errMsg
	}
	input["resource"] = resourceVal

	if ctx != nil && !isJSONNull(ctx) {
		ctxVal, errMsg := validateObject(ctx, "context")
		if errMsg != "" {
			return nil, errMsg
		}
		input["context"] = ctxVal
	}

	return input, ""
}

// applyObligationNegotiation implements the negotiation rule of the AuthZEN
// Obligations Profile 1.0: a PDP MUST ignore any value in a request's
// `context.supported_obligations` that it did not itself advertise. Only an
// operator who opted in is bound by it, so an unconfigured PDP passes context
// through untouched. An emptied array is kept rather than deleted — a PEP that
// declared only unsupported types has said something, which the profile
// distinguishes from the "no information" of an absent member — while a
// non-array member conveys no capability at all.
func applyObligationNegotiation(input map[string]any, advertised []string) {
	if len(advertised) == 0 {
		return
	}
	ctx, ok := input["context"].(map[string]any)
	if !ok {
		return
	}
	declared, present := ctx["supported_obligations"]
	if !present {
		return
	}
	list, ok := declared.([]any)
	if !ok {
		delete(ctx, "supported_obligations")
		return
	}
	kept := make([]any, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && slices.Contains(advertised, s) {
			kept = append(kept, s)
		}
	}
	ctx["supported_obligations"] = kept
}

// mergeField returns the override if present and non-null, otherwise the default (Section 7.1.1).
// A JSON `null` value is treated as absent. If both are null, nil is returned
// so that the required-field check catches the missing value.
func mergeField(deflt, override json.RawMessage) json.RawMessage {
	if len(override) > 0 && !isJSONNull(override) {
		return override
	}
	if len(deflt) > 0 && !isJSONNull(deflt) {
		return deflt
	}
	return nil
}

// evalErrorResponse builds a per-evaluation error response (Section 7.2.1).
func evalErrorResponse(status int, message string) evaluationResponse {
	errCtx, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"status":  status,
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
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	// Limit request body size to protect against DoS (Section 11.7).
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req evaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// subject, action, resource are required (Section 6.1).
	// A JSON null value is treated the same as absent.
	if req.Subject == nil || isJSONNull(req.Subject) ||
		req.Action == nil || isJSONNull(req.Action) ||
		req.Resource == nil || isJSONNull(req.Resource) {
		jsonError(w, "subject, action, and resource are required", http.StatusBadRequest)
		return
	}

	input, errMsg := buildInput(req.Subject, req.Action, req.Resource, req.Context)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	// Evaluate the decision and its optional context under a single
	// transaction so both observe the same policy/data snapshot.
	txn, err := p.manager.Store.NewTransaction(r.Context(), storage.TransactionParams{})
	if err != nil {
		p.logger.Error("AuthZEN evaluation: failed to create transaction: %v", err)
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}
	defer p.manager.Store.Abort(r.Context(), txn)

	path, decisionRule, ctxRule, obligations := p.configSnapshot()
	applyObligationNegotiation(input, obligations)

	decision, err := p.evalDecision(r.Context(), txn, input, path, decisionRule)
	if err != nil {
		p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "error": err}).Error("AuthZEN evaluation error")
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}

	decisionCtx, err := p.evalDecisionContext(r.Context(), txn, input, path, ctxRule)
	if err != nil {
		p.logger.WithFields(map[string]any{"path": path, "error": err}).Error("AuthZEN decision context error")
		jsonError(w, "evaluation failed", http.StatusInternalServerError)
		return
	}

	p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "decision": decision, "input": input}).Debug("AuthZEN evaluation")

	resp := evaluationResponse{
		Decision: decision,
		Context:  decisionCtx,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("AuthZEN evaluation: failed to encode response: %v", err)
	}
}

// evalDecision evaluates the configured decision rule under the given package
// path and returns the boolean decision. Path and rule come from a single
// configSnapshot.
func (p *AuthZenPlugin) evalDecision(ctx context.Context, txn storage.Transaction, input map[string]any, path, rule string) (bool, error) {
	val, err := p.evalRuleWithTxn(ctx, txn, input, path, rule)
	if err != nil {
		return false, err
	}
	decision, _ := val.(bool)
	return decision, nil
}

// configSnapshot reads the settings that an evaluation request depends on
// under a single lock acquisition, so a request observes one coherent config
// even when a concurrent Reconfigure lands mid-request.
func (p *AuthZenPlugin) configSnapshot() (path, decisionRule, contextRule string, obligations []string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg.Path, p.cfg.Decision, p.cfg.DecisionContext, p.cfg.SupportedObligations
}

// evalDecisionContext evaluates the configured decision-context rule (if any)
// under the given transaction and returns its value as the OPTIONAL `context`
// member of the Decision (Section 5.5.1). It returns a nil RawMessage — so the
// `context` member is omitted — when no rule is configured, the rule is
// undefined, or it yields JSON null or an empty object (nothing to convey).
// The spec requires `context` to be an object, so a non-object result is
// reported as an error. Shares the caller's transaction and configSnapshot
// with the decision evaluation.
func (p *AuthZenPlugin) evalDecisionContext(ctx context.Context, txn storage.Transaction, input map[string]any, path, rule string) (json.RawMessage, error) {
	if rule == "" {
		return nil, nil
	}

	val, err := p.evalRuleWithTxn(ctx, txn, input, path, rule)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	obj, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("decision_context rule %q must return an object; got %T", rule, val)
	}
	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj)
}

// evalRuleWithTxn evaluates an arbitrary rule under the configured package
// path and returns the raw value. Used by both the Access Evaluation and
// Search handlers. An optional existing transaction may be passed; if nil,
// a fresh one is created and aborted on return.
func (p *AuthZenPlugin) evalRuleWithTxn(ctx context.Context, txn storage.Transaction, input map[string]any, path, rule string) (any, error) {
	var err error
	if txn == nil {
		txn, err = p.manager.Store.NewTransaction(ctx, storage.TransactionParams{})
		if err != nil {
			return nil, fmt.Errorf("creating transaction: %w", err)
		}
		defer p.manager.Store.Abort(ctx, txn)
	}

	queryPath := fmt.Sprintf("data.%s.%s", strings.ReplaceAll(path, "/", "."), rule)

	r := rego.New(
		rego.Compiler(p.manager.GetCompiler()),
		rego.Store(p.manager.Store),
		rego.Transaction(txn),
		rego.Input(input),
		rego.Query(queryPath),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	return rs[0].Expressions[0].Value, nil
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

	if !isJSONContentType(r.Header.Get("Content-Type")) {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	// Limit request body size to protect against DoS (Section 11.7).
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req evaluationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Backward compatibility (Section 7.1): if evaluations is absent or empty,
	// behave as a single evaluation — request *and* response. Section 7.2
	// conditions the omission of the top-level `decision` key on the
	// `evaluations` array being present, and the AuthZEN certification
	// scenario (c-3-4-2, c-3-4-3) makes the response side explicit: the PDP
	// "MUST ... return an Access Evaluation response", whose structure the
	// harness validates. So this branch emits the singular shape.
	if len(req.Evaluations) == 0 {
		if req.Subject == nil || isJSONNull(req.Subject) ||
			req.Action == nil || isJSONNull(req.Action) ||
			req.Resource == nil || isJSONNull(req.Resource) {
			jsonError(w, "subject, action, and resource are required", http.StatusBadRequest)
			return
		}
		input, errMsg := buildInput(req.Subject, req.Action, req.Resource, req.Context)
		if errMsg != "" {
			jsonError(w, errMsg, http.StatusBadRequest)
			return
		}
		txn, err := p.manager.Store.NewTransaction(r.Context(), storage.TransactionParams{})
		if err != nil {
			p.logger.Error("AuthZEN evaluation: failed to create transaction: %v", err)
			jsonError(w, "evaluation failed", http.StatusInternalServerError)
			return
		}
		defer p.manager.Store.Abort(r.Context(), txn)

		path, decisionRule, ctxRule, obligations := p.configSnapshot()
		applyObligationNegotiation(input, obligations)
		decision, err := p.evalDecision(r.Context(), txn, input, path, decisionRule)
		if err != nil {
			p.logger.Error("AuthZEN evaluation error: path=%s.%s error=%v", path, decisionRule, err)
			jsonError(w, "evaluation failed", http.StatusInternalServerError)
			return
		}
		decisionCtx, err := p.evalDecisionContext(r.Context(), txn, input, path, ctxRule)
		if err != nil {
			p.logger.WithFields(map[string]any{"path": path, "error": err}).Error("AuthZEN decision context error")
			jsonError(w, "evaluation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(evaluationResponse{Decision: decision, Context: decisionCtx}); err != nil {
			p.logger.Error("AuthZEN evaluations: failed to encode response: %v", err)
		}
		return
	}

	// Limit the number of evaluations to protect against resource
	// exhaustion (Section 11.7).
	if len(req.Evaluations) > maxBatchSize {
		jsonError(w, fmt.Sprintf("evaluations array exceeds maximum size of %d", maxBatchSize), http.StatusRequestEntityTooLarge)
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

	// Snapshot config once for the whole batch: one coherent (path, decision,
	// context, obligations) tuple, and no per-iteration lock churn.
	path, decisionRule, ctxRule, obligations := p.configSnapshot()

	results := make([]evaluationResponse, 0, len(req.Evaluations))

	for _, item := range req.Evaluations {
		merged := evaluationRequest{
			Subject:  mergeField(req.Subject, item.Subject),
			Resource: mergeField(req.Resource, item.Resource),
			Action:   mergeField(req.Action, item.Action),
			Context:  mergeField(req.Context, item.Context),
		}

		if merged.Subject == nil || merged.Action == nil || merged.Resource == nil {
			results = append(results, evalErrorResponse(400, "subject, action, and resource are required"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		input, errMsg := buildInput(merged.Subject, merged.Action, merged.Resource, merged.Context)
		if errMsg != "" {
			results = append(results, evalErrorResponse(400, errMsg))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}
		applyObligationNegotiation(input, obligations)

		decision, err := p.evalDecision(r.Context(), txn, input, path, decisionRule)
		if err != nil {
			p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "error": err}).Error("AuthZEN batch evaluation error")
			results = append(results, evalErrorResponse(500, "evaluation failed"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		p.logger.WithFields(map[string]any{"path": path, "decision_rule": decisionRule, "decision": decision}).Debug("AuthZEN batch evaluation")

		if semantic == semanticDenyOnFirstDeny && !decision {
			// Short-circuit: include reason in context (Section 7.1.2.1).
			results = append(results, evaluationResponse{
				Decision: false,
				Context:  json.RawMessage(`{"code":"200","reason":"deny_on_first_deny"}`),
			})
			break
		}
		if semantic == semanticPermitOnFirstPermit && decision {
			results = append(results, evaluationResponse{
				Decision: true,
				Context:  json.RawMessage(`{"code":"200","reason":"permit_on_first_permit"}`),
			})
			break
		}

		// Surface the optional policy-supplied decision context (Section
		// 5.5.1) on non-short-circuit results. Short-circuit results above
		// carry the plugin's own reason context instead.
		decisionCtx, err := p.evalDecisionContext(r.Context(), txn, input, path, ctxRule)
		if err != nil {
			p.logger.WithFields(map[string]any{"path": path, "error": err}).Error("AuthZEN batch decision context error")
			results = append(results, evalErrorResponse(500, "evaluation failed"))
			if semantic == semanticDenyOnFirstDeny {
				break
			}
			continue
		}

		results = append(results, evaluationResponse{Decision: decision, Context: decisionCtx})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(evaluationsResponse{Evaluations: results}); err != nil {
		p.logger.Error("AuthZEN evaluations: failed to encode response: %v", err)
	}
}

// PDP Metadata endpoint (Section 9).
func (p *AuthZenPlugin) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	// Echo X-Request-ID if present (Section 10.1.3).
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

	// Determine the scheme and host for constructing the base URL.
	// NOTE: The Host header and X-Forwarded-* headers are trusted here.
	// In production, this endpoint should be behind a reverse proxy that
	// overrides or sanitizes these headers. If exposed directly, a client
	// could spoof these values to influence the metadata response.
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
	metadata := pdpMetadata{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpoint: base + "/access/v1/evaluations",
	}

	// Spec Section 9: omit search_*_endpoint when the corresponding rule is
	// unconfigured. Absence is the PEP's signal that the PDP is not capable.
	p.mu.RLock()
	search := p.cfg.Search
	capabilities := p.cfg.Capabilities
	obligations := p.cfg.SupportedObligations
	accessRequestEndpoint := p.cfg.AccessRequestEndpoint
	jwksURI := p.cfg.JWKSURI
	p.mu.RUnlock()
	if search.Subject != "" {
		metadata.SearchSubjectEndpoint = base + "/access/v1/search/subject"
	}
	if search.Resource != "" {
		metadata.SearchResourceEndpoint = base + "/access/v1/search/resource"
	}
	if search.Action != "" {
		metadata.SearchActionEndpoint = base + "/access/v1/search/action"
	}

	// Section 9.1.2: advertise operator-configured capability URNs. The
	// `capabilities` field is omitempty, so an empty list is omitted entirely.
	metadata.Capabilities = capabilities

	metadata.SupportedObligations = obligations

	// Access Request and Approval Profile, "Discovery". The endpoint is an
	// absolute operator-supplied URI rather than one derived from `base`,
	// because the profile permits a service other than the PDP to host it.
	metadata.AccessRequestEndpoint = accessRequestEndpoint
	metadata.JWKSURI = jwksURI

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", metadataCacheControl)
	w.Header().Set("Vary", metadataVary)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		p.logger.Error("AuthZEN well-known: failed to encode response: %v", err)
	}
}

// handleSubjectSearch serves POST /access/v1/search/subject (Section 8.4).
func (p *AuthZenPlugin) handleSubjectSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchSubject)
}

// handleResourceSearch serves POST /access/v1/search/resource (Section 8.5).
func (p *AuthZenPlugin) handleResourceSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchResource)
}

// handleActionSearch serves POST /access/v1/search/action (Section 8.6).
func (p *AuthZenPlugin) handleActionSearch(w http.ResponseWriter, r *http.Request) {
	p.handleSearch(w, r, searchAction)
}

// handleSearch implements the shared lifecycle for all three Search APIs:
// request validation (Section 8), single Rego evaluation, deterministic
// ordering, and stateless pagination over the resulting entity list
// (Section 8.2). The kind selects per-endpoint rules and the configured
// target rule.
func (p *AuthZenPlugin) handleSearch(w http.ResponseWriter, r *http.Request, kind searchKind) {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	p.mu.RLock()
	stopped := p.stopped
	path := p.cfg.Path
	search := p.cfg.Search
	obligations := p.cfg.SupportedObligations
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}

	ruleName := searchRuleName(search, kind)
	if ruleName == "" {
		jsonError(w, "search endpoint not configured", http.StatusNotImplemented)
		return
	}

	if !isJSONContentType(r.Header.Get("Content-Type")) {
		jsonError(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req searchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	input, errMsg := buildSearchInput(kind, req.Subject, req.Action, req.Resource, req.Context)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}
	// Before the pagination hash below, so values the PDP must ignore cannot
	// break a follow-up page.
	applyObligationNegotiation(input, obligations)

	limit, errMsg := resolveSearchLimit(req.Page, search.MaxLimit)
	if errMsg != "" {
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	// Bind subsequent pages to the normalized search input (Section 8.2).
	// Using the post-buildSearchInput map ensures that fields the spec says
	// MUST be ignored (e.g. subject.id on Subject Search) cannot break a
	// follow-up page just because the client did or didn't echo them back.
	reqHash := searchRequestHash(input, limit)
	offset := 0
	if req.Page != nil && req.Page.Token != "" {
		tok, err := decodePageToken(req.Page.Token)
		if err != nil {
			jsonError(w, "invalid page token", http.StatusBadRequest)
			return
		}
		if tok.Hash != reqHash {
			jsonError(w, "page token does not match request", http.StatusBadRequest)
			return
		}
		offset = tok.Offset
	}

	raw, err := p.evalRuleWithTxn(r.Context(), nil, input, path, ruleName)
	if err != nil {
		p.logger.WithFields(map[string]any{"path": path, "rule": ruleName, "error": err}).Error("AuthZEN search error")
		jsonError(w, "search evaluation failed", http.StatusInternalServerError)
		return
	}

	entities, errMsg := normaliseSearchResults(raw, kind)
	if errMsg != "" {
		p.logger.WithFields(map[string]any{"path": path, "rule": ruleName, "error": errMsg}).Error("AuthZEN search: invalid policy result")
		jsonError(w, "search evaluation failed", http.StatusInternalServerError)
		return
	}

	total := len(entities)
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	page := entities[offset:end]
	pageCount := len(page)

	resp := searchResponse{Results: page}
	// next_token is REQUIRED whenever the response does not contain the
	// entire result set (Section 8.2.2). Always emit a page object so
	// pagination state is unambiguous.
	nextToken := ""
	if end < total {
		nextToken = encodePageToken(pageToken{Offset: end, Hash: reqHash})
	}
	totalCopy := total
	countCopy := pageCount
	resp.Page = &pageResponse{
		NextToken: nextToken,
		Count:     &countCopy,
		Total:     &totalCopy,
	}

	p.logger.WithFields(map[string]any{
		"path":     path,
		"rule":     ruleName,
		"kind":     kind,
		"total":    total,
		"returned": pageCount,
		"offset":   offset,
	}).Debug("AuthZEN search")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("AuthZEN search: failed to encode response: %v", err)
	}
}

// searchRuleName returns the configured Rego rule for the given search kind,
// or the empty string if the endpoint is disabled.
func searchRuleName(s SearchConfig, kind searchKind) string {
	switch kind {
	case searchSubject:
		return s.Subject
	case searchResource:
		return s.Resource
	case searchAction:
		return s.Action
	}
	return ""
}

// resolveSearchLimit applies request and configuration bounds to the page
// limit. A negative limit is rejected; an unset limit means "no per-page
// cap" beyond the configured maximum.
func resolveSearchLimit(page *pageRequest, configMax int) (int, string) {
	maxLimit := configMax
	if maxLimit <= 0 {
		maxLimit = defaultSearchMaxLimit
	}
	if page == nil || page.Limit == nil {
		return maxLimit, ""
	}
	if *page.Limit < 0 {
		return 0, "page.limit must be non-negative"
	}
	if *page.Limit == 0 || *page.Limit > maxLimit {
		return maxLimit, ""
	}
	return *page.Limit, ""
}

// normaliseSearchResults coerces the Rego query result to a JSON-serializable
// list of entity objects. The plugin accepts either an array or a set; each
// element must itself be a JSON object so callers can rely on the AuthZEN
// information model (Section 5). Each entity is further required to carry
// the identifying field for the searched-for type (Section 8.3: results
// MUST contain only entities of the type being searched for): `type` for
// Subject/Resource Search and `name` for Action Search. Results are sorted
// by a stable identifier key so pagination is deterministic.
func normaliseSearchResults(raw any, kind searchKind) ([]any, string) {
	if raw == nil {
		return []any{}, ""
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Sprintf("search rule must return an array; got %T", raw)
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Sprintf("search rule must return objects; got %T", item)
		}
		if errMsg := validateSearchEntity(obj, kind); errMsg != "" {
			return nil, errMsg
		}
		out = append(out, obj)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return searchEntityKey(out[i].(map[string]any), kind) < searchEntityKey(out[j].(map[string]any), kind)
	})
	return out, ""
}

// validateSearchEntity enforces Section 8.3 ("results MUST contain only
// entities of the type being searched for") together with the Section 5
// entity shape: string `type` and `id` for Subject and Resource, string
// `name` for Action.
//
// A policy that omits one of these fields would return an entity that the
// PEP could not feed back into Access Evaluation (since `id`/`name` is
// also required there), so we reject it as a policy-authoring error.
func validateSearchEntity(entity map[string]any, kind searchKind) string {
	if kind == searchAction {
		if !hasStringField(entity, "name") {
			return "action search rule must return entities with a string `name` field"
		}
		return ""
	}
	prefix := "subject"
	if kind == searchResource {
		prefix = "resource"
	}
	if !hasStringField(entity, "type") {
		return prefix + " search rule must return entities with a string `type` field"
	}
	if !hasStringField(entity, "id") {
		return prefix + " search rule must return entities with a string `id` field"
	}
	return ""
}

// searchEntityKey extracts a stable string key for an entity, used solely
// for ordering between pages. Falls back to the JSON encoding when the
// natural identifier is absent.
func searchEntityKey(entity map[string]any, kind searchKind) string {
	if kind == searchAction {
		if name, ok := entity["name"].(string); ok {
			return name
		}
	} else {
		t, _ := entity["type"].(string)
		id, _ := entity["id"].(string)
		if t != "" || id != "" {
			return t + "\x00" + id
		}
	}
	b, _ := json.Marshal(entity)
	return string(b)
}

// searchRequestHash binds a pagination token to the normalized search input
// and effective page limit. Hashing the post-validation input (rather than
// the raw request body) keeps the hash stable across spec-ignored fields
// such as subject.id on Subject Search, while still detecting changes to
// any field that affects the query semantics. Section 8.2 requires the PDP
// to detect when callers change parameters mid-pagination.
func searchRequestHash(input map[string]any, limit int) string {
	h := sha256.New()
	// json.Marshal sorts map keys alphabetically, so equivalent inputs
	// always produce the same byte sequence regardless of YAML/Rego order.
	canon, _ := json.Marshal(input)
	_, _ = h.Write(canon)
	_, _ = fmt.Fprintf(h, "\x00limit\x00%d\x00", limit)
	return hex.EncodeToString(h.Sum(nil))
}

// encodePageToken returns a URL-safe base64 representation of the page
// token. The token is opaque to clients (Section 8.2).
func encodePageToken(t pageToken) string {
	b, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodePageToken reverses encodePageToken, returning an error if the token
// is not a valid base64-encoded pageToken JSON object.
func decodePageToken(s string) (pageToken, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageToken{}, err
	}
	var t pageToken
	if err := json.Unmarshal(b, &t); err != nil {
		return pageToken{}, err
	}
	if t.Offset < 0 {
		return pageToken{}, fmt.Errorf("negative offset")
	}
	return t, nil
}
