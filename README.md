# opa-authzen-plugin

An extended version of OPA (**OPA-AuthZEN**) that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) as a native OPA plugin.

## Architecture

```text
┌──────────────────────────────────────────────────┐
│               OPA Process (:8181)                │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │           OPA HTTP Server                  │  │
│  │                                            │  │
│  │  Built-in Routes       AuthZEN Routes      │  │
│  │  ┌──────────────┐  ┌───────────────────┐   │  │
│  │  │ POST /v1/    │  │ POST /access/v1/  │   │  │
│  │  │   data/...   │  │   evaluation      │   │  │
│  │  │ GET /health  │  │ POST /access/v1/  │   │  │
│  │  │ ...          │  │   evaluations     │   │  │
│  │  └──────────────┘  │ GET /.well-known/ │   │  │
│  │                    │   authzen-config. │   │  │
│  │                    └─────────┬─────────┘   │  │
│  └──────────────────────────────┼─────────────┘  │
│                                 │                │
│  ┌──────────────────────────────▼─────────────┐  │
│  │        AuthZEN Plugin (ExtraRoute)         │  │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐   │  │
│  │  │ Validate│  │ Evaluate │  │ Metadata │   │  │
│  │  │ Request │─▶│  Policy  │  │ Endpoint │   │  │
│  │  └─────────┘  └─────┬────┘  └──────────┘   │  │
│  └─────────────────────┼──────────────────────┘  │
│                        │                         │
│  ┌─────────────────────▼──────────────────────┐  │
│  │          OPA Rego Engine + Store           │  │
│  │  ┌──────────┐  ┌───────────┐  ┌─────────┐  │  │
│  │  │ Compiler │  │ In-Memory │  │ Bundles │  │  │
│  │  │          │  │   Store   │  │         │  │  │
│  │  └──────────┘  └───────────┘  └─────────┘  │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

The plugin registers AuthZEN endpoints directly on OPA's own HTTP server (`:8181`) using OPA's `ExtraRoute` extension point. This means AuthZEN routes get OPA's built-in Prometheus metrics, OpenTelemetry tracing, and server authorization automatically — no separate port or listener required.

## AuthZEN 1.0 Compliance

| Spec Section | Feature | Status |
|-------------|---------|--------|
| Section 5 | Information Model (Subject, Action, Resource, Context, Decision) | ✅ Supported |
| Section 6 | Access Evaluation API (`POST /access/v1/evaluation`) | ✅ Supported |
| Section 7 | Access Evaluations API (`POST /access/v1/evaluations`) | ✅ Supported |
| Section 7.1.1 | Default value merging for batch evaluations | ✅ Supported |
| Section 7.1.2.1 | Evaluation semantics (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`) | ✅ Supported |
| Section 8 | Search APIs (Subject, Resource, Action) | ✅ Supported (opt-in via `search` config) |
| Section 8.2 | Search pagination (stateless opaque token) | ✅ Supported |
| Section 9 | PDP Metadata (`GET /.well-known/authzen-configuration`) | ✅ Supported |
| Section 10.1 | HTTPS Transport Binding (JSON serialization, Content-Type validation) | ✅ Supported |
| Section 10.1.3 | X-Request-ID echo | ✅ Supported |
| Section 11.7 | Request payload protection (body size limit, batch size limit) | ✅ Supported |
| [Obligations Profile 1.0](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html) | Obligation discovery and PEP-capability negotiation | ✅ Supported (opt-in via `supported_obligations`) |

## Issue Management

Use [GitHub Issues](https://github.com/kanywst/opa-authzen-plugin/issues) to request features or file bugs.

## Quick Start

1. Build the plugin.

    ```bash
    make build
    ```

2. Create a policy file `policy.rego`:

    ```rego
    package authzen

    default allow = false

    allow if input.subject.properties.role == "admin"

    allow if {
        input.action.name == "read"
        input.subject.id != ""
    }
    ```

3. Create a config file `config.yaml`:

    ```yaml
    plugins:
      authzen:
        path: "authzen"
        decision: "allow"
    ```

4. Run the plugin.

    ```bash
    ./opa-authzen-plugin run --server --config-file config.yaml policy.rego
    ```

    This starts OPA on `:8181` with the AuthZEN endpoints registered on the same server.

5. Send an AuthZEN evaluation request.

    ```bash
    curl -s -X POST http://localhost:8181/access/v1/evaluation \
      -H "Content-Type: application/json" \
      -d '{
        "subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
        "resource": {"type": "document", "id": "doc-123"},
        "action": {"name": "delete"}
      }'
    ```

    The response should be:

    ```json
    {"decision":true}
    ```

6. Send a batch evaluation request.

    ```bash
    curl -s -X POST http://localhost:8181/access/v1/evaluations \
      -H "Content-Type: application/json" \
      -d '{
        "subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
        "action": {"name": "read"},
        "evaluations": [
          {"resource": {"type": "document", "id": "doc-1"}},
          {"resource": {"type": "document", "id": "doc-2"}},
          {"action": {"name": "delete"}, "resource": {"type": "document", "id": "doc-3"}}
        ]
      }'
    ```

    The response should be:

    ```json
    {"evaluations":[{"decision":true},{"decision":true},{"decision":true}]}
    ```

    Top-level `subject`, `action`, `resource`, and `context` serve as defaults for each item in the `evaluations` array. Individual items can override any of these fields. See [Section 7](https://openid.net/specs/authorization-api-1_0.html#section-7) of the AuthZEN spec for details on evaluation semantics (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`).

7. Use evaluation semantics to short-circuit batch processing.

    ```bash
    curl -s -X POST http://localhost:8181/access/v1/evaluations \
      -H "Content-Type: application/json" \
      -d '{
        "subject": {"type": "user", "id": "bob"},
        "action": {"name": "read"},
        "options": {"evaluations_semantic": "permit_on_first_permit"},
        "evaluations": [
          {"resource": {"type": "document", "id": "doc-1"}},
          {"resource": {"type": "document", "id": "doc-2"}}
        ]
      }'
    ```

8. Check the well-known metadata endpoint.

    ```bash
    curl -s http://localhost:8181/.well-known/authzen-configuration | jq .
    ```

    Response:

    ```json
    {
      "policy_decision_point": "http://localhost:8181",
      "access_evaluation_endpoint": "http://localhost:8181/access/v1/evaluation",
      "access_evaluations_endpoint": "http://localhost:8181/access/v1/evaluations"
    }
    ```

## API Gateway Integration

opa-authzen-plugin can serve as a standards-based PDP behind any API gateway
that supports external authorization. The
[`example/envoy-gateway/`](./example/envoy-gateway/) directory demonstrates
this pattern with Envoy proxy:

```text
Client → Envoy → ext-authz-bridge → opa-authzen-plugin (AuthZEN PDP)
                                          ↓
                                     OPA Rego policy
```

A thin translation layer (ext-authz-bridge) converts gateway-specific
protocols (e.g., Envoy ext_authz gRPC) into AuthZEN evaluation requests. The
PDP itself is **gateway-agnostic** — it can serve any AuthZEN-compatible PEP
(Kong, AWS API Gateway, Tyk, etc.) without modification.

This differs from
[opa-envoy-plugin](https://github.com/open-policy-agent/opa-envoy-plugin),
which embeds Envoy's gRPC ext_authz protocol directly into OPA.
opa-authzen-plugin uses the
[OpenID AuthZEN standard](https://openid.net/specs/authorization-api-1_0.html)
as the protocol between the gateway and PDP.

```bash
cd example/envoy-gateway
docker compose up --build
# Test
curl -i -H "X-User: rick" http://localhost:9000/todos    # → 200
curl -i -X POST -H "X-User: jerry" http://localhost:9000/todos  # → 403
```

## Docker

```bash
make docker-build
make docker-run
```

The published image is `ghcr.io/kanywst/opa-authzen-plugin`. Pass `--addr 0.0.0.0:8181` when you publish the port: OPA binds `localhost` by default, so a container started without it accepts no connections from outside itself.

```bash
docker run --rm -p 8181:8181 -v "$PWD/example:/example:ro" \
  ghcr.io/kanywst/opa-authzen-plugin:latest \
  run --server --addr 0.0.0.0:8181 --config-file /example/config.yaml /example/policy.rego
```

## Configuration

The plugin is configured under the `plugins.authzen` key in the OPA config file:

| Key                 | Type   | Default   | Description                                                              |
| ------------------- | ------ | --------- | ------------------------------------------------------------------------ |
| `path`              | string | `authzen` | OPA package path to query                                                |
| `decision`          | string | `allow`   | Rule name within the package that produces the boolean decision          |
| `decision_context`  | string | _(unset)_ | Rule name whose object value is returned as the Decision's optional `context` |
| `search.subject`    | string | _(unset)_ | Rule name returning the set of permitted subjects (enables Subject Search)  |
| `search.resource`   | string | _(unset)_ | Rule name returning the set of permitted resources (enables Resource Search) |
| `search.action`     | string | _(unset)_ | Rule name returning the set of permitted actions (enables Action Search)    |
| `search.max_limit`  | int    | `1000`    | Per-page cap; client `page.limit` is clamped to this value               |
| `capabilities`      | array  | _(unset)_ | PDP capability URNs advertised in the `capabilities` field of the PDP metadata |
| `supported_obligations` | array | _(unset)_ | Obligation Types advertised in the PDP metadata; also bounds the PEP-declared set on each request |

If a `search.*` rule is unset, the corresponding endpoint responds with 501 and is omitted from the PDP metadata (spec Section 9). Each configured rule must be defined in the package given by `path` and return a set/array of entity objects.

When `decision_context` is set, the named rule is evaluated alongside the decision (under the same policy/data snapshot) and its result is returned as the Decision's optional `context` member (spec Section 5.5.1), letting a policy convey reasons, obligations, or other metadata. The rule must evaluate to a JSON object; an undefined result or an empty object omits `context`, and a non-object result fails the request. `decision_context` is unset by default, so responses carry only `decision` unless you opt in.

The AuthZEN core specification registers no capability URNs of its own (the IANA "AuthZEN Policy Decision Point Capabilities" registry is populated by profiles and vendors), so `capabilities` is operator-supplied. Each entry must be a URN (start with `urn:`); the list is omitted from the metadata when empty. For example, a deployment that implements the [Access Request and Approval profile](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html) on top of this plugin would advertise `urn:openid:authzen:capability:access-request`.

### Obligations Profile

`supported_obligations` opts the PDP into the [AuthZEN Obligations Profile 1.0](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html). Set it to the Obligation Types your policies may issue — a type registered in the "AuthZEN Obligation Types" registry (`step-up`, `notification`, `session_termination`) or the literal `custom`. The registry is IANA "Specification Required" and therefore extensible, so unregistered values are accepted; only empty entries are rejected at startup.

The list does two things. It is advertised as the `supported_obligations` member of the PDP metadata, so a PEP can discover which types it must be prepared to execute. And it bounds the PEP's own `context.supported_obligations` array on each request: the profile requires a PDP to ignore any declared value it did not itself advertise, so the plugin filters the member before the input reaches Rego. Your policy can therefore read `input.context.supported_obligations` and trust every entry is a type this PDP is configured to issue. A member that survives filtering as an empty array is kept — a PEP declaring only unsupported types is telling you something, which the profile distinguishes from an absent member — while a member that is not an array at all is removed.

The obligations themselves ride in the Decision `context`, which the `decision_context` rule supplies, so a policy issuing obligations sets both keys:

```yaml
plugins:
  authzen:
    decision_context: obligations_ctx
    supported_obligations:
      - step-up
      - notification
```

```rego
package authzen

obligations_ctx := {"obligations": [{
    "id": "step-up-1",
    "type": "step-up",
    "properties": {"acr_value": "urn:com:example:loa:3"}
}]} if {
    not allow
    "step-up" in input.context.supported_obligations
}
```

Leaving `supported_obligations` unset means the PDP does not implement the profile: the metadata member is omitted and request context reaches the policy untouched. If your policy already reads `input.context.supported_obligations` for its own purposes, note that opting in changes what it sees.

The plugin paginates over the **entire** result set returned by the Rego rule, sorting by the entity's `type`+`id` (or `name` for actions) so page boundaries are stable across requests. If your search rules can return very large candidate sets (tens of thousands), prefer filtering inside Rego rather than relying on the plugin's per-page slicing — the rule still runs once per page request, so heavy candidate sets are paid for every call.

## API Reference

### `POST /access/v1/evaluation`

Single access evaluation. Request body:

```json
{
  "subject":  {"type": "user", "id": "alice@example.com"},
  "action":   {"name": "can_read"},
  "resource": {"type": "account", "id": "123"},
  "context":  {"time": "2024-10-26T01:22-07:00"}
}
```

Response: `{"decision": true}`

### `POST /access/v1/evaluations`

Batch access evaluations with default value merging and evaluation semantics. See [example/](./example/) for detailed usage.

### `POST /access/v1/search/subject`

Subject Search (spec Section 8.4). Requires `search.subject` to be configured. Request body:

```json
{
  "subject":  {"type": "user"},
  "action":   {"name": "can_read"},
  "resource": {"type": "account", "id": "123"},
  "page":     {"limit": 100}
}
```

Response:

```json
{
  "page": {"next_token": "", "count": 2, "total": 2},
  "results": [
    {"type": "user", "id": "alice@example.com"},
    {"type": "user", "id": "bob@example.com"}
  ]
}
```

### `POST /access/v1/search/resource`

Resource Search (spec Section 8.5). Requires `search.resource`. Same response shape as Subject Search; `results` are resource entities.

### `POST /access/v1/search/action`

Action Search (spec Section 8.6). Requires `search.action`. Request omits the `action` key. `results` are action entities of shape `{"name": "..."}`.

### `GET /.well-known/authzen-configuration`

PDP metadata discovery endpoint (Section 9).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
