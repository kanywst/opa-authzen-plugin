# Envoy Gateway + AuthZEN Integration

Demonstrates using opa-authzen-plugin as a standards-based PDP behind an Envoy proxy, with the Todo scenario from the [AuthZEN Interop](https://authzen-interop.net/docs/scenarios/todo-1.1/).

## Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │              docker compose                  │
                     │                                              │
  curl               │  ┌────────┐  gRPC    ┌─────────────────┐   │
  ──────────────────┼─►│ Envoy  │────────►│ ext-authz-bridge │   │
  localhost:9000     │  │ :9000  │ext_authz │ :3001            │   │
                     │  └───┬────┘         └──────┬────────────┘   │
                     │      │                     │ HTTP POST      │
                     │      │ if allowed          │ /access/v1/    │
                     │      ▼                     │ evaluation     │
                     │  ┌────────┐         ┌──────▼────────────┐   │
                     │  │backend │         │ opa-authzen-plugin │   │
                     │  │ :8080  │         │ :8181              │   │
                     │  └────────┘         │ (todo policy)      │   │
                     │                     └───────────────────┘   │
                     └──────────────────────────────────────────────┘
```

1. Client sends an HTTP request to Envoy with an `X-User` header
2. Envoy calls the **ext-authz-bridge** via gRPC ext_authz
3. The bridge translates the request into an [AuthZEN Access Evaluation](https://openid.net/specs/authorization-api-1_0.html) call and POSTs it to opa-authzen-plugin
4. OPA evaluates the Todo Rego policy and returns `{"decision": true/false}`
5. Envoy forwards to the backend (allowed) or returns 403 (denied)

### How this differs from opa-envoy-plugin

[opa-envoy-plugin](https://github.com/open-policy-agent/opa-envoy-plugin) embeds Envoy's gRPC ext_authz protocol directly into OPA. This example uses a thin translation layer (ext-authz-bridge) between the gateway and a **standards-based AuthZEN PDP** — the PDP itself is completely gateway-agnostic. The same opa-authzen-plugin instance could serve Kong, AWS API Gateway, or any other AuthZEN-compatible PEP without modification.

## Authorization Matrix

Uses the same policy as [example/todo](../todo/):

| Action            | admin (Rick) | evil_genius (Rick) | editor (Morty, Summer) | viewer (Beth, Jerry) |
| ----------------- | :----------: | :----------------: | :--------------------: | :------------------: |
| `can_read_user`   |    allow     |       allow        |         allow          |        allow         |
| `can_read_todos`  |    allow     |       allow        |         allow          |        allow         |
| `can_create_todo` |    allow     |         —          |         allow          |       **deny**       |
| `can_update_todo` | allow (any)  |    allow (any)     |    allow (own only)    |       **deny**       |
| `can_delete_todo` | allow (any)  |         —          |    allow (own only)    |       **deny**       |

### HTTP → AuthZEN Mapping

The ext-authz-bridge maps HTTP requests to AuthZEN actions:

| HTTP Method | Path               | AuthZEN Action    |
| ----------- | ------------------ | ----------------- |
| GET         | /users, /users/:id | `can_read_user`   |
| GET         | /todos, /todos/:id | `can_read_todos`  |
| POST        | /todos             | `can_create_todo` |
| PUT         | /todos/:id         | `can_update_todo` |
| DELETE      | /todos/:id         | `can_delete_todo` |

## Running

```bash
docker compose up --build
```

## Testing

### Manual

```bash
# Admin can read todos
curl -i -H "X-User: rick" http://localhost:9000/todos
# → 200

# Viewer cannot create todos
curl -i -X POST -H "X-User: jerry" -H "Content-Type: application/json" \
  -d '{}' http://localhost:9000/todos
# → 403

# Admin can delete any todo
curl -i -X DELETE -H "X-User: rick" http://localhost:9000/todos/todo-1
# → 204

# Missing user header → denied
curl -i http://localhost:9000/todos
# → 403
```

### Automated

```bash
./test.sh
```

## Limitations

- **No resource ownership** in the bridge: The ext-authz-bridge does not pass `resource.properties.ownerID` because it has no access to the todo database. This means editor ownership checks (e.g., "Morty can only update his own todos") are not fully demonstrated. Admin and evil_genius actions work correctly since the policy allows them on any resource.
- **Simplified authentication**: Uses `X-User` header instead of JWT. A production deployment would extract the subject from a Bearer token.

## Cleanup

```bash
docker compose down --rmi local
```
