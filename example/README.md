# Example Usage

This directory contains example configuration and policy files for opa-authzen-plugin.

## Examples

| Directory                          | Description                                              |
| ---------------------------------- | -------------------------------------------------------- |
| [Basic](./README.md#files)         | Simple RBAC + context-based policy (this file)           |
| [todo/](./todo/)                   | AuthZEN Interop Todo scenario (RBAC + resource ownership) |
| [abac/](./abac/)                   | Attribute-Based Access Control (clearance, department)    |
| [envoy-gateway/](./envoy-gateway/) | Envoy proxy + AuthZEN PDP integration (docker compose)    |

## Files

- `config.yaml` — OPA configuration with the AuthZEN plugin enabled
- `policy.rego` — Example Rego policy for AuthZEN evaluation

## Running

```bash
./opa-authzen-plugin run --server --config-file example/config.yaml example/policy.rego
```

## Example Requests

### Single Evaluation (Section 6)

```bash
# Admin role — should be allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
    "resource": {"type": "document", "id": "doc-123"},
    "action": {"name": "delete"}
  }'
# → {"decision":true}

# Read access for authenticated user — should be allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "resource": {"type": "document", "id": "doc-123"},
    "action": {"name": "read"}
  }'
# → {"decision":true}

#  Non-admin write — should be denied
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "resource": {"type": "document", "id": "doc-123"},
    "action": {"name": "write"}
  }'
# → {"decision":false}
```

### Evaluation with Context (Section 5.4)

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "resource": {"type": "office", "id": "building-a"},
    "action": {"name": "access"},
    "context": {"business_hours": true}
  }'
# → {"decision":true}
```

### Batch Evaluations with Defaults (Section 7.1.1)

Top-level fields act as defaults; individual items override them.

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
# → {"evaluations":[{"decision":true},{"decision":true},{"decision":true}]}
```

### Evaluation Semantics (Section 7.1.2.1)

#### `deny_on_first_deny` — stop on first denial

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "action": {"name": "read"},
    "options": {"evaluations_semantic": "deny_on_first_deny"},
    "evaluations": [
      {"resource": {"type": "document", "id": "doc-1"}},
      {"action": {"name": "delete"}, "resource": {"type": "document", "id": "doc-2"}},
      {"resource": {"type": "document", "id": "doc-3"}}
    ]
  }'
# Second evaluation (delete by non-admin) is denied → stops.
# Third evaluation is never executed.
```

#### `permit_on_first_permit` — stop on first permit

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "options": {"evaluations_semantic": "permit_on_first_permit"},
    "evaluations": [
      {"action": {"name": "delete"}, "resource": {"type": "document", "id": "doc-1"}},
      {"action": {"name": "read"}, "resource": {"type": "document", "id": "doc-2"}},
      {"action": {"name": "delete"}, "resource": {"type": "document", "id": "doc-3"}}
    ]
  }'
# First evaluation (delete by non-admin) is denied.
# Second evaluation (read) is permitted → stops.
# Third evaluation is never executed.
```

### X-Request-ID (Section 10.1.3)

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: my-trace-id-123" \
  -d '{
    "subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
    "resource": {"type": "document", "id": "doc-1"},
    "action": {"name": "read"}
  }' -D -
# Response includes: X-Request-ID: my-trace-id-123
```

### PDP Metadata (Section 9)

```bash
curl -s http://localhost:8181/.well-known/authzen-configuration | jq .
# → {
#   "policy_decision_point": "http://localhost:8181",
#   "access_evaluation_endpoint": "http://localhost:8181/access/v1/evaluation",
#   "access_evaluations_endpoint": "http://localhost:8181/access/v1/evaluations"
# }
```
