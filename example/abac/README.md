# ABAC Example

Attribute-Based Access Control using subject properties (department,
clearance level), resource properties (classification, department),
and context (business hours).

## Rules

| Action    | Condition                                                          |
| --------- | ------------------------------------------------------------------ |
| `read`    | Subject clearance >= resource classification                       |
| `write`   | Subject clearance >= resource classification AND same department   |
| `approve` | Subject has `secret` clearance AND within business hours (context) |

Clearance hierarchy: `public` < `internal` < `confidential` < `secret`

## Running

```bash
./opa-authzen-plugin run --server \
  --config-file example/abac/config.yaml \
  example/abac/policy.rego
```

## Example Requests

### Read: clearance check

```bash
# "confidential" clearance reading an "internal" doc — allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice", "properties": {"clearance": "confidential", "department": "engineering"}},
    "resource": {"type": "document", "id": "doc-1", "properties": {"classification": "internal", "department": "engineering"}},
    "action": {"name": "read"}
  }'
# → {"decision":true}

# "internal" clearance reading a "secret" doc — denied
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob", "properties": {"clearance": "internal", "department": "engineering"}},
    "resource": {"type": "document", "id": "doc-2", "properties": {"classification": "secret", "department": "engineering"}},
    "action": {"name": "read"}
  }'
# → {"decision":false}
```

### Write: clearance + department match

```bash
# Same department, sufficient clearance — allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice", "properties": {"clearance": "confidential", "department": "engineering"}},
    "resource": {"type": "document", "id": "doc-1", "properties": {"classification": "internal", "department": "engineering"}},
    "action": {"name": "write"}
  }'
# → {"decision":true}

# Different department — denied
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice", "properties": {"clearance": "confidential", "department": "engineering"}},
    "resource": {"type": "document", "id": "doc-3", "properties": {"classification": "internal", "department": "finance"}},
    "action": {"name": "write"}
  }'
# → {"decision":false}
```

### Approve: top clearance + context

```bash
# Secret clearance during business hours — allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "carol", "properties": {"clearance": "secret", "department": "legal"}},
    "resource": {"type": "document", "id": "doc-4", "properties": {"classification": "secret", "department": "legal"}},
    "action": {"name": "approve"},
    "context": {"business_hours": true}
  }'
# → {"decision":true}

# Secret clearance but outside business hours — denied
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "carol", "properties": {"clearance": "secret", "department": "legal"}},
    "resource": {"type": "document", "id": "doc-4", "properties": {"classification": "secret", "department": "legal"}},
    "action": {"name": "approve"},
    "context": {"business_hours": false}
  }'
# → {"decision":false}
```
