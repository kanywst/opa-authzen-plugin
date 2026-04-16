# Todo App Example

Role-based authorization for a Todo application, based on the
[AuthZEN Interop Todo scenario](https://authzen-interop.net/docs/scenarios/todo-1.1/).

## Authorization Matrix

| Action            | admin (Rick) | evil_genius (Rick) | editor (Morty, Summer) | viewer (Beth, Jerry) |
| ----------------- | :----------: | :----------------: | :--------------------: | :------------------: |
| `can_read_user`   |    allow     |       allow        |         allow          |        allow         |
| `can_read_todos`  |    allow     |       allow        |         allow          |        allow         |
| `can_create_todo` |    allow     |         —          |         allow          |       **deny**       |
| `can_update_todo` | allow (any)  |    allow (any)     |    allow (own only)    |       **deny**       |
| `can_delete_todo` | allow (any)  |         —          |    allow (own only)    |       **deny**       |

## Running

```bash
./opa-authzen-plugin run --server \
  --config-file example/todo/config.yaml \
  example/todo/policy.rego \
  example/todo/users.json
```

## Example Requests

### Admin can delete any todo

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "rick"},
    "resource": {"type": "todo", "id": "todo-1", "properties": {"ownerID": "morty@the-citadel.com"}},
    "action": {"name": "can_delete_todo"}
  }'
# → {"decision":true}
```

### Editor can only update their own todos

```bash
# Morty updating his own todo — allowed
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "morty"},
    "resource": {"type": "todo", "id": "todo-1", "properties": {"ownerID": "morty@the-citadel.com"}},
    "action": {"name": "can_update_todo"}
  }'
# → {"decision":true}

# Morty updating Rick's todo — denied
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "morty"},
    "resource": {"type": "todo", "id": "todo-2", "properties": {"ownerID": "rick@the-citadel.com"}},
    "action": {"name": "can_update_todo"}
  }'
# → {"decision":false}
```

### Viewer cannot create todos

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "jerry"},
    "resource": {"type": "todo", "id": "todo-1"},
    "action": {"name": "can_create_todo"}
  }'
# → {"decision":false}
```

### Batch: check multiple permissions at once (Section 7)

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "morty"},
    "resource": {"type": "todo", "id": "todo-1", "properties": {"ownerID": "morty@the-citadel.com"}},
    "evaluations": [
      {"action": {"name": "can_read_todos"}},
      {"action": {"name": "can_update_todo"}},
      {"action": {"name": "can_delete_todo"}}
    ]
  }'
# → {"evaluations":[{"decision":true},{"decision":true},{"decision":true}]}
```
