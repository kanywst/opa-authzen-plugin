package authzen

import rego.v1

default allow := false

# Resolve user from subject ID (base64-encoded PID)
user := data.users[input.subject.id]

# Every authorization rule below carries the action's expected resource
# type as an explicit precondition. This keeps `allow` from silently
# matching cross-type requests (e.g. asking whether a user resource is
# `can_update_todo`), which becomes user-visible once the Search APIs
# re-evaluate `allow` against candidate entities. The original interop
# test cases continue to pass because they always use the correct
# resource type for each action.

# can_read_user: any authenticated user, on a user-typed resource.
allow if {
	input.action.name == "can_read_user"
	input.resource.type == "user"
	user
}

# can_read_todos: any authenticated user, on a todo-typed resource.
allow if {
	input.action.name == "can_read_todos"
	input.resource.type == "todo"
	user
}

# can_create_todo: allow for admin or editor roles, on a todo-typed resource.
allow if {
	input.action.name == "can_create_todo"
	input.resource.type == "todo"
	some role in user.roles
	role in {"admin", "editor"}
}

# can_update_todo: admin or evil_genius can update any todo. (Note that
# can_delete_todo deliberately only grants admin; evil_genius is
# scoped to updates per the original interop scenario.)
allow if {
	input.action.name == "can_update_todo"
	input.resource.type == "todo"
	some role in user.roles
	role in {"admin", "evil_genius"}
}

# can_update_todo: editor can update only their own todos.
allow if {
	input.action.name == "can_update_todo"
	input.resource.type == "todo"
	"editor" in user.roles
	input.resource.properties.ownerID == user.email
}

# can_delete_todo: admin can delete any todo.
allow if {
	input.action.name == "can_delete_todo"
	input.resource.type == "todo"
	"admin" in user.roles
}

# can_delete_todo: editor can delete only their own todos.
allow if {
	input.action.name == "can_delete_todo"
	input.resource.type == "todo"
	"editor" in user.roles
	input.resource.properties.ownerID == user.email
}

# --- AuthZEN Search APIs (spec Section 8) -----------------------------------
# These rules are queried by the opa-authzen-plugin when the matching
# `search.*` field is set in config.yaml. Each rule enumerates candidate
# entities and re-evaluates `allow` with the candidate filled in, so search
# semantics stay consistent with single-evaluation semantics.

known_actions := {
	"can_read_user",
	"can_read_todos",
	"can_create_todo",
	"can_update_todo",
	"can_delete_todo",
}

# Subject Search: users (by PID) that would be permitted for the input
# action + resource. `input.subject.id` is absent (spec Section 8.1).
# Gated on `input.subject.type == "user"` so a request searching for a
# different subject type can't fall through and enumerate users — the
# same cross-type leak guard used on resource_search branches.
subject_search contains {"type": "user", "id": pid} if {
	input.subject.type == "user"
	some pid, _ in data.users
	allow with input as {
		"subject": {"type": "user", "id": pid},
		"action": input.action,
		"resource": input.resource,
	}
}

# Resource Search: enumerate resources of the requested type that the input
# subject can act upon (spec Section 8.2). Each rule branch is gated on
# `input.resource.type` so a request for one type cannot leak results of
# another. The todo branch carries the owner from data so ownership-based
# rules apply correctly; the user branch covers `can_read_user`, which
# treats user records as resources.

resource_search contains item if {
	input.resource.type == "todo"
	some tid, todo in data.todos
	item := {
		"type": "todo",
		"id": tid,
		"properties": {"ownerID": todo.ownerID},
	}
	allow with input as {
		"subject": input.subject,
		"action": input.action,
		"resource": item,
	}
}

resource_search contains item if {
	input.resource.type == "user"
	some _, u in data.users
	item := {"type": "user", "id": u.email}
	allow with input as {
		"subject": input.subject,
		"action": input.action,
		"resource": item,
	}
}

# Action Search: action names the input subject can perform on the input
# resource. `input.action` is absent in this request (spec Section 8.3).
action_search contains {"name": name} if {
	some name in known_actions
	allow with input as {
		"subject": input.subject,
		"action": {"name": name},
		"resource": input.resource,
	}
}

# --- Decision context (spec Section 5.5.1) ----------------------------------
# Named by `decision_context` in config.yaml and returned as the Decision's
# OPTIONAL `context` member. Composed from parts that each default to `{}`,
# since the plugin omits `context` on an empty object.

decision_context := object.union_n([reason_context, obligation_context, negotiation_context])

default reason := "not_permitted"

# `allow` requires a resolved `user` in every branch, so these two overrides
# are mutually exclusive and the complete rule can never conflict.
reason := "unknown_subject" if not user

reason := "permitted" if allow

reason_context := {"reason": reason}

# --- AuthZEN Obligations Profile 1.0 ----------------------------------------
# A privileged subject mutating somebody else's todo owes the owner a
# notification. The membership test is the profile's negotiation rule: only
# issue what the PEP declared it can execute. The plugin has already filtered
# that array down to config.yaml's `supported_obligations`.

default obligation_context := {}

obligation_context := {"obligations": [{
	"id": sprintf("notify-owner-%s", [input.resource.id]),
	"type": "notification",
	"properties": {
		"recipient": input.resource.properties.ownerID,
		"event": input.action.name,
		"actor": user.email,
	},
}]} if {
	allow
	input.action.name in {"can_update_todo", "can_delete_todo"}
	input.resource.properties.ownerID != user.email
	"notification" in input.context.supported_obligations
}

# Echoes what survived that filter, which is otherwise unobservable over HTTP
# and so untestable. Absent when the PEP declared nothing.
default negotiation_context := {}

negotiation_context := {"negotiated_obligations": input.context.supported_obligations} if {
	input.context.supported_obligations
}
