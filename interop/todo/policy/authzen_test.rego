package authzen_test

import rego.v1

import data.authzen

# User PIDs
rick_pid := "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
morty_pid := "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
summer_pid := "CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
beth_pid := "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
jerry_pid := "CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

# --- can_read_user: always allow ---

test_rick_can_read_user if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
}

test_jerry_can_read_user if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": jerry_pid},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
}

# --- can_read_todos: always allow ---

test_beth_can_read_todos if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_read_todos"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
}

# --- can_create_todo ---

test_rick_can_create_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
}

test_morty_can_create_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": morty_pid},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
}

test_beth_cannot_create_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
}

test_jerry_cannot_create_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": jerry_pid},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
}

# --- can_update_todo ---

test_rick_can_update_any_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "morty@the-citadel.com"}},
	}
}

test_morty_can_update_own_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": morty_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "morty@the-citadel.com"}},
	}
}

test_morty_cannot_update_rick_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": morty_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "rick@the-citadel.com"}},
	}
}

test_beth_cannot_update_own_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "beth@the-smiths.com"}},
	}
}

# --- can_delete_todo ---

test_rick_can_delete_any_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_delete_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "morty@the-citadel.com"}},
	}
}

test_summer_can_delete_own_todo if {
	authzen.allow with input as {
		"subject": {"type": "user", "id": summer_pid},
		"action": {"name": "can_delete_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "summer@the-smiths.com"}},
	}
}

test_summer_cannot_delete_rick_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": summer_pid},
		"action": {"name": "can_delete_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "rick@the-citadel.com"}},
	}
}

test_jerry_cannot_delete_own_todo if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": jerry_pid},
		"action": {"name": "can_delete_todo"},
		"resource": {"type": "todo", "id": "1", "properties": {"ownerID": "jerry@the-smiths.com"}},
	}
}

# --- unknown user: always deny ---

test_unknown_user_denied if {
	not authzen.allow with input as {
		"subject": {"type": "user", "id": "unknown-pid"},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
}

# --- Subject Search (spec Section 8.1) -------------------------------------

# can_read_user is allowed for every known user, so subject_search returns all 5.
test_subject_search_read_user_returns_all_known_users if {
	result := authzen.subject_search with input as {
		"subject": {"type": "user"},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
	count(result) == 5
}

# can_create_todo is restricted to admin/editor → Rick, Morty, Summer (3 users).
test_subject_search_create_todo_returns_admin_and_editors if {
	result := authzen.subject_search with input as {
		"subject": {"type": "user"},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
	count(result) == 3
	{"type": "user", "id": rick_pid} in result
	{"type": "user", "id": morty_pid} in result
	{"type": "user", "id": summer_pid} in result
}

# can_update_todo on a Rick-owned todo → only Rick (admin/evil_genius).
test_subject_search_update_owned_by_rick if {
	result := authzen.subject_search with input as {
		"subject": {"type": "user"},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": "7240d0db-8ff0-41ec-98b2-34a096273b92",
			"properties": {"ownerID": "rick@the-citadel.com"},
		},
	}
	result == {{"type": "user", "id": rick_pid}}
}

# subject_search with a subject type the policy doesn't model returns an
# empty result set, so the rule cannot leak user enumeration through a
# spec-ignored input.subject.id when the type doesn't match.
test_subject_search_unknown_type_returns_empty if {
	result := authzen.subject_search with input as {
		"subject": {"type": "robot"},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
	count(result) == 0
}

# --- Resource Search (spec Section 8.2) ------------------------------------

# Rick can update every todo in data (admin).
test_resource_search_rick_update_returns_all_todos if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo"},
	}
	count(result) == count(data.todos)
}

# Morty can only update todos owned by morty@... (only one such todo in data).
test_resource_search_morty_update_returns_only_own if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": morty_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo"},
	}
	count(result) == 1
	some item in result
	item.properties.ownerID == "morty@the-citadel.com"
}

# Beth (viewer) cannot update any todo.
test_resource_search_beth_update_returns_empty if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_update_todo"},
		"resource": {"type": "todo"},
	}
	count(result) == 0
}

# can_read_user is allowed for every known user, so a user-typed
# resource_search returns all 5 entries in data.users.
test_resource_search_user_read_returns_all_users if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_read_user"},
		"resource": {"type": "user"},
	}
	count(result) == count(data.users)
}

# A resource type the policy doesn't model returns an empty result set,
# so each search branch is correctly scoped by input.resource.type.
test_resource_search_unknown_type_returns_empty if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_read_user"},
		"resource": {"type": "spaceship"},
	}
	count(result) == 0
}

# --- Action Search (spec Section 8.3) --------------------------------------

# Rick (admin) on a todo: every todo-scoped action. can_read_user is
# excluded because the new resource-type guards make that action only
# valid on user resources.
test_action_search_rick_on_own_todo if {
	result := authzen.action_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"resource": {
			"type": "todo",
			"id": "7240d0db-8ff0-41ec-98b2-34a096273b92",
			"properties": {"ownerID": "rick@the-citadel.com"},
		},
	}
	result == {
		{"name": "can_read_todos"},
		{"name": "can_create_todo"},
		{"name": "can_update_todo"},
		{"name": "can_delete_todo"},
	}
}

# Rick (admin) on a user resource: only can_read_user is in scope.
test_action_search_rick_on_user if {
	result := authzen.action_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"resource": {"type": "user", "id": "beth@the-smiths.com"},
	}
	result == {{"name": "can_read_user"}}
}

# Morty (editor) on a Rick-owned todo: read_todos and create_todo only
# (update/delete blocked by ownership, can_read_user blocked by type).
test_action_search_morty_on_rick_todo if {
	result := authzen.action_search with input as {
		"subject": {"type": "user", "id": morty_pid},
		"resource": {
			"type": "todo",
			"id": "7240d0db-8ff0-41ec-98b2-34a096273b92",
			"properties": {"ownerID": "rick@the-citadel.com"},
		},
	}
	result == {
		{"name": "can_read_todos"},
		{"name": "can_create_todo"},
	}
}

# Morty (editor) on his own todo: every todo-scoped action.
test_action_search_morty_on_own_todo if {
	result := authzen.action_search with input as {
		"subject": {"type": "user", "id": morty_pid},
		"resource": {
			"type": "todo",
			"id": "7240d0db-8ff0-41ec-98b2-34a096273b91",
			"properties": {"ownerID": "morty@the-citadel.com"},
		},
	}
	result == {
		{"name": "can_read_todos"},
		{"name": "can_create_todo"},
		{"name": "can_update_todo"},
		{"name": "can_delete_todo"},
	}
}

# Beth (viewer) on a todo: can_read_todos only.
test_action_search_beth_on_todo if {
	result := authzen.action_search with input as {
		"subject": {"type": "user", "id": beth_pid},
		"resource": {
			"type": "todo",
			"id": "7240d0db-8ff0-41ec-98b2-34a096273b94",
			"properties": {"ownerID": "beth@the-smiths.com"},
		},
	}
	result == {{"name": "can_read_todos"}}
}

# resource_search across a mismatched action/type pair (todo action on
# user resource) must return zero results — proves the new guards stop
# cross-type leakage.
test_resource_search_cross_type_returns_empty if {
	result := authzen.resource_search with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_read_todos"},
		"resource": {"type": "user"},
	}
	count(result) == 0
}

# --- Decision context (spec Section 5.5.1) ---

morty_todo := "7240d0db-8ff0-41ec-98b2-34a096273b91"

rick_todo := "7240d0db-8ff0-41ec-98b2-34a096273b92"

# A permit carries the "permitted" reason and nothing else when the PEP
# declared no obligation support.
test_decision_context_reason_on_permit if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_read_todos"},
		"resource": {"type": "todo", "id": rick_todo},
	}
	ctx == {"reason": "permitted"}
}

test_decision_context_reason_on_deny if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_create_todo"},
		"resource": {"type": "todo", "id": "todo-1"},
	}
	ctx == {"reason": "not_permitted"}
}

test_decision_context_reason_on_unknown_subject if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": "no-such-pid"},
		"action": {"name": "can_read_todos"},
		"resource": {"type": "todo", "id": rick_todo},
	}
	ctx == {"reason": "unknown_subject"}
}

# --- Obligations Profile 1.0 ---

# Rick (admin) updating a todo Morty owns: the owner must be notified, and
# the PEP said it can execute `notification`.
test_notification_obligation_on_privileged_cross_owner_update if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": morty_todo,
			"properties": {"ownerID": "morty@the-citadel.com"},
		},
		"context": {"supported_obligations": ["notification"]},
	}
	ctx.reason == "permitted"
	ctx.obligations == [{
		"id": sprintf("notify-owner-%s", [morty_todo]),
		"type": "notification",
		"properties": {
			"recipient": "morty@the-citadel.com",
			"event": "can_update_todo",
			"actor": "rick@the-citadel.com",
		},
	}]
}

# Same request, but the PEP declared nothing. The profile's negotiation rule
# says the PDP must not issue an obligation the PEP cannot execute.
test_no_obligation_when_pep_declares_nothing if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": morty_todo,
			"properties": {"ownerID": "morty@the-citadel.com"},
		},
	}
	not ctx.obligations
}

# A PEP that declared only types this PDP does not advertise arrives at the
# policy with an empty array (the plugin filters it). Still no obligation.
test_no_obligation_when_declared_set_filters_to_empty if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": morty_todo,
			"properties": {"ownerID": "morty@the-citadel.com"},
		},
		"context": {"supported_obligations": []},
	}
	not ctx.obligations
	ctx.negotiated_obligations == []
}

# Acting on your own todo creates no duty to notify anyone.
test_no_obligation_on_own_todo if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": rick_pid},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": rick_todo,
			"properties": {"ownerID": "rick@the-citadel.com"},
		},
		"context": {"supported_obligations": ["notification"]},
	}
	not ctx.obligations
}

# A denied request carries no obligation: there is no enforcement to attach a
# duty to.
test_no_obligation_on_deny if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": beth_pid},
		"action": {"name": "can_update_todo"},
		"resource": {
			"type": "todo",
			"id": rick_todo,
			"properties": {"ownerID": "rick@the-citadel.com"},
		},
		"context": {"supported_obligations": ["notification"]},
	}
	not ctx.obligations
	ctx.reason == "not_permitted"
}

# The negotiated set is echoed so a PEP (and the e2e suite) can see what
# survived the plugin's filter.
test_negotiation_context_echoes_declared_set if {
	ctx := authzen.decision_context with input as {
		"subject": {"type": "user", "id": morty_pid},
		"action": {"name": "can_read_todos"},
		"resource": {"type": "todo", "id": rick_todo},
		"context": {"supported_obligations": ["notification"]},
	}
	ctx.negotiated_obligations == ["notification"]
}
