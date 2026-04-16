# Todo application authorization policy.
#
# Based on the AuthZEN Interop Todo scenario:
# https://authzen-interop.net/docs/scenarios/todo-1.1/
#
# Roles: admin, evil_genius, editor, viewer
# Actions: can_read_user, can_read_todos, can_create_todo,
#          can_update_todo, can_delete_todo

package authzen

import rego.v1

default allow := false

# Resolve user from the subject ID using external data.
user := data.users[input.subject.id]

# can_read_user / can_read_todos: any authenticated user
allow if {
	input.action.name in {"can_read_user", "can_read_todos"}
	user
}

# can_create_todo: admin or editor
allow if {
	input.action.name == "can_create_todo"
	some role in user.roles
	role in {"admin", "editor"}
}

# can_update_todo: admin or evil_genius can update any todo
allow if {
	input.action.name == "can_update_todo"
	some role in user.roles
	role in {"admin", "evil_genius"}
}

# can_update_todo: editor can update only their own todos
allow if {
	input.action.name == "can_update_todo"
	"editor" in user.roles
	input.resource.properties.ownerID == user.email
}

# can_delete_todo: admin can delete any todo
allow if {
	input.action.name == "can_delete_todo"
	"admin" in user.roles
}

# can_delete_todo: editor can delete only their own todos
allow if {
	input.action.name == "can_delete_todo"
	"editor" in user.roles
	input.resource.properties.ownerID == user.email
}
