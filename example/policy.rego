package authzen

default allow = false

# Allow if the subject has the "admin" role.
allow if input.subject.properties.role == "admin"

# Allow read access to any authenticated user.
allow if {
	input.action.name == "read"
	input.subject.id != ""
}
