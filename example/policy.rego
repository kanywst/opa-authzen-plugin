package authzen

default allow = false

# Allow if the subject has the "admin" role.
allow if input.subject.properties.role == "admin"

# Allow read access to any authenticated user.
allow if {
	input.action.name == "read"
	input.subject.id != ""
}

# Allow access during business hours (context-based).
allow if {
	input.action.name == "access"
	input.context.business_hours == true
}
