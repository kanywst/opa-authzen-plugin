package authzen

default allow := false

# Admins can do anything.
allow if input.subject.properties.role == "admin"

# Any identified subject can read.
allow if {
	input.action.name == "read"
	input.subject.id != ""
}
