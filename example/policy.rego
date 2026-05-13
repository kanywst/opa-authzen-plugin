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

# --- AuthZEN Search APIs (spec Section 8) -----------------------------------
# The plugin queries these rules when the corresponding `search.*` config
# field is set. Each rule returns a set of entity objects that conform to the
# AuthZEN information model. The plugin handles pagination on top of the set
# returned here.

known_users := ["alice", "bob", "carol"]

known_accounts := ["acct-100", "acct-200", "acct-300"]

known_verbs := ["read", "access"]

# Subject Search: return users that can perform the given action on the
# given resource. `input.subject.id` is absent here (spec Section 8.1).
subject_search contains {"type": "user", "id": u} if {
	some u in known_users
	allow with input.subject as {"type": "user", "id": u}
}

# Resource Search: return accounts the subject can act on. `input.resource.id`
# is absent here (spec Section 8.2).
resource_search contains {"type": "account", "id": a} if {
	some a in known_accounts
	allow with input.resource as {"type": "account", "id": a}
}

# Action Search: return verbs the subject may perform on the resource.
# `input.action` is absent here (spec Section 8.3).
action_search contains {"name": v} if {
	some v in known_verbs
	allow with input.action as {"name": v}
}
