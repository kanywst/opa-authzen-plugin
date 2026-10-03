# The authorization model of openid/authzen's Search demo, transcribed from
# interop/authzen-search-demo/test/test_response_generator.py, which generated
# the harness's expected results. data.search_demo holds the demo's users.json
# and records.json, loaded by build/run-search-harness.sh.
package authzen

users[u.id] := u if some u in data.search_demo.users

# Record ids are numbers in records.json and strings on the wire.
records[format_int(r.id, 10)] := r if some r in data.search_demo.records

actions := {"view", "edit", "delete"}

can(user, record, "view") if record.owner == user.id

can(user, record, "view") if record.department == user.department

can(user, record, "view") if user.role == "manager"

can(user, record, "edit") if record.owner == user.id

can(user, record, "edit") if {
	record.department == user.department
	user.role == "manager"
}

can(user, record, "delete") if record.owner == user.id

default allow := false

allow if {
	input.subject.type == "user"
	input.resource.type == "record"
	can(users[input.subject.id], records[input.resource.id], input.action.name)
}

subject_search contains {"type": "user", "id": id} if {
	input.subject.type == "user"
	input.resource.type == "record"
	record := records[input.resource.id]
	some id, user in users
	can(user, record, input.action.name)
}

resource_search contains {"type": "record", "id": id} if {
	input.subject.type == "user"
	input.resource.type == "record"
	user := users[input.subject.id]
	some id, record in records
	can(user, record, input.action.name)
}

action_search contains {"name": name} if {
	input.subject.type == "user"
	input.resource.type == "record"
	user := users[input.subject.id]
	record := records[input.resource.id]
	some name in actions
	can(user, record, name)
}
