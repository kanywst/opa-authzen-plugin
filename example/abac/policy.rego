# Attribute-Based Access Control (ABAC) example.
#
# Access decisions based on subject attributes (department, clearance),
# resource attributes (classification, department), and context (time).

package authzen

import rego.v1

default allow := false

subject_props := input.subject.properties

resource_props := input.resource.properties

# Read: subject's clearance must meet or exceed the resource classification.
clearance_levels := {
	"public": 0,
	"internal": 1,
	"confidential": 2,
	"secret": 3,
}

allow if {
	input.action.name == "read"
	clearance_levels[subject_props.clearance] >= clearance_levels[resource_props.classification]
}

# Write: same clearance check + subject must be in the same department.
allow if {
	input.action.name == "write"
	clearance_levels[subject_props.clearance] >= clearance_levels[resource_props.classification]
	subject_props.department == resource_props.department
}

# Approve: requires "secret" clearance and must be during business hours.
allow if {
	input.action.name == "approve"
	subject_props.clearance == "secret"
	input.context.business_hours == true
}
