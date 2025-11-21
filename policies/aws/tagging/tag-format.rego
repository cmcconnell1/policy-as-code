package aws.tagging.tag_format

import rego.v1

# METADATA
# title: Tag Format Validation
# description: Validates tag values follow required formats
# custom:
#   severity: LOW
#   frameworks:
#     - Cost Management
#     - Governance

# Valid environment values
valid_environments := {"dev", "test", "staging", "prod", "qa", "uat"}

# Valid data classification levels (financial services)
valid_data_classifications := {"public", "internal", "confidential", "restricted"}

# Validate Environment tag format
deny contains msg if {
	some resource in input.resource_changes
	resource_addr := resource.address

	tags := object.get(resource.change.after, "tags", {})
	environment := tags.Environment

	# Environment tag exists but has invalid value
	environment
	not valid_environments[lower(environment)]

	msg := {
		"policy": "aws.tagging.tag_format",
		"resource": resource_addr,
		"severity": "LOW",
		"message": sprintf("Environment tag has invalid value '%s' (must be one of: %v)", [environment, valid_environments]),
		"remediation": sprintf("Set Environment tag to one of: %v", [valid_environments])
	}
}

# Validate DataClassification tag format
deny contains msg if {
	some resource in input.resource_changes
	resource_addr := resource.address

	tags := object.get(resource.change.after, "tags", {})
	data_class := tags.DataClassification

	# DataClassification tag exists but has invalid value
	data_class
	not valid_data_classifications[lower(data_class)]

	msg := {
		"policy": "aws.tagging.tag_format",
		"resource": resource_addr,
		"severity": "LOW",
		"message": sprintf("DataClassification tag has invalid value '%s' (must be one of: %v)", [data_class, valid_data_classifications]),
		"remediation": sprintf("Set DataClassification tag to one of: %v", [valid_data_classifications])
	}
}

# Validate CostCenter tag format (should be numeric or alphanumeric code)
deny contains msg if {
	some resource in input.resource_changes
	resource_addr := resource.address

	tags := object.get(resource.change.after, "tags", {})
	cost_center := tags.CostCenter

	# CostCenter exists but doesn't match expected format (alphanumeric, 3-10 chars)
	cost_center
	not regex.match(`^[A-Z0-9]{3,10}$`, cost_center)

	msg := {
		"policy": "aws.tagging.tag_format",
		"resource": resource_addr,
		"severity": "LOW",
		"message": sprintf("CostCenter tag '%s' doesn't match expected format (3-10 uppercase alphanumeric characters)", [cost_center]),
		"remediation": "Use format like 'CC1234' or 'FINANCE01' for CostCenter tag"
	}
}

# Validate Owner tag format (should be email or username)
deny contains msg if {
	some resource in input.resource_changes
	resource_addr := resource.address

	tags := object.get(resource.change.after, "tags", {})
	owner := tags.Owner

	# Owner exists but doesn't look like an email or valid username
	owner
	not regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, owner)
	not regex.match(`^[a-zA-Z0-9._-]{3,}$`, owner)

	msg := {
		"policy": "aws.tagging.tag_format",
		"resource": resource_addr,
		"severity": "LOW",
		"message": sprintf("Owner tag '%s' should be a valid email address or username", [owner]),
		"remediation": "Use email format (user@example.com) or valid username for Owner tag"
	}
}
