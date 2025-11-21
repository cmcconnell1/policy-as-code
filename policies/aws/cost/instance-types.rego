package aws.cost.instance_types

import rego.v1

# METADATA
# title: EC2 Instance Type Restrictions
# description: Restricts EC2 instance types to approved cost-effective options
# custom:
#   severity: MEDIUM
#   frameworks:
#     - Cost Management
#     - FinOps

# Approved instance families for general workloads
approved_instance_families := {
	"t3", "t3a", # Burstable performance
	"t4g", # ARM-based burstable
	"m5", "m5a", "m6i", "m6a", # General purpose
	"m7g", # ARM-based general purpose
	"c5", "c5a", "c6i", "c6a", # Compute optimized
	"c7g", # ARM-based compute
	"r5", "r5a", "r6i", # Memory optimized
}

# Prohibited expensive instance families
prohibited_instance_families := {
	"p2", "p3", "p4", # GPU instances
	"inf1", "inf2", # Inferentia instances
	"trn1", # Trainium instances
	"x1", "x1e", "x2", # Extreme memory instances
	"u-", # High memory instances
}

# Maximum instance sizes allowed
max_allowed_sizes := {"medium", "large", "xlarge", "2xlarge"}

# Extract instance family from instance type
get_instance_family(instance_type) := family if {
	parts := split(instance_type, ".")
	count(parts) == 2
	family := parts[0]
}

# Extract instance size from instance type
get_instance_size(instance_type) := size if {
	parts := split(instance_type, ".")
	count(parts) == 2
	size := parts[1]
}

# Check if instance family is approved
is_approved_family(family) if {
	some approved_family in approved_instance_families
	startswith(family, approved_family)
}

# Check if instance family is prohibited
is_prohibited_family(family) if {
	some prohibited_family in prohibited_instance_families
	startswith(family, prohibited_family)
}

# Deny unapproved EC2 instance types
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_instance"
	instance_type := resource.change.after.instance_type

	family := get_instance_family(instance_type)
	not is_approved_family(family)

	msg := {
		"policy": "aws.cost.instance_types",
		"resource": resource.address,
		"severity": "MEDIUM",
		"message": sprintf("EC2 instance type '%s' is not in approved list (family: %s)", [instance_type, family]),
		"remediation": sprintf("Use instance types from approved families: %v", [approved_instance_families])
	}
}

# Deny prohibited expensive instance types
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_instance"
	instance_type := resource.change.after.instance_type

	family := get_instance_family(instance_type)
	is_prohibited_family(family)

	msg := {
		"policy": "aws.cost.instance_types",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("EC2 instance type '%s' uses prohibited expensive family: %s", [instance_type, family]),
		"remediation": "Specialized instances require cost approval. Contact FinOps team or use approved families"
	}
}

# Warn about oversized instances
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_instance"
	instance_type := resource.change.after.instance_type

	size := get_instance_size(instance_type)
	not max_allowed_sizes[size]

	msg := {
		"policy": "aws.cost.instance_types",
		"resource": resource.address,
		"severity": "MEDIUM",
		"message": sprintf("EC2 instance size '%s' exceeds recommended maximum (approved: %v)", [size, max_allowed_sizes]),
		"remediation": "Consider using multiple smaller instances or request approval for larger sizes"
	}
}
