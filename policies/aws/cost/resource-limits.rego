package aws.cost.resource_limits

import rego.v1

# METADATA
# title: Resource Quantity Limits
# description: Enforces limits on resource quantities to prevent cost overruns
# custom:
#   severity: MEDIUM
#   frameworks:
#     - Cost Management
#     - FinOps

# Maximum allowed resource counts per deployment
max_resource_limits := {
	"aws_instance": 10,
	"aws_rds_instance": 5,
	"aws_rds_cluster": 3,
	"aws_elasticache_cluster": 5,
	"aws_nat_gateway": 3,
	"aws_vpc": 5,
	"aws_eip": 10,
}

# Count resources by type
count_resources_by_type(resource_type) := resource_count if {
	resources := [r | some r in input.resource_changes; r.type == resource_type]
	resource_count := count(resources)
}

# Deny exceeding resource limits
deny contains msg if {
	some resource_type, max_count in max_resource_limits
	actual_count := count_resources_by_type(resource_type)
	actual_count > max_count

	msg := {
		"policy": "aws.cost.resource_limits",
		"resource": sprintf("Multiple %s resources", [resource_type]),
		"severity": "MEDIUM",
		"message": sprintf("Deployment creates %d %s resources, exceeding limit of %d", [actual_count, resource_type, max_count]),
		"remediation": sprintf("Reduce number of %s resources or request limit increase from FinOps team", [resource_type])
	}
}

# Warn about NAT Gateways (expensive)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_nat_gateway"

	msg := {
		"policy": "aws.cost.resource_limits",
		"resource": resource.address,
		"severity": "LOW",
		"message": "NAT Gateway incurs hourly charges plus data transfer costs (~$32-45/month per gateway)",
		"remediation": "Consider using NAT instances for dev/test or VPC endpoints for AWS services to reduce costs"
	}
}

# Warn about multiple EIPs (indicates potential architecture issues)
deny contains msg if {
	eip_count := count_resources_by_type("aws_eip")
	eip_count > 5

	msg := {
		"policy": "aws.cost.resource_limits",
		"resource": "Multiple aws_eip resources",
		"severity": "LOW",
		"message": sprintf("Deployment uses %d Elastic IPs (limit: 5 per account by default)", [eip_count]),
		"remediation": "Review architecture: consider using load balancers instead of multiple EIPs"
	}
}

# Deny RDS instances without specifying instance class limits
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	instance_class := resource.change.after.instance_class

	# Prohibit very large RDS instances
	prohibited_classes := {"db.r5.12xlarge", "db.r5.16xlarge", "db.r5.24xlarge", "db.x1", "db.x2"}
	some prohibited in prohibited_classes
	startswith(instance_class, prohibited)

	msg := {
		"policy": "aws.cost.resource_limits",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("RDS instance class '%s' is extremely expensive", [instance_class]),
		"remediation": "Use smaller instance classes (db.t3, db.m5, db.r5.large/xlarge) or request approval"
	}
}
