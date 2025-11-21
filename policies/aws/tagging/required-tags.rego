package aws.tagging.required_tags

import rego.v1

# METADATA
# title: Required Resource Tags
# description: Enforces mandatory tags on all AWS resources
# custom:
#   severity: MEDIUM
#   frameworks:
#     - Cost Management
#     - FFIEC D5.RM.RM.B.1

# Required tags for all resources (financial services industry)
required_tags := [
	"Environment",
	"CostCenter",
	"Owner",
	"Application",
	"DataClassification",
]

# Resources that support tagging
taggable_resources := {
	"aws_instance",
	"aws_s3_bucket",
	"aws_db_instance",
	"aws_rds_instance",
	"aws_rds_cluster",
	"aws_ebs_volume",
	"aws_vpc",
	"aws_subnet",
	"aws_security_group",
	"aws_iam_role",
	"aws_lambda_function",
	"aws_dynamodb_table",
	"aws_efs_file_system",
	"aws_kms_key",
	"aws_ecr_repository",
	"aws_ecs_cluster",
	"aws_eks_cluster",
	"aws_elasticache_cluster",
	"aws_redshift_cluster",
	"aws_cloudwatch_log_group",
}

# Check if resource type supports tagging
is_taggable(resource_type) if {
	resource_type in taggable_resources
}

# Get tags from resource (handles both tags and tags_all)
get_tags(resource) := tags if {
	tags := resource.tags
} else := tags if {
	tags := resource.tags_all
} else := {}

# Check if all required tags are present
has_required_tags(tags) if {
	every tag in required_tags {
		tags[tag]
	}
}

# Deny resources missing required tags
deny contains msg if {
	some resource in input.resource_changes
	is_taggable(resource.type)
	resource_addr := resource.address

	tags := get_tags(resource.change.after)

	# Find missing tags
	missing_tags := [tag |
		some tag in required_tags
		not tags[tag]
	]

	count(missing_tags) > 0

	msg := {
		"policy": "aws.tagging.required_tags",
		"resource": resource_addr,
		"severity": "MEDIUM",
		"message": sprintf("Resource is missing required tags: %v", [missing_tags]),
		"remediation": sprintf("Add tags block with: %v", [missing_tags])
	}
}

# Warn about empty tag values
deny contains msg if {
	some resource in input.resource_changes
	is_taggable(resource.type)
	resource_addr := resource.address

	tags := get_tags(resource.change.after)

	# Find tags with empty values
	empty_tags := [tag_name |
		some tag_name, tag_value in tags
		tag_name in required_tags
		trim_space(tag_value) == ""
	]

	count(empty_tags) > 0

	msg := {
		"policy": "aws.tagging.required_tags",
		"resource": resource_addr,
		"severity": "MEDIUM",
		"message": sprintf("Resource has required tags with empty values: %v", [empty_tags]),
		"remediation": "Provide non-empty values for all required tags"
	}
}
