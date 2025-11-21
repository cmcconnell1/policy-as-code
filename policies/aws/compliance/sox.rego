package aws.compliance.sox

import rego.v1

# METADATA
# title: SOX Compliance Controls
# description: Sarbanes-Oxley Act compliance for financial reporting systems
# custom:
#   severity: HIGH
#   frameworks:
#     - SOX-302 (CEO/CFO Certification)
#     - SOX-404 (Internal Controls)
#     - SOX-ITGC (IT General Controls)

# SOX-302: Change Management & Access Controls
# Deny IAM users (prefer roles for auditable access)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_iam_user"
	username := resource.change.after.name

	msg := {
		"policy": "aws.compliance.sox",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "SOX-302",
		"message": sprintf("IAM user '%s' violates SOX change management controls (use roles for auditable access)", [username]),
		"remediation": "Use IAM roles with federated access (SSO) instead of IAM users for better auditability"
	}
}

# SOX-404: Audit Logging Required
# Deny S3 buckets without logging enabled
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	bucket_name := resource.change.after.bucket

	# Check if there's a corresponding logging configuration
	logging_configs := [log |
		some log in input.resource_changes
		log.type == "aws_s3_bucket_logging"
		log.change.after.bucket == bucket_name
	]

	count(logging_configs) == 0

	msg := {
		"policy": "aws.compliance.sox",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "SOX-404",
		"message": sprintf("S3 bucket '%s' does not have access logging enabled (required for audit trail)", [bucket_name]),
		"remediation": "Add aws_s3_bucket_logging resource to enable access logs"
	}
}

# SOX-ITGC: Segregation of Duties
# Deny overly broad IAM policies that combine read and write
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_iam_policy"
	policy_name := resource.change.after.name

	policy_doc := json.unmarshal(resource.change.after.policy)

	some statement in policy_doc.Statement
	statement.Effect == "Allow"

	# Check for combined read/write/delete permissions
	actions := statement.Action
	has_read := [a | some a in actions; contains(a, "Get")]
	has_write := [a | some a in actions; contains(a, "Put")]
	has_delete := [a | some a in actions; contains(a, "Delete")]

	count(has_read) > 0
	count(has_write) > 0
	count(has_delete) > 0

	msg := {
		"policy": "aws.compliance.sox",
		"resource": resource.address,
		"severity": "MEDIUM",
		"compliance": "SOX-ITGC",
		"message": sprintf("IAM policy '%s' combines read, write, and delete permissions (violates segregation of duties)", [policy_name]),
		"remediation": "Split into separate read-only and write policies; assign based on roles"
	}
}

# SOX-ITGC: Database Change Tracking
# Deny RDS instances without automated backups
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier

	backup_retention := resource.change.after.backup_retention_period
	backup_retention == 0

	msg := {
		"policy": "aws.compliance.sox",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "SOX-404",
		"message": sprintf("RDS instance '%s' has automated backups disabled (required for data integrity)", [db_name]),
		"remediation": "Set backup_retention_period to at least 7 days (recommended: 30 for SOX)"
	}
}

# SOX-ITGC: Change Control for Production
# Deny resources in production without proper tagging and approval
deny contains msg if {
	some resource in input.resource_changes
	resource.change.actions[_] == "create"

	tags := object.get(resource.change.after, "tags", {})
	environment := lower(object.get(tags, "Environment", ""))

	environment == "prod"

	# Check for change approval tag
	not tags.ChangeTicket
	not tags.ApprovedBy

	msg := {
		"policy": "aws.compliance.sox",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "SOX-302",
		"message": "Production resource creation requires change approval tags (ChangeTicket or ApprovedBy)",
		"remediation": "Add tags: ChangeTicket = 'TICKET-123' and ApprovedBy = 'manager@example.com'"
	}
}
