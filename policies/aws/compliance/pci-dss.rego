package aws.compliance.pci_dss

import rego.v1

# METADATA
# title: PCI-DSS Compliance Controls
# description: Payment Card Industry Data Security Standard requirements
# custom:
#   severity: CRITICAL
#   frameworks:
#     - PCI-DSS 3.2.1
#     - PCI-DSS 4.0

# PCI-DSS Requirement 1: Firewall Configuration
# Already covered by ec2-security-groups.rego

# PCI-DSS Requirement 2: No vendor defaults
# Deny RDS instances with default ports
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier
	engine := resource.change.after.engine
	port := resource.change.after.port

	default_ports := {
		"mysql": 3306,
		"postgres": 5432,
		"sqlserver": 1433,
		"oracle": 1521,
		"mariadb": 3306,
	}

	default_ports[engine] == port

	msg := {
		"policy": "aws.compliance.pci_dss",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "PCI-DSS 2.2.4",
		"message": sprintf("RDS instance '%s' uses default port %d for engine %s", [db_name, port, engine]),
		"remediation": "Change port to non-default value to comply with PCI-DSS 2.2.4"
	}
}

# PCI-DSS Requirement 3: Protect stored cardholder data
# Deny unencrypted EBS volumes in cardholder data environment
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_ebs_volume"

	not resource.change.after.encrypted

	tags := object.get(resource.change.after, "tags", {})
	data_class := lower(object.get(tags, "DataClassification", ""))

	# Check if this might store cardholder data
	data_class in ["restricted", "confidential", "pci", "cardholder"]

	msg := {
		"policy": "aws.compliance.pci_dss",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "PCI-DSS 3.4",
		"message": "EBS volume storing sensitive data must be encrypted",
		"remediation": "Set encrypted = true and specify kms_key_id for customer-managed encryption"
	}
}

# PCI-DSS Requirement 7: Restrict access to cardholder data
# Deny overly permissive S3 bucket policies
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_policy"
	bucket := resource.change.after.bucket

	policy_doc := json.unmarshal(resource.change.after.policy)

	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	statement.Principal == "*"

	msg := {
		"policy": "aws.compliance.pci_dss",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "PCI-DSS 7.1",
		"message": sprintf("S3 bucket '%s' has policy allowing access to all principals (*)", [bucket]),
		"remediation": "Restrict Principal to specific AWS accounts or IAM principals"
	}
}

# PCI-DSS Requirement 8: Identify and authenticate access
# Covered by iam-mfa-enforcement.rego

# PCI-DSS Requirement 10: Track and monitor access
# Deny accounts without CloudTrail
deny contains msg if {
	# Count CloudTrail resources
	trails := [t | some t in input.resource_changes; t.type == "aws_cloudtrail"]

	count(trails) == 0

	# Check if any compute resources are being created
	compute_resources := [r |
		some r in input.resource_changes
		r.type in ["aws_instance", "aws_lambda_function", "aws_ecs_service"]
	]

	count(compute_resources) > 0

	msg := {
		"policy": "aws.compliance.pci_dss",
		"resource": "infrastructure",
		"severity": "CRITICAL",
		"compliance": "PCI-DSS 10.2",
		"message": "Deployment includes compute resources but no CloudTrail for audit logging",
		"remediation": "Add aws_cloudtrail resource with multi-region enabled and log file validation"
	}
}

# PCI-DSS Requirement 10: Log aggregation and protection
# Deny CloudTrail without log file validation
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	trail_name := resource.change.after.name

	not resource.change.after.enable_log_file_validation

	msg := {
		"policy": "aws.compliance.pci_dss",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "PCI-DSS 10.5",
		"message": sprintf("CloudTrail '%s' does not have log file validation enabled", [trail_name]),
		"remediation": "Set enable_log_file_validation = true to prevent log tampering"
	}
}
