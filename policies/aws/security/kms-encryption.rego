package aws.security.kms_encryption

import rego.v1

# METADATA
# title: KMS Encryption for Data at Rest
# description: Ensures sensitive resources use KMS encryption
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 3.4
#     - SOX-ITGC
#     - FFIEC D3.DC.Rm.B.3

# Resources that should be encrypted with KMS
encrypted_resource_types := {
	"aws_ebs_volume",
	"aws_rds_cluster",
	"aws_rds_instance",
	"aws_db_instance",
	"aws_dynamodb_table",
	"aws_redshift_cluster",
	"aws_efs_file_system",
}

# Check if resource type requires encryption
requires_encryption(resource_type) if {
	resource_type in encrypted_resource_types
}

# EBS Volume encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_ebs_volume"
	volume_id := resource.change.after.id

	not resource.change.after.encrypted

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("EBS volume is not encrypted", []),
		"remediation": "Set 'encrypted = true' and optionally specify 'kms_key_id' for customer-managed keys"
	}
}

# RDS Instance encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier

	not resource.change.after.storage_encrypted

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("RDS instance '%s' does not have storage encryption enabled", [db_name]),
		"remediation": "Set 'storage_encrypted = true' and optionally specify 'kms_key_id'"
	}
}

# RDS Cluster encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_rds_cluster"
	cluster_name := resource.change.after.cluster_identifier

	not resource.change.after.storage_encrypted

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("RDS cluster '%s' does not have storage encryption enabled", [cluster_name]),
		"remediation": "Set 'storage_encrypted = true' and optionally specify 'kms_key_id'"
	}
}

# DynamoDB table encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_dynamodb_table"
	table_name := resource.change.after.name

	# Check if server_side_encryption block exists and is enabled
	not resource.change.after.server_side_encryption

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("DynamoDB table '%s' does not have server-side encryption enabled", [table_name]),
		"remediation": "Add server_side_encryption block with 'enabled = true' and optionally specify 'kms_key_arn'"
	}
}

# EFS encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_efs_file_system"

	not resource.change.after.encrypted

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": "EFS file system does not have encryption enabled",
		"remediation": "Set 'encrypted = true' and optionally specify 'kms_key_id'"
	}
}

# Redshift cluster encryption check
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_redshift_cluster"
	cluster_name := resource.change.after.cluster_identifier

	not resource.change.after.encrypted

	msg := {
		"policy": "aws.security.kms_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Redshift cluster '%s' does not have encryption enabled", [cluster_name]),
		"remediation": "Set 'encrypted = true' and optionally specify 'kms_key_id'"
	}
}
