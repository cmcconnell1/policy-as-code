package aws.compliance.glba

import rego.v1

# METADATA
# title: GLBA Compliance Controls
# description: Gramm-Leach-Bliley Act - Financial privacy and consumer data protection
# custom:
#   severity: HIGH
#   frameworks:
#     - GLBA-SAFEGUARDS (Safeguards Rule)
#     - GLBA-ACCESS (Access Control)
#     - GLBA-MONITORING (Security Monitoring)
#     - GLBA-BREACH (Breach Notification - 2024 Rule)
#     - GLBA-VENDOR (Third-Party Oversight)

# GLBA-SAFEGUARDS: Encryption of Customer Data (NPI)
# Deny S3 buckets storing customer data without encryption
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	bucket_name := resource.change.after.bucket

	# Check for data classification tags indicating customer/financial data
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check if there's a corresponding encryption configuration
	encryption_configs := [enc |
		some enc in input.resource_changes
		enc.type == "aws_s3_bucket_server_side_encryption_configuration"
		enc.change.after.bucket == bucket_name
	]

	count(encryption_configs) == 0

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "GLBA-SAFEGUARDS",
		"message": sprintf("S3 bucket '%s' stores customer data (NPI) without encryption (violates GLBA Safeguards Rule)", [bucket_name]),
		"remediation": "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms encryption"
	}
}

# GLBA-SAFEGUARDS: Database Encryption for Financial Data
# Deny RDS instances storing financial data without encryption
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier

	# Check for data classification tags
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check if encryption is disabled
	storage_encrypted := object.get(resource.change.after, "storage_encrypted", false)
	not storage_encrypted

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "GLBA-SAFEGUARDS",
		"message": sprintf("RDS instance '%s' stores financial data without encryption at rest (violates GLBA)", [db_name]),
		"remediation": "Set storage_encrypted = true and specify kms_key_id for encryption"
	}
}

# GLBA-ACCESS: Public Access to Customer Data
# Deny any public access to resources containing customer information
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	bucket_name := resource.change.after.bucket

	# Check for customer data classification
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check for public ACL
	acl := object.get(resource.change.after, "acl", "private")
	acl in ["public-read", "public-read-write"]

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "GLBA-ACCESS",
		"message": sprintf("S3 bucket '%s' containing customer data (NPI) has public access (violates GLBA access controls)", [bucket_name]),
		"remediation": "Change ACL to 'private' and configure aws_s3_bucket_public_access_block with all settings true"
	}
}

# GLBA-ACCESS: MFA Required for Access to Customer Data Systems
# Deny IAM users accessing financial systems without MFA
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_iam_user"
	username := resource.change.after.name

	# Check if user has tags indicating access to financial systems
	tags := object.get(resource.change.after, "tags", {})
	access_level := lower(object.get(tags, "AccessLevel", ""))
	access_level in ["financial", "customer-data", "npi"]

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "GLBA-ACCESS",
		"message": sprintf("IAM user '%s' has access to financial/customer data systems (must use MFA and roles)", [username]),
		"remediation": "Use IAM roles with MFA enforcement instead of IAM users for accessing customer data"
	}
}

# GLBA-MONITORING: Logging for Breach Detection (2024 Breach Notification Rule)
# Deny S3 buckets storing customer data without access logging
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	bucket_name := resource.change.after.bucket

	# Check for customer data
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check if there's a corresponding logging configuration
	logging_configs := [log |
		some log in input.resource_changes
		log.type == "aws_s3_bucket_logging"
		log.change.after.bucket == bucket_name
	]

	count(logging_configs) == 0

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "GLBA-MONITORING",
		"message": sprintf("S3 bucket '%s' with customer data (NPI) lacks access logging (required for breach detection and 30-day notification)", [bucket_name]),
		"remediation": "Add aws_s3_bucket_logging resource to track access for breach notification compliance"
	}
}

# GLBA-MONITORING: CloudTrail for Audit Trail
# Deny environments storing customer data without CloudTrail
deny contains msg if {
	some resource in input.resource_changes

	# Check for resources that store customer data
	resource.type in ["aws_s3_bucket", "aws_rds_instance", "aws_db_instance", "aws_dynamodb_table"]

	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check if CloudTrail exists
	cloudtrail_trails := [trail |
		some trail in input.resource_changes
		trail.type == "aws_cloudtrail"
	]

	count(cloudtrail_trails) == 0

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "GLBA-MONITORING",
		"message": "Resources storing customer data require CloudTrail for continuous monitoring and breach detection",
		"remediation": "Enable AWS CloudTrail with log file validation for audit trail"
	}
}

# GLBA-VENDOR: Third-Party Service Provider Oversight (Cloud/Hybrid)
# Deny use of non-compliant AWS regions for customer data
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_s3_bucket", "aws_rds_instance", "aws_db_instance"]

	# Check for customer data classification
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check for VendorCompliance tag (should indicate AWS region is approved)
	not tags.VendorCompliance
	not tags.ApprovedRegion

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "GLBA-VENDOR",
		"message": "Resources storing customer data (NPI) must be deployed in approved regions with documented vendor compliance",
		"remediation": "Add tags: VendorCompliance = 'AWS-SOC2-2024' and ApprovedRegion = 'true' after vendor assessment"
	}
}

# GLBA-BREACH: Data Retention for Breach Investigation
# Deny backup configurations that don't meet 30-day breach notification timeline
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier

	# Check for customer data
	tags := object.get(resource.change.after, "tags", {})
	data_classification := lower(object.get(tags, "DataClassification", ""))
	data_classification in ["confidential", "restricted", "pii", "npi"]

	# Check backup retention (must be at least 30 days for breach investigation)
	backup_retention := object.get(resource.change.after, "backup_retention_period", 0)
	backup_retention < 30

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "GLBA-BREACH",
		"message": sprintf("RDS instance '%s' with customer data has backup retention < 30 days (insufficient for breach notification compliance)", [db_name]),
		"remediation": "Set backup_retention_period to at least 30 days to support breach investigation and 30-day notification requirement"
	}
}

# GLBA-SAFEGUARDS: Encryption in Transit for Customer Data
# Deny load balancers handling customer data without HTTPS
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_lb_listener"

	# Check for customer data handling
	tags := object.get(resource.change.after, "tags", {})
	data_type := lower(object.get(tags, "DataType", ""))
	data_type in ["customer", "financial", "pii", "npi"]

	# Check if using HTTP instead of HTTPS
	protocol := resource.change.after.protocol
	protocol == "HTTP"

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "GLBA-SAFEGUARDS",
		"message": "Load balancer handling customer data (NPI) uses HTTP instead of HTTPS (violates GLBA encryption in transit)",
		"remediation": "Change protocol to HTTPS and configure SSL certificate"
	}
}

# GLBA-ACCESS: Network Isolation for Customer Data
# Deny security groups allowing unrestricted access to customer data systems
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group"
	sg_name := resource.change.after.name

	# Check for customer data system tagging
	tags := object.get(resource.change.after, "tags", {})
	system_type := lower(object.get(tags, "SystemType", ""))
	system_type in ["customer-data", "financial", "npi-storage"]

	# Check for ingress rules allowing 0.0.0.0/0
	some ingress in object.get(resource.change.after, "ingress", [])
	some cidr in ingress.cidr_blocks
	cidr == "0.0.0.0/0"

	msg := {
		"policy": "aws.compliance.glba",
		"resource": resource.address,
		"severity": "CRITICAL",
		"compliance": "GLBA-ACCESS",
		"message": sprintf("Security group '%s' for customer data system allows unrestricted access from 0.0.0.0/0 (violates GLBA access controls)", [sg_name]),
		"remediation": "Restrict ingress to specific IP ranges or VPN connections only"
	}
}
