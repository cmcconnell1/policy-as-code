package aws.compliance.glba

import rego.v1

# Test: S3 bucket with customer data and encryption passes
test_s3_customer_data_encrypted_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.customer_data",
			"type": "aws_s3_bucket",
			"change": {"after": {
				"bucket": "customer-data-bucket",
				"tags": {
					"DataClassification": "NPI",
					"VendorCompliance": "AWS-SOC2-2024",
					"ApprovedRegion": "true",
				},
			}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.customer_data",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "customer-data-bucket",
				"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
			}},
		},
		{
			"address": "aws_s3_bucket_logging.customer_data",
			"type": "aws_s3_bucket_logging",
			"change": {"after": {"bucket": "customer-data-bucket"}},
		},
		{
			"address": "aws_cloudtrail.audit",
			"type": "aws_cloudtrail",
			"change": {"after": {"name": "audit-trail"}},
		},
	]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: S3 bucket with customer data without encryption fails
test_s3_customer_data_no_encryption_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.insecure_customer_data",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "insecure-bucket",
			"tags": {"DataClassification": "NPI"},
		}},
	}]}

	result := deny with input as test_data
	count(result) >= 1
	some violation in result
	violation.compliance == "GLBA-SAFEGUARDS"
	contains(violation.message, "encryption")
}

# Test: RDS with customer data encrypted passes
test_rds_customer_data_encrypted_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_rds_instance.customer_db",
			"type": "aws_rds_instance",
			"change": {"after": {
				"identifier": "customer-db",
				"storage_encrypted": true,
				"backup_retention_period": 30,
				"tags": {
					"DataClassification": "confidential",
					"VendorCompliance": "AWS-SOC2-2024",
					"ApprovedRegion": "true",
				},
			}},
		},
		{
			"address": "aws_cloudtrail.audit",
			"type": "aws_cloudtrail",
			"change": {"after": {"name": "audit-trail"}},
		},
	]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: RDS with customer data unencrypted fails
test_rds_customer_data_unencrypted_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_rds_instance.insecure_db",
		"type": "aws_rds_instance",
		"change": {"after": {
			"identifier": "insecure-db",
			"storage_encrypted": false,
			"tags": {"DataClassification": "PII"},
		}},
	}]}

	result := deny with input as test_data
	count(result) >= 1
	some violation in result
	violation.compliance == "GLBA-SAFEGUARDS"
}

# Test: S3 bucket with public access to customer data fails
test_s3_public_customer_data_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.public_customer_data",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "public-bucket",
			"acl": "public-read",
			"tags": {"DataClassification": "NPI"},
		}},
	}]}

	result := deny with input as test_data
	count(result) >= 1
	some violation in result
	violation.compliance == "GLBA-ACCESS"
	contains(violation.message, "public access")
}

# Test: IAM user with financial access fails
test_iam_user_financial_access_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_iam_user.financial_user",
		"type": "aws_iam_user",
		"change": {"after": {
			"name": "financial-admin",
			"tags": {"AccessLevel": "financial"},
		}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.compliance == "GLBA-ACCESS"
	contains(violation.message, "MFA")
}

# Test: S3 bucket with customer data and logging passes
test_s3_customer_data_with_logging_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.customer_data",
			"type": "aws_s3_bucket",
			"change": {"after": {
				"bucket": "customer-bucket",
				"tags": {"DataClassification": "restricted"},
			}},
		},
		{
			"address": "aws_s3_bucket_logging.customer_data",
			"type": "aws_s3_bucket_logging",
			"change": {"after": {"bucket": "customer-bucket"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.customer_data",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "customer-bucket",
				"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
			}},
		},
	]}

	result := deny with input as test_data
	# Should not have logging violation
	logging_violations := [v | some v in result; v.compliance == "GLBA-MONITORING"; contains(v.message, "logging")]
	count(logging_violations) == 0
}

# Test: S3 bucket with customer data without logging fails
test_s3_customer_data_no_logging_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.no_logging",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "no-logging-bucket",
			"tags": {"DataClassification": "confidential"},
		}},
	}]}

	result := deny with input as test_data
	some violation in result
	violation.compliance == "GLBA-MONITORING"
	contains(violation.message, "logging")
}

# Test: RDS with proper backup retention passes
test_rds_proper_backup_retention_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_rds_instance.customer_db",
		"type": "aws_rds_instance",
		"change": {"after": {
			"identifier": "customer-db",
			"backup_retention_period": 30,
			"tags": {"DataClassification": "NPI"},
		}},
	}]}

	result := deny with input as test_data
	# Check no GLBA-BREACH violation about retention
	breach_violations := [v | some v in result; v.compliance == "GLBA-BREACH"]
	count(breach_violations) == 0
}

# Test: RDS with insufficient backup retention fails
test_rds_insufficient_backup_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_rds_instance.short_backup",
		"type": "aws_rds_instance",
		"change": {"after": {
			"identifier": "short-backup-db",
			"backup_retention_period": 7,
			"tags": {"DataClassification": "PII"},
		}},
	}]}

	result := deny with input as test_data
	some violation in result
	violation.compliance == "GLBA-BREACH"
	contains(violation.message, "30 days")
}

# Test: Load balancer with HTTPS passes
test_lb_https_customer_data_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_lb_listener.secure",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"tags": {"DataType": "customer"},
		}},
	}]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: Load balancer with HTTP for customer data fails
test_lb_http_customer_data_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_lb_listener.insecure",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTP",
			"tags": {"DataType": "financial"},
		}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.compliance == "GLBA-SAFEGUARDS"
	contains(violation.message, "HTTPS")
}

# Test: Security group with restricted access passes
test_sg_restricted_access_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_security_group.customer_sg",
		"type": "aws_security_group",
		"change": {"after": {
			"name": "customer-data-sg",
			"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}],
			"tags": {"SystemType": "customer-data"},
		}},
	}]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: Security group with unrestricted access fails
test_sg_unrestricted_access_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_security_group.open_sg",
		"type": "aws_security_group",
		"change": {"after": {
			"name": "open-sg",
			"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
			"tags": {"SystemType": "financial"},
		}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.compliance == "GLBA-ACCESS"
	contains(violation.message, "0.0.0.0/0")
}

# Test: Resource without vendor compliance tagging fails
test_resource_no_vendor_compliance_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.no_vendor_tag",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "no-vendor-bucket",
			"tags": {"DataClassification": "restricted"},
		}},
	}]}

	result := deny with input as test_data
	some violation in result
	violation.compliance == "GLBA-VENDOR"
	contains(violation.message, "vendor compliance")
}

# Test: Resource with vendor compliance tagging passes
test_resource_with_vendor_compliance_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.vendor_compliant",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "vendor-compliant-bucket",
			"tags": {
				"DataClassification": "confidential",
				"VendorCompliance": "AWS-SOC2-2024",
				"ApprovedRegion": "true",
			},
		}},
	}]}

	result := deny with input as test_data
	# Check no GLBA-VENDOR violations
	vendor_violations := [v | some v in result; v.compliance == "GLBA-VENDOR"]
	count(vendor_violations) == 0
}
