package aws.security.s3_encryption

import rego.v1

# METADATA
# title: S3 Bucket Encryption Enforcement
# description: Ensures all S3 buckets have server-side encryption enabled
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 3.4
#     - SOX-ITGC
#     - FFIEC D3.DC.Rm.B.3

# Check if resource is an S3 bucket
is_s3_bucket(resource) if {
	resource.type == "aws_s3_bucket"
}

# Check if bucket has server-side encryption configuration
has_encryption(resource) if {
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
}

# Check if encryption uses AES256 or aws:kms
valid_encryption_algorithm(config) if {
	rule := config.rule[_]
	apply_server_side_encryption := rule.apply_server_side_encryption_by_default
	apply_server_side_encryption.sse_algorithm in ["AES256", "aws:kms"]
}

# Deny S3 buckets without encryption
deny contains msg if {
	some resource in input.resource_changes
	is_s3_bucket(resource)
	bucket_name := resource.change.after.bucket

	# Check if there's a corresponding encryption configuration
	encryption_configs := [enc |
		some enc in input.resource_changes
		has_encryption(enc)
		enc.change.after.bucket == bucket_name
	]

	count(encryption_configs) == 0

	msg := {
		"policy": "aws.security.s3_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("S3 bucket '%s' does not have server-side encryption enabled", [bucket_name]),
		"remediation": "Add aws_s3_bucket_server_side_encryption_configuration resource with AES256 or aws:kms encryption"
	}
}

# Deny encryption configurations with invalid algorithms
deny contains msg if {
	some resource in input.resource_changes
	has_encryption(resource)
	bucket_name := resource.change.after.bucket
	not valid_encryption_algorithm(resource.change.after)

	msg := {
		"policy": "aws.security.s3_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("S3 bucket '%s' encryption uses invalid algorithm (must be AES256 or aws:kms)", [bucket_name]),
		"remediation": "Update sse_algorithm to 'AES256' or 'aws:kms'"
	}
}
