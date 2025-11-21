package aws.security.s3_public_access

import rego.v1

# METADATA
# title: S3 Public Access Block Enforcement
# description: Ensures S3 buckets have public access blocked
# custom:
#   severity: CRITICAL
#   frameworks:
#     - PCI-DSS 1.2.1
#     - PCI-DSS 1.3.1
#     - SOX-302
#     - FFIEC D3.DC.Am.B.1

# Check if resource is an S3 bucket
is_s3_bucket(resource) if {
	resource.type == "aws_s3_bucket"
}

# Check if resource is public access block configuration
is_public_access_block(resource) if {
	resource.type == "aws_s3_bucket_public_access_block"
}

# Validate all public access block settings are enabled
valid_public_access_block(config) if {
	config.block_public_acls == true
	config.block_public_policy == true
	config.ignore_public_acls == true
	config.restrict_public_buckets == true
}

# Deny S3 buckets without public access block
deny contains msg if {
	some resource in input.resource_changes
	is_s3_bucket(resource)
	bucket_name := resource.change.after.bucket

	# Check if there's a corresponding public access block
	public_access_blocks := [pab |
		some pab in input.resource_changes
		is_public_access_block(pab)
		pab.change.after.bucket == bucket_name
	]

	count(public_access_blocks) == 0

	msg := {
		"policy": "aws.security.s3_public_access",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("S3 bucket '%s' does not have public access block configured", [bucket_name]),
		"remediation": "Add aws_s3_bucket_public_access_block resource with all settings set to true"
	}
}

# Deny public access blocks with incomplete settings
deny contains msg if {
	some resource in input.resource_changes
	is_public_access_block(resource)
	bucket_name := resource.change.after.bucket
	not valid_public_access_block(resource.change.after)

	msg := {
		"policy": "aws.security.s3_public_access",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("S3 bucket '%s' public access block is incomplete (all settings must be true)", [bucket_name]),
		"remediation": "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true"
	}
}

# Deny buckets with ACL set to public-read or public-read-write
deny contains msg if {
	some resource in input.resource_changes
	is_s3_bucket(resource)
	bucket_name := resource.change.after.bucket
	acl := resource.change.after.acl
	acl in ["public-read", "public-read-write"]

	msg := {
		"policy": "aws.security.s3_public_access",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("S3 bucket '%s' has public ACL '%s'", [bucket_name, acl]),
		"remediation": "Remove or change ACL to 'private' and configure aws_s3_bucket_public_access_block"
	}
}
