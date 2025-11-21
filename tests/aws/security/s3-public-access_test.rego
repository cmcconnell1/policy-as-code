package aws.security.s3_public_access

import rego.v1

# Test: S3 bucket with full public access block passes
test_s3_with_public_access_block_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.secure",
			"type": "aws_s3_bucket",
			"change": {"after": {
				"bucket": "secure-bucket",
				"acl": "private",
			}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.secure",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"after": {
				"bucket": "secure-bucket",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: S3 bucket without public access block fails
test_s3_without_public_access_block_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.insecure",
		"type": "aws_s3_bucket",
		"change": {"after": {"bucket": "insecure-bucket"}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.severity == "CRITICAL"
}

# Test: S3 bucket with incomplete public access block fails
test_s3_with_incomplete_block_fails if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.partial",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "partial-bucket"}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.partial",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"after": {
				"bucket": "partial-bucket",
				"block_public_acls": true,
				"block_public_policy": false,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	contains(violation.message, "incomplete")
}

# Test: S3 bucket with public-read ACL fails
test_s3_with_public_read_acl_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.public_read",
		"type": "aws_s3_bucket",
		"change": {"after": {
			"bucket": "public-bucket",
			"acl": "public-read",
		}},
	}]}

	result := deny with input as test_data
	count(result) >= 1
	some violation in result
	violation.severity == "CRITICAL"
	contains(violation.message, "public ACL")
}
