package aws.security.s3_encryption

import rego.v1

# Test: S3 bucket with proper encryption passes
test_s3_bucket_with_encryption_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.compliant",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "test-bucket"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.compliant",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "test-bucket",
				"rule": [{
					"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"},
				}],
			}},
		},
	]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: S3 bucket without encryption fails
test_s3_bucket_without_encryption_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.non_compliant",
		"type": "aws_s3_bucket",
		"change": {"after": {"bucket": "test-bucket"}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.severity == "HIGH"
	violation.policy == "aws.security.s3_encryption"
}

# Test: S3 bucket with KMS encryption passes
test_s3_bucket_with_kms_encryption_passes if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.kms_encrypted",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "test-bucket-kms"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.kms",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "test-bucket-kms",
				"rule": [{
					"apply_server_side_encryption_by_default": {
						"sse_algorithm": "aws:kms",
						"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				}],
			}},
		},
	]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: S3 bucket with invalid encryption algorithm fails
test_s3_bucket_with_invalid_algorithm_fails if {
	test_data := {"resource_changes": [
		{
			"address": "aws_s3_bucket.invalid_algo",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "test-bucket"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.invalid",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "test-bucket",
				"rule": [{
					"apply_server_side_encryption_by_default": {"sse_algorithm": "DES"},
				}],
			}},
		},
	]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	contains(violation.message, "invalid algorithm")
}
