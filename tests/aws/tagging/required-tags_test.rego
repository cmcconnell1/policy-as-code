package aws.tagging.required_tags

import rego.v1

# Test: Resource with all required tags passes
test_resource_with_all_tags_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_instance.compliant",
		"type": "aws_instance",
		"change": {"after": {"tags": {
			"Environment": "dev",
			"CostCenter": "CC1234",
			"Owner": "team@example.com",
			"Application": "myapp",
			"DataClassification": "internal",
		}}},
	}]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: Resource missing required tags fails
test_resource_missing_tags_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_instance.incomplete",
		"type": "aws_instance",
		"change": {"after": {"tags": {
			"Environment": "dev",
			"Owner": "team@example.com",
		}}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	violation.severity == "MEDIUM"
	contains(violation.message, "missing required tags")
}

# Test: Resource with empty tag values fails
test_resource_with_empty_tags_fails if {
	test_data := {"resource_changes": [{
		"address": "aws_instance.empty_tags",
		"type": "aws_instance",
		"change": {"after": {"tags": {
			"Environment": "",
			"CostCenter": "CC1234",
			"Owner": "team@example.com",
			"Application": "myapp",
			"DataClassification": "internal",
		}}},
	}]}

	result := deny with input as test_data
	count(result) == 1
	some violation in result
	contains(violation.message, "empty values")
}

# Test: Non-taggable resource is ignored
test_non_taggable_resource_ignored if {
	test_data := {"resource_changes": [{
		"address": "aws_iam_policy_attachment.test",
		"type": "aws_iam_policy_attachment",
		"change": {"after": {}},
	}]}

	result := deny with input as test_data
	count(result) == 0
}

# Test: S3 bucket with required tags passes
test_s3_with_tags_passes if {
	test_data := {"resource_changes": [{
		"address": "aws_s3_bucket.tagged",
		"type": "aws_s3_bucket",
		"change": {"after": {"tags": {
			"Environment": "prod",
			"CostCenter": "FIN001",
			"Owner": "dataeng@example.com",
			"Application": "datalake",
			"DataClassification": "confidential",
		}}},
	}]}

	result := deny with input as test_data
	count(result) == 0
}
