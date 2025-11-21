package aws.security.iam_mfa

import rego.v1

# METADATA
# title: IAM MFA Enforcement
# description: Ensures IAM users and roles require MFA for privileged access
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 8.3.1
#     - SOX-302
#     - FFIEC D2.AC.Au.B.3

# Check if resource is an IAM policy
is_iam_policy(resource) if {
	resource.type == "aws_iam_policy"
}

# Check if resource is an IAM role
is_iam_role(resource) if {
	resource.type == "aws_iam_role"
}

# Check if policy document contains privileged actions
has_privileged_actions(policy_doc) if {
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	some action in statement.Action
	privileged_action_patterns := [
		"iam:*",
		"*:*",
		"sts:AssumeRole",
		"ec2:TerminateInstances",
		"s3:DeleteBucket",
		"rds:DeleteDBInstance",
	]
	some pattern in privileged_action_patterns
	action == pattern
}

# Check if policy has MFA condition
has_mfa_condition(policy_doc) if {
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	statement.Condition.Bool["aws:MultiFactorAuthPresent"] == "true"
}

# Check if policy has MFA condition (alternative format)
has_mfa_condition(policy_doc) if {
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	statement.Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "true"
}

# Deny IAM policies with privileged actions but no MFA requirement
deny contains msg if {
	some resource in input.resource_changes
	is_iam_policy(resource.change.after)
	policy_name := resource.change.after.name

	# Parse policy document (may be JSON string or object)
	policy_doc := json.unmarshal(resource.change.after.policy)

	has_privileged_actions(policy_doc)
	not has_mfa_condition(policy_doc)

	msg := {
		"policy": "aws.security.iam_mfa",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("IAM policy '%s' grants privileged access without requiring MFA", [policy_name]),
		"remediation": "Add Condition with 'aws:MultiFactorAuthPresent': 'true' to policy statements"
	}
}

# Deny IAM roles with privileged assume role policy but no MFA requirement
deny contains msg if {
	some resource in input.resource_changes
	is_iam_role(resource.change.after)
	role_name := resource.change.after.name

	# Parse assume role policy document
	assume_role_policy := json.unmarshal(resource.change.after.assume_role_policy)

	some statement in assume_role_policy.Statement
	statement.Effect == "Allow"
	statement.Principal.AWS
	not statement.Condition.Bool["aws:MultiFactorAuthPresent"]

	msg := {
		"policy": "aws.security.iam_mfa",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("IAM role '%s' allows assume role without MFA", [role_name]),
		"remediation": "Add MFA condition to assume_role_policy: Condition.Bool['aws:MultiFactorAuthPresent'] = 'true'"
	}
}
