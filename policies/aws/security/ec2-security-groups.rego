package aws.security.ec2_security_groups

import rego.v1

# METADATA
# title: EC2 Security Group Restrictions
# description: Prevents overly permissive security group rules
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 1.2.1
#     - PCI-DSS 1.3
#     - FFIEC D3.DC.Ev.B.1

# Check if resource is a security group
is_security_group(resource) if {
	resource.type == "aws_security_group"
}

# Check if resource is a security group rule
is_security_group_rule(resource) if {
	resource.type == "aws_security_group_rule"
}

# Check if CIDR is unrestricted (0.0.0.0/0 or ::/0)
is_unrestricted_cidr(cidr) if {
	cidr in ["0.0.0.0/0", "::/0"]
}

# Sensitive ports that should never be open to 0.0.0.0/0
sensitive_ports := [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 5601]

# Deny security groups with ingress from 0.0.0.0/0 on sensitive ports
deny contains msg if {
	some resource in input.resource_changes
	is_security_group(resource.change.after)
	sg_name := resource.change.after.name

	some ingress in resource.change.after.ingress
	some cidr in ingress.cidr_blocks
	is_unrestricted_cidr(cidr)

	# Check if port range includes sensitive ports
	from_port := ingress.from_port
	to_port := ingress.to_port
	some sensitive_port in sensitive_ports
	sensitive_port >= from_port
	sensitive_port <= to_port

	msg := {
		"policy": "aws.security.ec2_security_groups",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("Security group '%s' allows unrestricted access (0.0.0.0/0) to sensitive port %d", [sg_name, sensitive_port]),
		"remediation": sprintf("Restrict cidr_blocks to specific IP ranges, not 0.0.0.0/0 for port %d", [sensitive_port])
	}
}

# Deny security group rules with ingress from 0.0.0.0/0 on sensitive ports
deny contains msg if {
	some resource in input.resource_changes
	is_security_group_rule(resource.change.after)
	resource.change.after.type == "ingress"

	some cidr in resource.change.after.cidr_blocks
	is_unrestricted_cidr(cidr)

	from_port := resource.change.after.from_port
	to_port := resource.change.after.to_port
	some sensitive_port in sensitive_ports
	sensitive_port >= from_port
	sensitive_port <= to_port

	msg := {
		"policy": "aws.security.ec2_security_groups",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("Security group rule allows unrestricted access (0.0.0.0/0) to sensitive port %d", [sensitive_port]),
		"remediation": sprintf("Restrict cidr_blocks to specific IP ranges, not 0.0.0.0/0 for port %d", [sensitive_port])
	}
}

# Warn about security groups allowing all ports from 0.0.0.0/0
deny contains msg if {
	some resource in input.resource_changes
	is_security_group(resource.change.after)
	sg_name := resource.change.after.name

	some ingress in resource.change.after.ingress
	ingress.from_port == 0
	ingress.to_port == 65535
	some cidr in ingress.cidr_blocks
	is_unrestricted_cidr(cidr)

	msg := {
		"policy": "aws.security.ec2_security_groups",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("Security group '%s' allows ALL ports from 0.0.0.0/0", [sg_name]),
		"remediation": "Restrict to specific ports and source IP ranges using least privilege principle"
	}
}
