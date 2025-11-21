package azure.security.network_security

import rego.v1

# METADATA
# title: Azure Network Security Group Rules
# description: Prevents overly permissive network security group rules
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 1.2.1
#     - PCI-DSS 1.3
#     - FFIEC D3.DC.Ev.B.1

# Check if resource is a network security group
is_nsg(resource) if {
	resource.type == "azurerm_network_security_group"
}

# Check if resource is a network security rule
is_nsg_rule(resource) if {
	resource.type == "azurerm_network_security_rule"
}

# Check if source is unrestricted
is_unrestricted_source(source) if {
	source in ["*", "Internet", "0.0.0.0/0", "::/0"]
}

# Sensitive ports that should never be open to Internet
sensitive_ports := [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 5601, 445, 135, 139]

# Check if port range includes sensitive port
includes_sensitive_port(from_port, to_port) if {
	some sensitive_port in sensitive_ports
	from_port_int := to_number(from_port)
	to_port_int := to_number(to_port)
	sensitive_port >= from_port_int
	sensitive_port <= to_port_int
}

# Special case for "*" port
includes_sensitive_port(port, _) if {
	port == "*"
}

# Deny NSG rules with inbound access from Internet on sensitive ports
deny contains msg if {
	some resource in input.resource_changes
	is_nsg_rule(resource.change.after)
	rule_name := resource.change.after.name

	resource.change.after.direction == "Inbound"
	resource.change.after.access == "Allow"

	# Check source
	source := resource.change.after.source_address_prefix
	is_unrestricted_source(source)

	# Check destination port
	dest_port := resource.change.after.destination_port_range
	includes_sensitive_port(dest_port, dest_port)

	msg := {
		"policy": "azure.security.network_security",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("NSG rule '%s' allows inbound Internet access on sensitive port %s", [rule_name, dest_port]),
		"remediation": "Restrict source_address_prefix to specific IP ranges, not '*' or 'Internet'"
	}
}

# Deny NSG inline rules with inbound access from Internet on sensitive ports
deny contains msg if {
	some resource in input.resource_changes
	is_nsg(resource.change.after)
	nsg_name := resource.change.after.name

	some rule in resource.change.after.security_rule
	rule.direction == "Inbound"
	rule.access == "Allow"

	source := rule.source_address_prefix
	is_unrestricted_source(source)

	dest_port := rule.destination_port_range
	includes_sensitive_port(dest_port, dest_port)

	msg := {
		"policy": "azure.security.network_security",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("NSG '%s' has inline rule allowing Internet access on sensitive port %s", [nsg_name, dest_port]),
		"remediation": "Restrict source_address_prefix to specific IP ranges, not '*' or 'Internet'"
	}
}

# Warn about rules allowing all ports from Internet
deny contains msg if {
	some resource in input.resource_changes
	is_nsg_rule(resource.change.after)
	rule_name := resource.change.after.name

	resource.change.after.direction == "Inbound"
	resource.change.after.access == "Allow"

	source := resource.change.after.source_address_prefix
	is_unrestricted_source(source)

	dest_port := resource.change.after.destination_port_range
	dest_port == "*"

	msg := {
		"policy": "azure.security.network_security",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("NSG rule '%s' allows ALL ports from Internet", [rule_name]),
		"remediation": "Restrict to specific ports and source IP ranges using least privilege principle"
	}
}
