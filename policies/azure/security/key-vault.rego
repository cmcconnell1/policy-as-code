package azure.security.key_vault

import rego.v1

# METADATA
# title: Azure Key Vault Security
# description: Ensures Key Vaults follow security best practices
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 3.4
#     - SOX-302
#     - FFIEC D3.DC.Rm.B.3

# Check if resource is a Key Vault
is_key_vault(resource) if {
	resource.type == "azurerm_key_vault"
}

# Deny Key Vaults without soft delete enabled
deny contains msg if {
	some resource in input.resource_changes
	is_key_vault(resource.change.after)
	vault_name := resource.change.after.name

	resource.change.after.soft_delete_retention_days == 0

	msg := {
		"policy": "azure.security.key_vault",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Key Vault '%s' does not have soft delete enabled", [vault_name]),
		"remediation": "Set 'soft_delete_retention_days' to a value between 7 and 90 (recommended: 90)"
	}
}

# Deny Key Vaults without purge protection
deny contains msg if {
	some resource in input.resource_changes
	is_key_vault(resource.change.after)
	vault_name := resource.change.after.name

	not resource.change.after.purge_protection_enabled

	msg := {
		"policy": "azure.security.key_vault",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Key Vault '%s' does not have purge protection enabled", [vault_name]),
		"remediation": "Set 'purge_protection_enabled = true' to prevent permanent deletion"
	}
}

# Deny Key Vaults allowing public network access without firewall rules
deny contains msg if {
	some resource in input.resource_changes
	is_key_vault(resource.change.after)
	vault_name := resource.change.after.name

	# Check if public network access is enabled
	resource.change.after.public_network_access_enabled == true

	# Check if network ACLs are configured
	not resource.change.after.network_acls

	msg := {
		"policy": "azure.security.key_vault",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Key Vault '%s' allows public network access without firewall rules", [vault_name]),
		"remediation": "Configure 'network_acls' block or set 'public_network_access_enabled = false'"
	}
}

# Deny Key Vaults with default network ACL action set to Allow
deny contains msg if {
	some resource in input.resource_changes
	is_key_vault(resource.change.after)
	vault_name := resource.change.after.name

	network_acls := resource.change.after.network_acls
	network_acls.default_action == "Allow"

	msg := {
		"policy": "azure.security.key_vault",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Key Vault '%s' has network ACL default action set to 'Allow'", [vault_name]),
		"remediation": "Set network_acls.default_action = 'Deny' and explicitly allow trusted networks"
	}
}

# Warn about Key Vaults not using RBAC for access control
deny contains msg if {
	some resource in input.resource_changes
	is_key_vault(resource.change.after)
	vault_name := resource.change.after.name

	not resource.change.after.enable_rbac_authorization

	msg := {
		"policy": "azure.security.key_vault",
		"resource": resource.address,
		"severity": "MEDIUM",
		"message": sprintf("Key Vault '%s' does not use RBAC for access control (uses access policies)", [vault_name]),
		"remediation": "Set 'enable_rbac_authorization = true' for centralized access management (recommended for new vaults)"
	}
}
