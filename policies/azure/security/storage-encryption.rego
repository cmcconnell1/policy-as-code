package azure.security.storage_encryption

import rego.v1

# METADATA
# title: Azure Storage Account Encryption
# description: Ensures Azure Storage accounts have encryption enabled
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 3.4
#     - SOX-ITGC
#     - FFIEC D3.DC.Rm.B.3

# Check if resource is a storage account
is_storage_account(resource) if {
	resource.type == "azurerm_storage_account"
}

# Deny storage accounts without infrastructure encryption
deny contains msg if {
	some resource in input.resource_changes
	is_storage_account(resource.change.after)
	account_name := resource.change.after.name

	# infrastructure_encryption_enabled should be true for double encryption
	not resource.change.after.infrastructure_encryption_enabled

	msg := {
		"policy": "azure.security.storage_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Storage account '%s' does not have infrastructure encryption enabled", [account_name]),
		"remediation": "Set 'infrastructure_encryption_enabled = true' for double encryption at rest"
	}
}

# Deny storage accounts with insecure minimum TLS version
deny contains msg if {
	some resource in input.resource_changes
	is_storage_account(resource.change.after)
	account_name := resource.change.after.name

	tls_version := resource.change.after.min_tls_version
	tls_version != "TLS1_2"

	msg := {
		"policy": "azure.security.storage_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Storage account '%s' allows TLS version lower than 1.2 (current: %s)", [account_name, tls_version]),
		"remediation": "Set 'min_tls_version = \"TLS1_2\"' to enforce secure transport"
	}
}

# Deny storage accounts allowing public blob access
deny contains msg if {
	some resource in input.resource_changes
	is_storage_account(resource.change.after)
	account_name := resource.change.after.name

	# allow_blob_public_access should be false
	resource.change.after.allow_blob_public_access == true

	msg := {
		"policy": "azure.security.storage_encryption",
		"resource": resource.address,
		"severity": "CRITICAL",
		"message": sprintf("Storage account '%s' allows public blob access", [account_name]),
		"remediation": "Set 'allow_blob_public_access = false' to prevent unauthorized access"
	}
}

# Deny storage accounts without HTTPS enforcement
deny contains msg if {
	some resource in input.resource_changes
	is_storage_account(resource.change.after)
	account_name := resource.change.after.name

	resource.change.after.enable_https_traffic_only == false

	msg := {
		"policy": "azure.security.storage_encryption",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("Storage account '%s' does not enforce HTTPS-only traffic", [account_name]),
		"remediation": "Set 'enable_https_traffic_only = true' to enforce secure transport"
	}
}
