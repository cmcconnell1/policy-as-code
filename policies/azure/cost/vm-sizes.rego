package azure.cost.vm_sizes

import rego.v1

# METADATA
# title: Azure VM Size Restrictions
# description: Restricts Azure VM sizes to approved cost-effective options
# custom:
#   severity: MEDIUM
#   frameworks:
#     - Cost Management
#     - FinOps

# Approved VM size prefixes
approved_vm_prefixes := {
	"Standard_B", # Burstable
	"Standard_D", # General purpose
	"Standard_E", # Memory optimized
	"Standard_F", # Compute optimized
}

# Prohibited expensive VM series
prohibited_vm_prefixes := {
	"Standard_M", # Extreme memory (very expensive)
	"Standard_G", # Deprecated, expensive
	"Standard_N", # GPU instances
	"Standard_H", # HPC instances
	"Standard_L", # Storage optimized (expensive)
}

# Maximum allowed VM sizes (by suffix)
max_allowed_sizes := {
	"1s", "2s", "4s", "8s", # Standard sizes
	"1", "2", "4", "8", # Non-premium sizes
	"v2", "v3", "v4", "v5", # Version suffixes are OK
}

# Check if VM size is approved
is_approved_vm(vm_size) if {
	some prefix in approved_vm_prefixes
	startswith(vm_size, prefix)
}

# Check if VM size is prohibited
is_prohibited_vm(vm_size) if {
	some prefix in prohibited_vm_prefixes
	startswith(vm_size, prefix)
}

# Extract size number from VM size (e.g., "16" from "Standard_D16s_v3")
get_vm_size_number(vm_size) := size_num if {
	# Match pattern like "Standard_D16s_v3"
	regex.match(`Standard_[A-Z]+([0-9]+)`, vm_size)
	parts := regex.find_n(`[0-9]+`, vm_size, 1)
	count(parts) > 0
	size_num := to_number(parts[0])
}

# Deny unapproved Azure VM sizes
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"]
	vm_size := resource.change.after.size

	not is_approved_vm(vm_size)

	msg := {
		"policy": "azure.cost.vm_sizes",
		"resource": resource.address,
		"severity": "MEDIUM",
		"message": sprintf("VM size '%s' is not in approved list", [vm_size]),
		"remediation": sprintf("Use VM sizes starting with: %v", [approved_vm_prefixes])
	}
}

# Deny prohibited expensive VM sizes
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"]
	vm_size := resource.change.after.size

	is_prohibited_vm(vm_size)

	msg := {
		"policy": "azure.cost.vm_sizes",
		"resource": resource.address,
		"severity": "HIGH",
		"message": sprintf("VM size '%s' uses prohibited expensive series", [vm_size]),
		"remediation": "Specialized VMs require cost approval. Contact FinOps team or use approved series"
	}
}

# Warn about oversized VMs (16+ cores)
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"]
	vm_size := resource.change.after.size

	size_num := get_vm_size_number(vm_size)
	size_num >= 16

	msg := {
		"policy": "azure.cost.vm_sizes",
		"resource": resource.address,
		"severity": "MEDIUM",
		"message": sprintf("VM size '%s' has %d vCPUs, which may be oversized", [vm_size, size_num]),
		"remediation": "Consider using smaller VMs (4-8 vCPUs) or request approval for larger sizes"
	}
}
