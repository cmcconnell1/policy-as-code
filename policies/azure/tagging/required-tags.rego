package azure.tagging.required_tags

import rego.v1

# METADATA
# title: Required Resource Tags
# description: Enforces mandatory tags on all Azure resources
# custom:
#   severity: MEDIUM
#   frameworks:
#     - Cost Management
#     - FFIEC D5.RM.RM.B.1

# Required tags for all resources (financial services industry)
required_tags := [
	"Environment",
	"CostCenter",
	"Owner",
	"Application",
	"DataClassification",
]

# Resources that support tagging
taggable_resources := {
	"azurerm_resource_group",
	"azurerm_virtual_machine",
	"azurerm_linux_virtual_machine",
	"azurerm_windows_virtual_machine",
	"azurerm_storage_account",
	"azurerm_sql_database",
	"azurerm_sql_server",
	"azurerm_postgresql_server",
	"azurerm_mysql_server",
	"azurerm_virtual_network",
	"azurerm_subnet",
	"azurerm_network_security_group",
	"azurerm_key_vault",
	"azurerm_kubernetes_cluster",
	"azurerm_container_registry",
	"azurerm_app_service",
	"azurerm_function_app",
	"azurerm_cosmosdb_account",
	"azurerm_redis_cache",
	"azurerm_log_analytics_workspace",
}

# Check if resource type supports tagging
is_taggable(resource_type) if {
	resource_type in taggable_resources
}

# Get tags from resource
get_tags(resource) := tags if {
	tags := resource.tags
} else := {}

# Check if all required tags are present
has_required_tags(tags) if {
	every tag in required_tags {
		tags[tag]
	}
}

# Deny resources missing required tags
deny contains msg if {
	some resource in input.resource_changes
	is_taggable(resource.type)
	resource_addr := resource.address

	tags := get_tags(resource.change.after)

	# Find missing tags
	missing_tags := [tag |
		some tag in required_tags
		not tags[tag]
	]

	count(missing_tags) > 0

	msg := {
		"policy": "azure.tagging.required_tags",
		"resource": resource_addr,
		"severity": "MEDIUM",
		"message": sprintf("Resource is missing required tags: %v", [missing_tags]),
		"remediation": sprintf("Add tags block with: %v", [missing_tags])
	}
}

# Warn about empty tag values
deny contains msg if {
	some resource in input.resource_changes
	is_taggable(resource.type)
	resource_addr := resource.address

	tags := get_tags(resource.change.after)

	# Find tags with empty values
	empty_tags := [tag_name |
		some tag_name, tag_value in tags
		tag_name in required_tags
		trim_space(tag_value) == ""
	]

	count(empty_tags) > 0

	msg := {
		"policy": "azure.tagging.required_tags",
		"resource": resource_addr,
		"severity": "MEDIUM",
		"message": sprintf("Resource has required tags with empty values: %v", [empty_tags]),
		"remediation": "Provide non-empty values for all required tags"
	}
}
