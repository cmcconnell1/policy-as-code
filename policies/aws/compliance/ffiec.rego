package aws.compliance.ffiec

import rego.v1

# METADATA
# title: FFIEC Cybersecurity Assessment Tool
# description: Federal Financial Institutions Examination Council requirements
# custom:
#   severity: HIGH
#   frameworks:
#     - FFIEC CAT (Cybersecurity Assessment Tool)
#     - Banking Industry Standards

# FFIEC Domain 2: Threat Intelligence & Collaboration
# Deny production resources without security monitoring tags
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_instance", "aws_rds_instance", "aws_lambda_function"]

	tags := object.get(resource.change.after, "tags", {})
	environment := lower(object.get(tags, "Environment", ""))

	environment in ["prod", "production"]

	not tags.SecurityMonitoring
	not tags.AlertingEnabled

	msg := {
		"policy": "aws.compliance.ffiec",
		"resource": resource.address,
		"severity": "MEDIUM",
		"compliance": "FFIEC D2.TI.Ti.B.1",
		"message": "Production resources must have security monitoring tags",
		"remediation": "Add tags: SecurityMonitoring = 'enabled' and AlertingEnabled = 'true'"
	}
}

# FFIEC Domain 3: Cybersecurity Controls - Preventative
# Deny VPCs without flow logs enabled
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_vpc"
	vpc_id := resource.change.after.id

	# Check if there's a corresponding flow log
	flow_logs := [fl |
		some fl in input.resource_changes
		fl.type == "aws_flow_log"
		fl.change.after.vpc_id == vpc_id
	]

	count(flow_logs) == 0

	msg := {
		"policy": "aws.compliance.ffiec",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "FFIEC D3.DC.Ev.B.1",
		"message": "VPC does not have flow logs enabled for network monitoring",
		"remediation": "Add aws_flow_log resource to capture network traffic for security analysis"
	}
}

# FFIEC Domain 3: Data Security & Privacy
# Already covered by encryption policies

# FFIEC Domain 4: Cybersecurity Event Detection
# Deny lack of GuardDuty in security-sensitive deployments
deny contains msg if {
	# Check for GuardDuty detector
	guardduty := [gd | some gd in input.resource_changes; gd.type == "aws_guardduty_detector"]

	count(guardduty) == 0

	# Check if any data storage resources exist
	data_resources := [r |
		some r in input.resource_changes
		r.type in ["aws_s3_bucket", "aws_rds_instance", "aws_dynamodb_table"]
		tags := object.get(r.change.after, "tags", {})
		data_class := lower(object.get(tags, "DataClassification", ""))
		data_class in ["restricted", "confidential"]
	]

	count(data_resources) > 0

	msg := {
		"policy": "aws.compliance.ffiec",
		"resource": "infrastructure",
		"severity": "MEDIUM",
		"compliance": "FFIEC D4.DC.De.B.1",
		"message": "Deployment includes sensitive data resources but no GuardDuty for threat detection",
		"remediation": "Add aws_guardduty_detector resource for continuous security monitoring"
	}
}

# FFIEC Domain 5: Cyber Resilience
# Deny RDS without multi-AZ for production
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_rds_instance", "aws_db_instance"]
	db_name := resource.change.after.identifier

	tags := object.get(resource.change.after, "tags", {})
	environment := lower(object.get(tags, "Environment", ""))

	environment in ["prod", "production"]

	not resource.change.after.multi_az

	msg := {
		"policy": "aws.compliance.ffiec",
		"resource": resource.address,
		"severity": "HIGH",
		"compliance": "FFIEC D5.DR.De.B.1",
		"message": sprintf("Production RDS instance '%s' does not have multi-AZ enabled for resilience", [db_name]),
		"remediation": "Set multi_az = true for automatic failover capability"
	}
}

# FFIEC: Backup and Recovery
# Deny critical resources without backup tags
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["aws_ebs_volume", "aws_rds_instance", "aws_efs_file_system"]

	tags := object.get(resource.change.after, "tags", {})

	not tags.BackupPolicy
	not tags.BackupSchedule

	msg := {
		"policy": "aws.compliance.ffiec",
		"resource": resource.address,
		"severity": "MEDIUM",
		"compliance": "FFIEC D5.DR.De.B.3",
		"message": "Data storage resource missing backup policy tags",
		"remediation": "Add tags: BackupPolicy = 'daily' and BackupSchedule = '0 2 * * *' (or appropriate schedule)"
	}
}
