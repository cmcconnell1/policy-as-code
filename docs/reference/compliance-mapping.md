# Compliance Framework Mapping

This document maps policies to SOX, PCI-DSS, and FFIEC compliance requirements.

## SOX (Sarbanes-Oxley Act)

### SOX-302: CEO/CFO Certification

**Purpose**: Establish responsibility for internal controls and financial reporting

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.sox.deny_iam_users` | Change Management | Prohibit IAM users; use federated roles for auditability |
| `aws.compliance.sox.deny_prod_without_approval` | Change Control | Require approval tags for production changes |

### SOX-404: Internal Control Assessment

**Purpose**: Assess effectiveness of internal controls

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.sox.deny_s3_without_logging` | Audit Logging | Require S3 access logging for audit trail |
| `aws.compliance.sox.deny_rds_without_backups` | Data Integrity | Require automated backups (30 days retention) |

### SOX-ITGC: IT General Controls

**Purpose**: IT controls supporting financial reporting

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.sox.deny_combined_permissions` | Segregation of Duties | Separate read/write/delete permissions |

## PCI-DSS (Payment Card Industry Data Security Standard)

### Requirement 1: Firewall Configuration

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.security.ec2_security_groups` | PCI-DSS 1.2.1 | Restrict inbound/outbound traffic |
| `azure.security.network_security` | PCI-DSS 1.3 | Network segmentation |

### Requirement 2: No Vendor Defaults

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.pci_dss.deny_default_ports` | PCI-DSS 2.2.4 | Prohibit default database ports |

### Requirement 3: Protect Cardholder Data

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.security.s3_encryption` | PCI-DSS 3.4 | Encrypt data at rest |
| `aws.security.kms_encryption` | PCI-DSS 3.4 | Use strong cryptography (KMS) |
| `azure.security.storage_encryption` | PCI-DSS 3.4 | Azure storage encryption |

### Requirement 7: Restrict Access

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.pci_dss.deny_public_s3_policy` | PCI-DSS 7.1 | Least privilege access |

### Requirement 8: Identify and Authenticate

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.security.iam_mfa` | PCI-DSS 8.3.1 | MFA for privileged access |

### Requirement 10: Track and Monitor

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.pci_dss.deny_no_cloudtrail` | PCI-DSS 10.2 | Audit logging required |
| `aws.compliance.pci_dss.deny_cloudtrail_without_validation` | PCI-DSS 10.5 | Log file validation |

## FFIEC (Federal Financial Institutions Examination Council)

### Domain 2: Threat Intelligence & Collaboration

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.ffiec.deny_prod_without_monitoring` | FFIEC D2.TI.Ti.B.1 | Security monitoring tags required |

### Domain 3: Cybersecurity Controls

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.ffiec.deny_vpc_without_flow_logs` | FFIEC D3.DC.Ev.B.1 | VPC flow logs for network monitoring |
| `aws.security.s3_encryption` | FFIEC D3.DC.Rm.B.3 | Data encryption at rest |
| `aws.security.kms_encryption` | FFIEC D3.DC.Rm.B.3 | Key management |

### Domain 4: Event Detection

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.ffiec.deny_no_guardduty` | FFIEC D4.DC.De.B.1 | Threat detection (GuardDuty) |

### Domain 5: Cyber Resilience

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.compliance.ffiec.deny_prod_rds_without_multi_az` | FFIEC D5.DR.De.B.1 | High availability (Multi-AZ) |
| `aws.compliance.ffiec.deny_no_backup_tags` | FFIEC D5.DR.De.B.3 | Backup and recovery |

### Domain 5: Risk Management

| Policy | Control | Description |
|--------|---------|-------------|
| `aws.tagging.required_tags` | FFIEC D5.RM.RM.B.1 | Asset inventory and tracking |

## Cross-Framework Controls

### Data Encryption

| Framework | Requirement | Policy |
|-----------|-------------|--------|
| SOX | SOX-ITGC | `aws.security.s3_encryption` |
| PCI-DSS | 3.4 | `aws.security.kms_encryption` |
| FFIEC | D3.DC.Rm.B.3 | `azure.security.storage_encryption` |

### Access Control

| Framework | Requirement | Policy |
|-----------|-------------|--------|
| SOX | SOX-302 | `aws.security.iam_mfa` |
| PCI-DSS | 7.1, 8.3.1 | `aws.security.s3_public_access` |
| FFIEC | D3.DC.Am.B.1 | `azure.security.network_security` |

### Audit Logging

| Framework | Requirement | Policy |
|-----------|-------------|--------|
| SOX | SOX-404 | `aws.compliance.sox.deny_s3_without_logging` |
| PCI-DSS | 10.2, 10.5 | `aws.compliance.pci_dss.deny_no_cloudtrail` |
| FFIEC | D4.DC.De.B.1 | `aws.compliance.ffiec.deny_vpc_without_flow_logs` |

### Network Security

| Framework | Requirement | Policy |
|-----------|-------------|--------|
| PCI-DSS | 1.2.1, 1.3 | `aws.security.ec2_security_groups` |
| FFIEC | D3.DC.Ev.B.1 | `azure.security.network_security` |

## Compliance Report Generation

### Generate Framework-Specific Reports

```bash
# SOX compliance report
uv run python -m reporting.cli compliance \
  --framework sox \
  --input policy-results.json \
  --output reports

# PCI-DSS compliance report
uv run python -m reporting.cli compliance \
  --framework pci-dss \
  --input policy-results.json \
  --output reports

# FFIEC compliance report
uv run python -m reporting.cli compliance \
  --framework ffiec \
  --input policy-results.json \
  --output reports
```

### Automated Weekly Reports

GitHub Actions workflow runs weekly to generate all compliance reports.

See `.github/workflows/scheduled-report.yml`

## Audit Evidence

### What Auditors Need

1. **Policy Definitions**: All Rego policies in `policies/`
2. **Test Evidence**: Test results from `make test-policies`
3. **CI/CD Integration**: GitHub Actions workflows showing enforcement
4. **Compliance Reports**: Weekly reports from `reports/`
5. **Violation History**: Git history of policy violations and remediation

### Generating Audit Package

```bash
# Run all tests
make test-policies > audit-evidence/test-results.txt

# Generate compliance reports
for framework in sox pci-dss ffiec; do
  uv run python -m reporting.cli compliance \
    --framework $framework \
    --input policy-results.json \
    --output audit-evidence/
done

# Package for auditors
tar -czf audit-package-$(date +%Y%m%d).tar.gz audit-evidence/
```

## References

- [SOX Act](https://www.sec.gov/spotlight/sarbanes-oxley.htm)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/)
- [FFIEC Cybersecurity Assessment Tool](https://www.ffiec.gov/cyberassessmenttool.htm)
- [AWS Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
