# Compliance Reporting Guide

This guide explains how to generate compliance reports that map policy violations to banking industry frameworks.

## Overview

The compliance reporting tool automatically generates framework-specific reports that:
- Map policy violations to compliance controls
- Calculate compliance scores (0-100%)
- Provide pass/fail status for each control
- Include audit evidence and remediation guidance
- Generate HTML reports ready for compliance audits

## Supported Frameworks

### SOX (Sarbanes-Oxley Act)

**Purpose**: Financial reporting integrity and internal controls
**Industry**: Public companies, especially financial services
**Key Controls**:
- SOX-302: CEO/CFO Certification of Internal Controls
- SOX-404: Management Assessment of Internal Controls
- SOX-ITGC: IT General Controls

**Focus Areas**:
- Access controls and MFA enforcement
- Audit logging and data encryption
- Segregation of duties
- Change management for production systems

### PCI DSS (Payment Card Industry Data Security Standard)

**Purpose**: Payment card data security
**Industry**: Any organization handling payment cards
**Key Requirements**:
- REQ-1: Firewall configuration
- REQ-2: No vendor-supplied defaults
- REQ-3: Protect stored cardholder data
- REQ-7: Restrict access by need-to-know
- REQ-8: Identify and authenticate access
- REQ-10: Track and monitor access

**Focus Areas**:
- Network security (firewalls, security groups)
- Data encryption (at rest and in transit)
- Access control and authentication
- Logging and monitoring

### FFIEC (Federal Financial Institutions Examination Council)

**Purpose**: Cybersecurity maturity assessment
**Industry**: Banks, credit unions, financial institutions
**Key Domains**:
- D1: Cyber Risk Management and Oversight
- D2: Threat Intelligence and Collaboration
- D3: Cybersecurity Controls
- D4: External Dependency Management
- D5: Cyber Incident Management and Resilience

**Focus Areas**:
- Governance and risk management
- Preventative and detective controls
- Threat detection and response
- Business continuity and resilience

### GLBA (Gramm-Leach-Bliley Act)

**Purpose**: Financial privacy and consumer data protection
**Industry**: Financial services (banks, insurance, investment)
**Key Controls**:
- Safeguards Rule: Protect customer information
- Access Control: Limit access to authorized personnel
- Monitoring: Detect unauthorized access

**Focus Areas**:
- Data protection safeguards
- Access restrictions
- Security monitoring
- Employee training

## Generating Compliance Reports

### Quick Start (No Cloud Credentials Needed)

```bash
# Generate all compliance reports using test fixtures
make compliance-reports

# This will:
# 1. Evaluate policies against test fixtures
# 2. Extract violations to reports/violations.json
# 3. Generate HTML compliance reports

# Output files created:
#   reports/compliance/sox-compliance-report.html
#   reports/compliance/pci-compliance-report.html
#   reports/compliance/ffiec-compliance-report.html
#   reports/compliance/glba-compliance-report.html
```

### Generate Specific Framework Reports

```bash
# SOX compliance report (automatically evaluates fixtures first)
make compliance-sox

# PCI DSS report
make compliance-pci

# FFIEC report
make compliance-ffiec

# GLBA report
make compliance-glba

# Manual approach with custom violations file:
python reporting/compliance_report.py \
  --framework sox \
  --input reports/violations.json \
  --output reports/sox-compliance.html
```

### Using Real Policy Violations

```bash
# 1. Scan your Terraform code
cd your-terraform-project/
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# 2. Evaluate with OPA and extract violations
opa eval \
  --data /path/to/policy-as-code/policies/aws \
  --input tfplan.json \
  --format json \
  'data.aws' | python3 /path/to/policy-as-code/scripts/extract-violations.py > violations.json

# 3. Generate compliance report
python /path/to/policy-as-code/reporting/compliance_report.py \
  --framework sox \
  --input violations.json \
  --output sox-compliance.html

# Or use the all-in-one command (requires AWS credentials):
make scan-terraform
```

## Understanding Compliance Reports

### Report Sections

**1. Header**
- Framework name and description
- Report generation timestamp
- Overall compliance score

**2. Summary Dashboard**
- Overall compliance score (0-100%)
- Pass/Partial/Fail count breakdown
- Total controls evaluated

**3. Control Assessment**
Each control includes:
- Control ID and title
- Status badge (PASS/PARTIAL/FAIL)
- Compliance score (0-100%)
- Findings (policy violations)
- Evidence (passing checks)

### Compliance Scoring

**Pass (100%)**
- No policy violations found for the control
- All security requirements met
- Green status indicator

**Partial (65%)**
- 1-2 policy violations found
- Some requirements met
- Orange status indicator
- Requires attention but not critical

**Fail (25%)**
- 3+ policy violations found
- Critical security gaps
- Red status indicator
- Immediate remediation required

### Overall Score Calculation

```
Overall Score = Average of all control scores

Example:
  3 controls passing (100% each) = 300 points
  2 controls partial (65% each) = 130 points
  1 control failing (25%) = 25 points
  Total: 455 points / 6 controls = 75.8% overall
```

## Policy-to-Control Mappings

### SOX Mappings

| Control | Mapped Policies |
|---------|----------------|
| SOX-302 | aws.security.iam_mfa, aws.compliance.sox, azure.security.key_vault |
| SOX-404 | aws.security.s3_encryption, aws.compliance.sox, azure.security.storage_encryption |
| SOX-ITGC | aws.security.kms_encryption, aws.compliance.sox, aws.tagging.required_tags |

### PCI DSS Mappings

| Control | Mapped Policies |
|---------|----------------|
| PCI-REQ-1 | aws.security.ec2_security_groups, azure.security.network_security |
| PCI-REQ-3 | aws.security.s3_encryption, aws.security.kms_encryption, azure.security.storage_encryption |
| PCI-REQ-7 | aws.security.s3_public_access, aws.security.iam_mfa |
| PCI-REQ-8 | aws.security.iam_mfa |
| PCI-REQ-10 | aws.compliance.pci_dss, aws.compliance.sox |

### FFIEC Mappings

| Domain | Mapped Policies |
|--------|----------------|
| FFIEC-D1 | aws.tagging.required_tags, aws.compliance.ffiec |
| FFIEC-D3 | aws.security.s3_encryption, aws.security.kms_encryption, aws.security.ec2_security_groups, azure.security.* |
| FFIEC-D5 | aws.compliance.ffiec |

## Automated Compliance Reporting in CI/CD

### GitHub Actions Integration

Update `.github/workflows/scheduled-report.yml`:

```yaml
name: Weekly Compliance Reports

on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM UTC
  workflow_dispatch:

jobs:
  compliance-reports:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Generate compliance reports
        run: |
          make compliance-reports

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: reports/compliance/
          retention-days: 90
```

### Scheduled Reporting

```bash
# Add to cron for weekly reports
0 9 * * 1 cd /path/to/policy-as-code && make compliance-reports && \
  mail -s "Weekly Compliance Report" compliance@example.com < /dev/null
```

## For Auditors

### Preparing Audit Package

```bash
# 1. Run all policy tests
make test-policies > audit-evidence/test-results.txt

# 2. Generate all compliance reports
make compliance-reports

# 3. Copy reports to audit folder
cp -r reports/compliance/ audit-evidence/

# 4. Include policy definitions
cp -r policies/ audit-evidence/

# 5. Package for delivery
tar -czf compliance-audit-$(date +%Y%m%d).tar.gz audit-evidence/
```

### What Auditors Need

1. **Policy Definitions**: All Rego policy files (`policies/`)
2. **Test Evidence**: Test results showing policies work (`make test-policies`)
3. **Compliance Reports**: Framework-specific reports with scores
4. **CI/CD Integration**: Evidence of automated enforcement (GitHub Actions logs)
5. **Violation History**: Git history of violations and fixes

### Evidence of Continuous Compliance

- **Weekly Reports**: Automated compliance reports via GitHub Actions
- **Pull Request Checks**: Policies enforced on every code change
- **Audit Trail**: Git history of policy changes and approvals
- **Test Coverage**: Comprehensive tests for all policies

## Customizing Compliance Mappings

Edit `reporting/compliance_report.py` to customize policy-to-control mappings:

```python
FRAMEWORK_CONTROLS = {
    "sox": {
        "controls": {
            "SOX-302": {
                "policy_mappings": [
                    "aws.security.iam_mfa",
                    "aws.compliance.sox",
                    "your.custom.policy",  # Add your policy
                ],
            },
        },
    },
}
```

## Troubleshooting

### No violations found

```bash
# Check input file format
cat reports/policy-violations.json | jq .

# Should contain either:
# {"violations": [...]}
# or
# {"deny": [...]}
```

### Wrong compliance score

```bash
# Verify policy violations are mapped correctly
python reporting/compliance_report.py \
  --framework sox \
  --input reports/policy-violations.json \
  --output test-report.html

# Check console output for mapping details
```

### Report not generating

```bash
# Ensure Python dependencies installed
uv sync

# Check file permissions
chmod +x reporting/compliance_report.py

# Run with verbose output
python reporting/compliance_report.py --help
```

## Best Practices

1. **Run Weekly**: Generate reports weekly to track compliance trends
2. **Archive Reports**: Keep reports for audit trail (90+ days)
3. **Review Failures**: Prioritize fixing FAIL status controls
4. **Track Improvements**: Monitor score improvements over time
5. **Share with Teams**: Distribute reports to relevant stakeholders

## References

- [SOX Act](https://www.sec.gov/spotlight/sarbanes-oxley.htm)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [FFIEC Assessment Tool](https://www.ffiec.gov/cyberassessmenttool.htm)
- [GLBA Safeguards Rule](https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act)
- [AWS Security Best Practices](https://docs.aws.amazon.com/securityhub/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
