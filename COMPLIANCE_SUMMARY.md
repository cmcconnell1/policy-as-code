# Compliance Reporting Summary

Quick reference for compliance reporting capabilities in the policy-as-code framework.

## Supported Frameworks

| Framework | Description | Controls |
|-----------|-------------|----------|
| **SOX** | Sarbanes-Oxley Act - Financial reporting integrity | SOX-302, SOX-404, SOX-ITGC |
| **PCI DSS** | Payment Card Industry - Card data security | Requirements 1, 2, 3, 7, 8, 10 |
| **FFIEC** | Federal Financial Institutions - Cybersecurity maturity | Domains D1-D5 |
| **GLBA** | Gramm-Leach-Bliley Act - Financial privacy | Safeguards, Access, Monitoring |

## Quick Commands

```bash
# Generate all compliance reports (no cloud credentials needed)
make compliance-reports

# Generate specific framework report
make compliance-sox       # SOX report
make compliance-pci       # PCI DSS report
make compliance-ffiec     # FFIEC report
make compliance-glba      # GLBA report

# Manual workflow:
# 1. Evaluate policies and extract violations
make evaluate-fixture

# 2. Generate compliance report
python reporting/compliance_report.py \
  --framework sox \
  --input reports/violations.json \
  --output reports/sox-compliance.html
```

## Report Features

- **Overall Compliance Score**: 0-100% score per framework
- **Control Assessment**: Pass/Partial/Fail for each control
- **Policy Mappings**: Links violations to compliance requirements
- **Audit Evidence**: Ready for compliance audits
- **HTML Format**: Professional reports with charts and styling

## Scoring System

| Status | Score | Violations | Color |
|--------|-------|------------|-------|
| PASS | 100% | 0 violations | Green |
| PARTIAL | 65% | 1-2 violations | Orange |
| FAIL | 25% | 3+ violations | Red |

## Policy-to-Framework Mappings

### SOX Controls Map To:
- IAM MFA enforcement policies
- S3/Storage encryption policies
- KMS encryption policies
- Tagging and audit logging policies
- Change management policies

### PCI DSS Controls Map To:
- Network security groups policies
- Encryption policies (S3, KMS, storage)
- Public access blocking policies
- IAM authentication policies
- Audit logging policies

### FFIEC Controls Map To:
- All security baseline policies
- Tagging and governance policies
- Network and access control policies
- Encryption and data protection policies
- Monitoring and logging policies

### GLBA Controls Map To:
- Data encryption policies
- Access control policies
- Key vault security policies
- Monitoring and logging policies

## Report Outputs

```
reports/
├── compliance/
│   ├── sox-compliance-report.html
│   ├── pci-compliance-report.html
│   ├── ffiec-compliance-report.html
│   └── glba-compliance-report.html
└── ...
```

## CI/CD Integration

Compliance reports can be automatically generated:
- **Weekly**: Scheduled GitHub Actions workflow
- **On-Demand**: Manual workflow trigger
- **Per-PR**: Optional PR compliance check

See `.github/workflows/scheduled-report.yml` for automation.

## For Auditors

Compliance reports include:
1. Overall compliance score
2. Control-by-control assessment
3. Specific policy violations
4. Evidence of passing controls
5. Remediation recommendations
6. Timestamp and audit trail

## Example Workflow

### Quick Start (No Cloud Credentials)

```bash
# 1. Generate compliance reports using test fixtures
make compliance-reports

# 2. Review reports
open reports/compliance/*.html

# 3. Understand violations from reports/violations.json
```

### Production Workflow (With Cloud Credentials)

```bash
# 1. Scan Terraform infrastructure
cd your-terraform-project/
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# 2. Evaluate with OPA and extract violations
opa eval \
  --data /path/to/policy-as-code/policies/aws \
  --input tfplan.json \
  --format json \
  'data.aws' | python3 /path/to/policy-as-code/scripts/extract-violations.py > violations.json

# 3. Generate compliance reports
python /path/to/policy-as-code/reporting/compliance_report.py \
  --framework all \
  --input violations.json \
  --output-dir reports/compliance/

# 4. Review reports
open reports/compliance/*.html

# 5. Fix violations and re-scan
# 6. Submit reports for audit
```

## Documentation

- **Full Guide**: [docs/guides/compliance-reporting.md](docs/guides/compliance-reporting.md)
- **Compliance Mapping**: [docs/reference/compliance-mapping.md](docs/reference/compliance-mapping.md)
- **README**: [README.md](README.md#compliance-reporting)

## Key Benefits

1. **Automated**: Generate reports in seconds from policy violations
2. **Comprehensive**: Covers 4 major banking industry frameworks
3. **Audit-Ready**: Professional HTML reports for compliance audits
4. **Actionable**: Clear mapping from violations to remediation
5. **Integrated**: Works seamlessly with OPA policy enforcement
6. **CI/CD**: Can be automated in GitHub Actions or other CI systems

## Support

For questions or issues with compliance reporting:
1. Review [docs/guides/compliance-reporting.md](docs/guides/compliance-reporting.md)
2. Check policy-to-control mappings in `reporting/compliance_report.py`
3. Open GitHub issue with framework name and details
