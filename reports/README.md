# Reports Directory

Generated policy validation and compliance reports are stored here.

## Report Types

- **policy-validation-*.html** - HTML dashboard showing policy violations
- **policy-validation-*.json** - Machine-readable policy results
- **compliance-*.html** - Compliance framework reports (SOX, PCI-DSS, FFIEC)
- **terraform-scan-*.json** - Terraform plan scanning results

## Generating Reports

```bash
# Generate policy validation report
make report

# Generate compliance report
python reporting/cli.py --framework sox --cloud aws

# Scan Terraform plan
./scripts/check-terraform.sh examples/aws/non-compliant/
```

All reports in this directory are gitignored and not committed to version control.
