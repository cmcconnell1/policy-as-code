# Quick Start Guide

Get the policy-as-code framework running in 5 minutes.

## Step 1: Install Required Tools

```bash
# Check Python version (need 3.11+)
python3 --version

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install OPA (macOS)
brew install opa

# Or install OPA (Linux)
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Install Terraform (if not already installed)
# macOS: brew install terraform
# Linux: https://www.terraform.io/downloads
```

## Step 2: Setup Project

```bash
# Run automated setup
./scripts/setup.sh
```

## Step 3: Test Everything Works

```bash
# Test policies (should pass)
make test-policies

# Scan example Terraform (should find violations)
make scan-terraform

# Generate report
make report
```

## Step 4: View Your First Report

```bash
# Open the HTML report in your browser
open reports/policy-report-*.html

# Or on Linux:
xdg-open reports/policy-report-*.html
```

You should see a dashboard showing:
- Total violations found
- Violations by severity (Critical, High, Medium, Low)
- Detailed violation information with remediation steps

## Step 5: Generate Compliance Reports

```bash
# Generate all compliance framework reports
make compliance-reports

# View SOX compliance report
open reports/compliance/sox-compliance-report.html

# View PCI DSS compliance report
open reports/compliance/pci-compliance-report.html
```

Compliance reports show:
- Overall compliance score (0-100%)
- Pass/Partial/Fail status for each control
- Policy violations mapped to compliance requirements
- Audit-ready documentation

## What's Next?

### Scan Your Own Terraform

```bash
# In your Terraform directory
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Scan with policies
opa eval \
  --data /path/to/policy-as-code/policies \
  --input tfplan.json \
  --format pretty \
  'data.aws.deny'
```

### Integrate with CI/CD

1. Copy `.github/workflows/` to your repo
2. Push to GitHub
3. Policies automatically run on every PR

### Customize Policies

1. Browse `policies/aws/` and `policies/azure/`
2. Modify required tags in `policies/aws/tagging/required-tags.rego`
3. Adjust cost limits in `policies/aws/cost/resource-limits.rego`
4. Test changes: `make test-policies`

## Available Commands

```bash
make help              # Show all commands
make test-policies     # Test OPA policies
make scan-terraform    # Scan example Terraform
make report            # Generate sample report
make lint              # Lint Python code
make clean             # Clean generated files
```

## Troubleshooting

### "opa: command not found"

```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
opa version
```

### "uv: command not found"

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Or restart your shell
```

### Tests fail with "permission denied"

```bash
# Make scripts executable
chmod +x scripts/*.sh
```

## Understanding the Output

### Policy Test Output

```
[OK] Testing AWS policies...
PASS: 15/15
[OK] All policy tests passed!
```

### Terraform Scan Output

```
[WARNING] Found policy violations:
  - aws.security.s3_encryption: S3 bucket not encrypted
  - aws.tagging.required_tags: Missing tags: CostCenter, Owner
[FAILED] Policy validation failed with 2 violation(s)
```

### Report Output

HTML report shows:
- Summary cards with violation counts
- Violations grouped by severity
- Each violation includes:
  - Policy name
  - Resource affected
  - Severity level
  - Problem description
  - How to fix it
  - Compliance framework (SOX, PCI-DSS, FFIEC)

## Real-World Usage

### Pre-Commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
make test-policies || exit 1
```

### GitHub Actions

The framework includes ready-to-use workflows:
- `policy-validation.yml` - Run on every commit
- `terraform-scan.yml` - Scan Terraform in PRs
- `scheduled-report.yml` - Weekly compliance reports

### Terraform Cloud/Enterprise

When you get access to Sentinel:
1. Policies are similar (same concepts)
2. Can run OPA and Sentinel in parallel
3. Migration guide in README.md

## Need Help?

- **Documentation**: Check `docs/` folder
- **Examples**: Look at `examples/aws/compliant/`
- **Tests**: Review `tests/aws/` for examples
- **Issues**: Open a GitHub issue

## What You Built

You now have:

1. **15+ Security Policies** for AWS and Azure
2. **Compliance Controls** for SOX, PCI-DSS, FFIEC
3. **Automated Testing** with OPA
4. **CI/CD Integration** with GitHub Actions
5. **Reporting Dashboard** with HTML/JSON/CSV output
6. **Cost Governance** to prevent expensive resources

## Next Steps

1. Read the full [README.md](README.md)
2. Review [Getting Started Guide](docs/guides/getting-started.md)
3. Explore [Compliance Mapping](docs/reference/compliance-mapping.md)
4. Customize policies for your organization
5. Integrate with your CI/CD pipeline

---

**Time to Value**: 5 minutes to setup, 30 minutes to master
