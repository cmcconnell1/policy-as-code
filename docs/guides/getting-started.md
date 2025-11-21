# Getting Started - Step by Step

This guide will get you running the policy-as-code framework in 5 minutes **without needing cloud credentials**.

## Prerequisites Check

Required tools:
- Python 3.9+
- uv (package manager) - Install from https://github.com/astral-sh/uv
- OPA (policy engine) - Install from https://www.openpolicyagent.org/

## Step 1: Install Python Dependencies

```bash
# Clone and enter the project directory
cd policy-as-code

# Install dependencies
uv sync
```

## Step 2: Test the Policies

```bash
# Test all policies (no cloud credentials needed)
make test-policies
```

Expected output:
```
[OK] Testing AWS policies...
PASS: tests passed
[OK] Testing Azure policies...
PASS: tests passed
[OK] All policy tests passed
```

## Step 3: Evaluate Test Fixtures

```bash
# Evaluate policies against test fixtures (no cloud credentials needed)
make evaluate-fixture
```

This will:
- Run OPA policies against test fixtures
- Extract policy violations
- Save results to `reports/violations.json`

Expected output:
```
[OK] Evaluating test fixture...
[OK] Found 5 violations
[OK] Violations saved to reports/violations.json
```

## Step 4: Generate Compliance Reports

```bash
# Generate all compliance framework reports
make compliance-reports
```

This will:
1. Automatically evaluate test fixtures (if not done already)
2. Generate HTML compliance reports

This creates:
- `reports/compliance/sox-compliance-report.html`
- `reports/compliance/pci-compliance-report.html`
- `reports/compliance/ffiec-compliance-report.html`
- `reports/compliance/glba-compliance-report.html`

## Step 5: View the Reports

```bash
# Open HTML reports
open reports/policy-report-*.html
open reports/compliance/sox-compliance-report.html

# Or on Linux:
xdg-open reports/policy-report-*.html
```

## Understanding What You Just Did

1. **Tested Policies**: Verified all OPA/Rego policies work correctly
2. **Evaluated Fixtures**: Ran policies against test data to find violations
3. **Generated Compliance Reports**: Created SOX, PCI-DSS, FFIEC, GLBA reports
4. **No Cloud Needed**: Everything works with test fixtures (no AWS/Azure credentials)

## Testing with Real Terraform (Optional)

If you want to test with real Terraform code, you have two options:

### Option A: Test Without Cloud Credentials (Recommended)

Use the built-in evaluation workflow:

```bash
# Evaluate test fixtures
make evaluate-fixture

# View the extracted violations
cat reports/violations.json

# Or evaluate manually with OPA
opa eval \
  --data policies/aws/ \
  --input tests/test-fixtures/aws/s3-non-compliant.json \
  --format pretty \
  'data.aws'
```

### Option B: Test With AWS Credentials (If You Have Them)

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"

# Or use AWS CLI
aws configure

# Now you can run the full workflow
cd examples/aws/non-compliant
terraform init -backend=false
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Scan with OPA
opa eval \
  --data ../../../policies \
  --input tfplan.json \
  --format pretty \
  'data.aws.deny'
```

## Common Commands

```bash
# Show all available commands
make help

# Test policies
make test-policies

# Evaluate test fixtures (no credentials)
make evaluate-fixture

# Generate compliance reports
make compliance-reports

# Generate specific compliance report
make compliance-sox
make compliance-pci
make compliance-ffiec
make compliance-glba

# Clean generated files
make clean

# Run all validations
make validate-all
```

## Troubleshooting

### "terraform plan" fails with credential error

This is **expected** if you haven't configured AWS credentials. Use the test fixtures instead:

```bash
# Evaluate test fixtures (no credentials needed)
make evaluate-fixture

# Generate compliance reports from fixtures
make compliance-reports
```

### "uv sync" fails

```bash
# Make sure you're in the project root directory
cd policy-as-code

# Try installing with pip as fallback
pip3 install jinja2 click pyyaml python-dateutil
```

### "opa test" fails

```bash
# Check OPA is installed
which opa
opa version

# Run tests manually from project root
opa test policies/aws/ tests/aws/ -v
```

### Reports not generating

```bash
# Check Python is working
python3 -c "import jinja2; print('OK')"

# Try running directly
uv run python -m reporting.cli generate \
  --input tests/test-fixtures/aws/s3-non-compliant.json \
  --output reports \
  --format html
```

## What's in the Test Fixtures?

The `tests/test-fixtures/` directory contains example Terraform plan JSON files that demonstrate policy violations. These work **without any cloud credentials**.

```
tests/test-fixtures/aws/
├── s3-compliant.json       # Passes all policies
└── s3-non-compliant.json   # Violates several policies
```

These are used for:
- Testing the reporting system
- Demonstrating compliance reports
- CI/CD pipeline testing

## Next Steps

Now that everything works:

1. **Explore Policies**: Browse `policies/aws/` and `policies/azure/`
2. **Read Compliance Guide**: See `docs/guides/compliance-reporting.md`
3. **Customize**: Modify policies for your organization
4. **Integrate CI/CD**: Use `.github/workflows/` examples

## Quick Reference

| Task | Command |
|------|---------|
| Test all policies | `make test-policies` |
| Evaluate test fixtures | `make evaluate-fixture` |
| Generate compliance reports | `make compliance-reports` |
| Generate SOX report | `make compliance-sox` |
| Generate PCI-DSS report | `make compliance-pci` |
| Generate FFIEC report | `make compliance-ffiec` |
| Generate GLBA report | `make compliance-glba` |
| Clean reports | `make clean` |
| Show all commands | `make help` |

## Need Help?

1. Check [quickstart.md](quickstart.md) for condensed guide
2. Read `README.md` for full documentation
3. See `docs/guides/` for detailed guides
4. Open GitHub issue if you find bugs
