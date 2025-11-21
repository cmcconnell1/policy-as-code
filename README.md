# Multi-Cloud Policy-as-Code Framework

A comprehensive Policy-as-Code framework for enforcing security, compliance, and cost governance across AWS and Azure using **Open Policy Agent (OPA)** and **Rego**.

Designed for **financial services** and banking institutions, with built-in compliance controls for SOX, PCI-DSS, and FFIEC.

**Status**: Production-ready MVP with comprehensive policies and automated testing

---

## Table of Contents

- [Policy Engine](#policy-engine) - What is OPA and Rego?
- [Quick Start](#quick-start) - Get started in 5 minutes
- [Project Structure](#project-structure) - How the code is organized
- [Features](#features) - Security, tagging, cost, and compliance policies
- [Compliance Reporting](#compliance-reporting) - SOX, PCI-DSS, FFIEC, GLBA reports
- [Development Workflow](#development-workflow) - How to contribute
- [Real-World Usage](#real-world-usage) - Production integration examples

### Documentation
| Document | Description |
|----------|-------------|
| [Getting Started](GETTING_STARTED.md) | Quick start guide - no cloud credentials needed |
| [Compliance Reporting](docs/guides/compliance-reporting.md) | Generate SOX, PCI-DSS, FFIEC, GLBA reports |
| [Compliance Mapping](docs/reference/compliance-mapping.md) | Framework compliance mappings |
| [Quickstart](QUICKSTART.md) | Condensed quick reference |
| [Changelog](CHANGELOG.md) | Version history and changes |

---

## Policy Engine

This framework uses **Open Policy Agent (OPA)** with the **Rego** policy language.

### What is OPA?

[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) is an open-source, general-purpose policy engine that enables unified policy enforcement across the stack. It's a CNCF graduated project.

### Why OPA?

- **Free and Open Source**: No licensing costs (unlike HashiCorp Sentinel)
- **No Cloud Credentials Needed**: Can test policies offline with test fixtures
- **CI/CD Integration**: Can fail pipelines based on policy violations
- **Multi-Cloud**: Works with AWS, Azure, GCP, Kubernetes, and more
- **Declarative Language**: Rego policies are easy to read and maintain
- **Migration Path**: Can migrate to Sentinel later if needed (see [Migration Guide](#migrating-to-sentinel))

### What is Rego?

Rego is OPA's declarative policy language designed for writing policies over complex hierarchical data. All policies in this framework are written in Rego v1.

**Example Rego Policy:**
```rego
package aws.security.s3_encryption

import rego.v1

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not has_encryption(resource)

    msg := {
        "policy": "aws.security.s3_encryption",
        "resource": resource.address,
        "severity": "HIGH",
        "message": "S3 bucket must have encryption enabled"
    }
}
```

---

## Quick Start

### 1. Prerequisites

Required tools:
- **Python 3.9+**
- **uv** (Rust-based Python package manager)
- **OPA** (Open Policy Agent)
- **Terraform 1.5+** (optional - only needed for live infrastructure scanning)
- **Git**

### 2. Installation

```bash
# Clone repository
git clone <your-repo-url>
cd policy-as-code

# Run setup script
./scripts/setup.sh

# Or manually:
uv sync
chmod +x scripts/*.sh
```

### 3. Run Policy Tests

```bash
# Test all policies
make test-policies

# Test specific cloud
opa test policies/aws/ tests/aws/ -v
opa test policies/azure/ tests/azure/ -v
```

### 4. Evaluate Policies (No Credentials Needed)

```bash
# Evaluate test fixtures without AWS/Azure credentials
make evaluate-fixture

# This will:
# - Run OPA policies against test fixtures
# - Extract policy violations
# - Save results to reports/violations.json
```

### 5. Scan Live Terraform (Requires Cloud Credentials)

```bash
# Scan example Terraform code
make scan-terraform

# Or manually:
cd examples/aws/non-compliant
terraform init -backend=false
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval --data ../../../policies --input tfplan.json 'data.aws.deny'
```

### 6. Generate Compliance Reports

```bash
# Generate all compliance reports (SOX, PCI-DSS, FFIEC, GLBA)
make compliance-reports

# Or generate specific framework reports
make compliance-sox       # SOX compliance only
make compliance-pci       # PCI-DSS compliance only
make compliance-ffiec     # FFIEC compliance only
make compliance-glba      # GLBA compliance only
```

See the [Compliance Reporting](#compliance-reporting) section below for detailed information about compliance frameworks and report features.

---

## Project Structure

```
policy-as-code/
├── policies/                      # OPA/Rego policy definitions
│   ├── aws/
│   │   ├── security/              # Security baseline policies
│   │   ├── tagging/               # Tagging enforcement
│   │   ├── cost/                  # Cost governance
│   │   └── compliance/            # SOX, PCI-DSS, FFIEC
│   ├── azure/
│   │   ├── security/              # Azure security policies
│   │   ├── tagging/               # Azure tagging
│   │   ├── cost/                  # Azure cost controls
│   │   └── compliance/            # Compliance frameworks
│   └── common/lib/                # Shared Rego functions
│
├── tests/                         # Policy tests
│   ├── aws/                       # AWS policy tests
│   ├── azure/                     # Azure policy tests
│   └── test-fixtures/             # Mock Terraform plans
│
├── reporting/                     # Python reporting framework
│   ├── generators/                # Report generators (HTML, JSON, CSV)
│   ├── templates/                 # HTML templates
│   └── cli.py                     # CLI tool
│
├── examples/                      # Example Terraform code
│   ├── aws/
│   │   ├── compliant/             # Passes all policies
│   │   └── non-compliant/         # Fails policies (for testing)
│   └── azure/
│
├── scripts/                       # Automation scripts
│   ├── setup.sh                   # Environment setup
│   ├── validate-policies.sh       # Run policy tests
│   ├── check-terraform.sh         # Scan Terraform
│   └── extract-violations.py      # Extract violations from OPA output
│
├── .github/workflows/             # GitHub Actions
│   ├── policy-validation.yml      # Test policies on every commit
│   ├── terraform-scan.yml         # Scan Terraform in PRs
│   └── scheduled-report.yml       # Weekly compliance reports
│
├── docs/                          # Documentation
├── Makefile                       # Development tasks
├── pyproject.toml                 # Python dependencies
└── README.md                      # This file
```

---

## Features

### Security Baseline Policies

**AWS Security Controls:**
- S3 bucket encryption enforcement (AES256 or KMS)
- S3 public access blocking
- EC2 security group restrictions (no SSH/RDP from 0.0.0.0/0)
- IAM MFA enforcement for privileged access
- KMS encryption for data at rest (EBS, RDS, DynamoDB, etc.)

**Azure Security Controls:**
- Storage account encryption and HTTPS enforcement
- Network security group restrictions
- Key Vault security (soft delete, purge protection, network ACLs)
- TLS 1.2+ enforcement

### Tagging Enforcement

Required tags for all resources (financial services):
- `Environment` (dev, test, staging, prod)
- `CostCenter` (alphanumeric code)
- `Owner` (email or username)
- `Application` (application name)
- `DataClassification` (public, internal, confidential, restricted)

### Cost Governance

**AWS Cost Controls:**
- Approved EC2 instance types only (t3, m5, c5, r5 families)
- Prohibited expensive instances (GPU, extreme memory)
- Resource quantity limits
- RDS instance class restrictions

**Azure Cost Controls:**
- Approved VM sizes (B, D, E, F series)
- Prohibited expensive VMs (M, G, N, H series)
- VM size limits (max 16 vCPUs without approval)

### Compliance Framework Policies

**SOX (Sarbanes-Oxley):**
- Change management controls (no IAM users, use roles)
- Audit logging requirements (S3, CloudTrail)
- Segregation of duties (IAM policies)
- Database change tracking (RDS backups)

**PCI-DSS (Payment Card Industry):**
- Firewall configuration (security groups)
- No vendor defaults (non-default ports)
- Protect cardholder data (encryption)
- Access restrictions
- Audit logging (CloudTrail with validation)

**FFIEC (Federal Financial Institutions):**
- Security monitoring tags
- VPC flow logs
- GuardDuty for threat detection
- Multi-AZ for production databases
- Backup policy enforcement

---

## Policy Enforcement in CI/CD

### GitHub Actions Integration

Policies are automatically enforced on:
- **Every commit**: Run policy tests
- **Pull requests**: Scan Terraform changes
- **Weekly schedule**: Generate compliance reports

### How It Works

1. Developer writes Terraform code
2. Opens pull request
3. GitHub Actions workflow runs:
   - `terraform plan` generates plan JSON
   - OPA evaluates plan against policies
   - Pipeline **FAILS** if violations found
4. Developer fixes violations
5. Pipeline passes, PR approved

### Example Workflow Output

```
[OK] Testing AWS policies...
[OK] Testing Azure policies...
[WARNING] Found policy violations:
  - aws.security.s3_encryption: S3 bucket 'my-bucket' not encrypted
  - aws.tagging.required_tags: Missing required tags: CostCenter, Owner
[FAILED] Policy validation failed with 2 violation(s)
```

---

## Writing Custom Policies

### Basic Policy Structure

```rego
package aws.security.my_policy

import rego.v1

# METADATA
# title: My Custom Policy
# description: Description of what this policy enforces
# custom:
#   severity: HIGH
#   frameworks:
#     - PCI-DSS 3.4

# Deny rule
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"

    # Your policy logic here
    not resource.change.after.versioning_enabled

    msg := {
        "policy": "aws.security.my_policy",
        "resource": resource.address,
        "severity": "HIGH",
        "message": "S3 bucket versioning must be enabled",
        "remediation": "Add versioning_configuration block"
    }
}
```

### Testing Your Policy

```rego
package aws.security.my_policy

import rego.v1

test_bucket_with_versioning_passes if {
    input := {"resource_changes": [{
        "type": "aws_s3_bucket",
        "change": {"after": {"versioning_enabled": true}}
    }]}

    count(deny) == 0
}

test_bucket_without_versioning_fails if {
    input := {"resource_changes": [{
        "type": "aws_s3_bucket",
        "change": {"after": {"versioning_enabled": false}}
    }]}

    count(deny) == 1
}
```

Run tests:
```bash
opa test policies/aws/security/ tests/aws/security/ -v
```

---

## Compliance Reporting

Automated compliance reports for banking industry frameworks:

| Framework | Focus | Key Controls |
|-----------|-------|--------------|
| **SOX** | Financial reporting integrity | SOX-302, SOX-404, SOX-ITGC |
| **FFIEC** | Cybersecurity maturity | D1-D5 domains |
| **GLBA** | Consumer data protection | Safeguards, Access Control, Monitoring |
| **PCI DSS** | Payment card security | Requirements 1, 2, 3, 7, 8, 10 |

### Generate Compliance Reports

```bash
# Quick start - generate all compliance reports (no cloud credentials needed)
make compliance-reports

# This will:
# 1. Evaluate policies against test fixtures
# 2. Extract violations to reports/violations.json
# 3. Generate HTML compliance reports for SOX, PCI-DSS, FFIEC, GLBA

# Or generate specific framework reports
make compliance-sox       # SOX compliance only
make compliance-pci       # PCI-DSS compliance only
make compliance-ffiec     # FFIEC compliance only
make compliance-glba      # GLBA compliance only

# Manual approach with custom violations file:
python reporting/compliance_report.py \
  --framework sox \
  --input reports/violations.json \
  --output reports/sox-compliance.html

# Generate all frameworks at once
python reporting/compliance_report.py \
  --framework all \
  --input reports/violations.json \
  --output-dir reports/compliance/
```

### Compliance Report Features

- **Overall Compliance Score**: 0-100% score for each framework
- **Control-by-Control Assessment**: Pass/Partial/Fail status for each control
- **Policy Violation Mapping**: Links violations to specific compliance requirements
- **Audit Evidence**: Documentation ready for compliance audits
- **Remediation Guidance**: Clear recommendations for fixing violations
- **HTML Format**: Professional reports with charts and styling

For detailed information on compliance frameworks and advanced usage, see:
- [Compliance Reporting Guide](docs/guides/compliance-reporting.md)
- [Compliance Summary](COMPLIANCE_SUMMARY.md)

---

## Development Workflow

### Making Changes

1. Create feature branch: `git checkout -b feature/new-policy`
2. Write policy in `policies/`
3. Write tests in `tests/`
4. Run tests: `make test-policies`
5. Run linter: `make lint`
6. Commit and push
7. Open pull request
8. Automated checks run
9. Merge after approval

### Available Make Targets

```bash
make help                 # Show all available targets
make install              # Install Python dependencies

# Testing
make test                 # Run all tests
make test-policies        # Test OPA policies only

# Code Quality
make lint                 # Lint Python code
make format               # Format Python code

# Policy Evaluation
make evaluate-fixture     # Evaluate test fixtures (no credentials needed)
make scan-terraform       # Scan live Terraform (requires AWS credentials)
make check-terraform      # Validate Terraform syntax

# Compliance Reports
make compliance-reports   # Generate all framework reports
make compliance-sox       # Generate SOX report
make compliance-pci       # Generate PCI-DSS report
make compliance-ffiec     # Generate FFIEC report
make compliance-glba      # Generate GLBA report

# Utilities
make clean                # Clean generated files
make validate-all         # Run all validations
```

Run `make help` to see all available targets with descriptions.

---

## Real-World Usage

### Scan Live Terraform

```bash
# In your Terraform directory
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate policies
opa eval \
  --data /path/to/policy-as-code/policies \
  --input tfplan.json \
  --format pretty \
  'data.aws.deny'
```

### Integrate with Terraform Cloud

Use OPA with Terraform Cloud Sentinel alternative:

```hcl
# In your Terraform workspace settings
resource "tfe_policy_set" "opa_policies" {
  name         = "opa-security-policies"
  description  = "OPA-based security policies"
  organization = "your-org"
  kind         = "opa"

  policy_ids = [
    tfe_policy.s3_encryption.id,
    tfe_policy.tagging.id,
  ]
}
```

### Use in Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: terraform-opa-check
        name: Terraform OPA Policy Check
        entry: ./scripts/check-terraform.sh
        language: system
        files: \.tf$
```

---

## Migrating to Sentinel

When you get access to Terraform Cloud/Enterprise, migration path:

1. Rego policies translate directly to Sentinel concepts
2. Both use similar policy structure (rules, conditions, messages)
3. Main difference: Sentinel uses HCL-like syntax vs Rego
4. Can run both OPA and Sentinel in parallel during migration

Example comparison:

**Rego:**
```rego
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not resource.change.after.encrypted
}
```

**Sentinel:**
```hcl
import "tfplan/v2" as tfplan

deny_unencrypted_s3 = rule {
    all tfplan.resource_changes as _, rc {
        rc.type is "aws_s3_bucket" implies
            rc.change.after.encrypted is true
    }
}
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new policies
- Writing tests
- Documentation standards
- Code review process

---

## Support & Documentation

- **Getting Started**: See [GETTING_STARTED.md](GETTING_STARTED.md) for step-by-step setup
- **Compliance Guide**: See [docs/guides/compliance-reporting.md](docs/guides/compliance-reporting.md)
- **Quickstart**: See [QUICKSTART.md](QUICKSTART.md) for quick reference
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for version history

---

## Acknowledgments

Built with:
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [Terraform](https://www.terraform.io/)
- AWS & Azure Security Best Practices
- CIS Cloud Foundations Benchmarks
- NIST Cybersecurity Framework

---

**Last Updated**: 2025-11-20 | **Version**: 1.0.0
