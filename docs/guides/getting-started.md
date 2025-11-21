# Getting Started with Policy-as-Code

This guide will help you get the policy-as-code framework up and running.

## Prerequisites

### Required Tools

1. **Python 3.11 or higher**
   ```bash
   python3 --version
   ```

2. **uv (Python package manager)**
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **OPA (Open Policy Agent)**
   ```bash
   # macOS
   brew install opa

   # Linux
   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
   chmod +x opa
   sudo mv opa /usr/local/bin/

   # Verify
   opa version
   ```

4. **Terraform 1.5+**
   ```bash
   # macOS
   brew install terraform

   # Linux
   # Download from https://www.terraform.io/downloads
   ```

5. **Git**
   ```bash
   git --version
   ```

## Installation

### 1. Clone Repository

```bash
git clone <your-repo-url>
cd policy-as-code
```

### 2. Run Setup Script

```bash
./scripts/setup.sh
```

This will:
- Check for required tools
- Install Python dependencies via uv
- Make scripts executable
- Create reports directory

### 3. Verify Installation

```bash
# Test policies
make test-policies

# Should see:
# [OK] Testing AWS policies...
# [OK] Testing Azure policies...
# [OK] All policy tests passed!
```

## Your First Policy Scan

### 1. Review Example Code

```bash
# Compliant example (passes all policies)
cat examples/aws/compliant/main.tf

# Non-compliant example (fails policies)
cat examples/aws/non-compliant/main.tf
```

### 2. Scan the Non-Compliant Example

```bash
make scan-terraform
```

You should see violations like:
```
[WARNING] Found policy violations:
  - S3 bucket not encrypted
  - Missing required tags
  - Security group allows SSH from 0.0.0.0/0
```

### 3. Generate a Report

```bash
make report
```

Open `reports/policy-report-*.html` in your browser to see the interactive dashboard.

## Understanding the Structure

```
policy-as-code/
├── policies/          # Policy definitions
│   ├── aws/
│   │   ├── security/  # Security policies
│   │   ├── tagging/   # Tagging policies
│   │   ├── cost/      # Cost policies
│   │   └── compliance/# Compliance (SOX, PCI, FFIEC)
│   └── azure/         # Azure policies
│
├── tests/             # Policy tests
│   ├── aws/           # Test AWS policies
│   └── azure/         # Test Azure policies
│
├── examples/          # Example Terraform
│   ├── aws/compliant/     # Passes policies
│   └── aws/non-compliant/ # Fails policies
│
└── reporting/         # Report generation
```

## Next Steps

1. **Read the Policies**: Browse `policies/aws/security/` to understand what's enforced
2. **Review Tests**: Look at `tests/aws/security/` to see how policies are tested
3. **Write Custom Policy**: See [Writing Policies](writing-policies.md)
4. **Integrate CI/CD**: See [CI/CD Integration](cicd-integration.md)

## Common Commands

```bash
# Test all policies
make test-policies

# Test specific cloud
opa test policies/aws/ tests/aws/ -v

# Scan Terraform code
make scan-terraform

# Generate reports
make report

# Lint Python code
make lint

# See all commands
make help
```

## Troubleshooting

### OPA not found

```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
```

### uv not found

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Python version too old

```bash
# Install Python 3.11+
# macOS: brew install python@3.11
# Ubuntu: sudo apt install python3.11

# Verify
python3 --version
```

## Getting Help

- Check [documentation](../reference/)
- Review [example code](../../examples/)
- Open an [issue](https://github.com/your-org/policy-as-code/issues)
