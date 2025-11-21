# Policy Enforcement Strategies

How to integrate OPA/Rego with existing repositories and prevent developers from bypassing policies.

## The Challenge

Having policies is useless if developers can:
- Skip running policy checks
- Push directly to production branches
- Deploy infrastructure without approval
- Use local Terraform without policy validation

This guide explains enforcement mechanisms for financial services and regulated industries.

---

## Integration Points

### 1. GitHub Branch Protection (Primary Defense)

**Required Status Checks** - Force policies to pass before merging:

```yaml
# Repository Settings > Branches > Branch protection rules
Branch: main
  [x] Require status checks to pass before merging
  [x] Require branches to be up to date before merging
  Required checks:
    - policy-validation
    - terraform-scan
    - compliance-check

  [x] Require pull request reviews before merging
  [x] Dismiss stale pull request approvals when new commits are pushed
  [x] Require review from Code Owners

  [x] Do not allow bypassing the above settings
  [x] Restrict who can push to matching branches
    - Only: security-team, compliance-team
```

**Key Settings**:
- **"Do not allow bypassing"** - Prevents admins from bypassing (critical!)
- **Required checks** - GitHub won't allow merge until OPA checks pass
- **Code Owners** - Security/compliance team must approve infrastructure changes

### 2. GitHub Actions (Automated Enforcement)

```yaml
# .github/workflows/policy-enforcement.yml
name: Policy Enforcement

on:
  pull_request:
    branches: [main, production, staging]
    paths:
      - '**.tf'
      - '**.tfvars'
      - 'infrastructure/**'
  push:
    branches: [main, production, staging]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OPA
        run: |
          curl -L -o opa https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/

      - name: Validate Terraform
        run: |
          terraform init -backend=false
          terraform validate

      - name: Generate Terraform Plan
        run: |
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Run Policy Checks
        id: policy-check
        run: |
          opa eval \
            --data https://github.com/your-org/policy-as-code/archive/main.zip \
            --input tfplan.json \
            --format pretty \
            'data.aws.deny' > violations.txt

          if [ -s violations.txt ]; then
            echo "POLICY VIOLATIONS FOUND:"
            cat violations.txt
            exit 1
          fi

      - name: Post Violations to PR
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const violations = fs.readFileSync('violations.txt', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Policy Violations Found\n\n\`\`\`\n${violations}\n\`\`\`\n\n**Action Required**: Fix violations before merge.`
            });

      - name: Fail if violations found
        if: failure()
        run: exit 1

  compliance-check:
    runs-on: ubuntu-latest
    needs: policy-check
    steps:
      - name: Generate Compliance Report
        run: |
          # Generate SOX/PCI/FFIEC/GLBA reports
          make compliance-reports

      - name: Upload Compliance Reports
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: reports/compliance/
          retention-days: 90
```

**Why This Works**:
- Runs automatically on every PR
- Cannot be skipped (required status check)
- Posts violations directly to PR for visibility
- Fails the build if violations found
- Generates audit trail (compliance reports)

### 3. CODEOWNERS File (Required Approvals)

```
# .github/CODEOWNERS
# Terraform files require security/compliance approval

# All infrastructure requires security team review
*.tf @your-org/security-team @your-org/compliance-team
*.tfvars @your-org/security-team @your-org/compliance-team
infrastructure/** @your-org/security-team @your-org/compliance-team

# Production environments require additional approval
infrastructure/production/** @your-org/security-team @your-org/compliance-team @your-org/infrastructure-leads

# Policy changes require compliance team approval
policies/** @your-org/compliance-team @your-org/legal-team

# Any changes to IAM/security groups require explicit approval
**/iam.tf @your-org/security-team @your-org/ciso
**/security-groups.tf @your-org/security-team @your-org/ciso
```

**Why This Works**:
- GitHub enforces required approvals from code owners
- Security/compliance team must review every infrastructure change
- Cannot merge without their approval
- Creates accountability and audit trail

### 4. Centralized Policy Repository

**Repository Structure**:
```
your-org/
├── policy-as-code/              # Central policy repository
│   ├── policies/
│   ├── tests/
│   └── .github/workflows/
│
├── app-team-1-infra/            # Application team repos
│   ├── terraform/
│   └── .github/workflows/
│       └── policy-check.yml     # References central policies
│
├── app-team-2-infra/
│   ├── terraform/
│   └── .github/workflows/
│       └── policy-check.yml     # References central policies
```

**Central Policy Repository Benefits**:
- Single source of truth for all policies
- Security team controls policy changes
- Application teams cannot modify policies
- Policies versioned and auditable

**Application Team Workflow**:
```yaml
# app-team-1-infra/.github/workflows/policy-check.yml
- name: Download Central Policies
  run: |
    # Download policies from central repository (specific version)
    curl -L -o policies.zip \
      https://github.com/your-org/policy-as-code/archive/v1.0.0.zip
    unzip policies.zip

- name: Run Policy Checks
  run: |
    opa eval \
      --data policy-as-code-1.0.0/policies \
      --input tfplan.json \
      'data.aws.deny'
```

**Enforcement Mechanism**:
- Application teams MUST reference central policy repo
- Cannot use custom policies
- Policy version pinned (security team controls updates)
- GitHub branch protection ensures workflow runs

---

## Preventing Workarounds

### Workaround 1: "I'll just push directly to main"

**Prevention**:
```yaml
# Branch Protection Rules
[x] Do not allow bypassing the above settings
[x] Restrict who can push to matching branches
    - Only: security-team (emergency use only)
```

- Developers cannot push directly to protected branches
- Even admins cannot bypass (unless explicitly allowed)
- All changes must go through PR + policy checks

### Workaround 2: "I'll run Terraform locally without policies"

**Prevention**:

**A. AWS/Azure Account-Level Controls**:
```hcl
# Service Control Policy (AWS Organizations)
# Deny any infrastructure changes NOT tagged with ApprovalTicket
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "s3:CreateBucket",
        "rds:CreateDBInstance"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:RequestTag/ApprovalTicket": "JIRA-*"
        }
      }
    }
  ]
}
```

**B. Terraform Cloud/Enterprise (Recommended)**:
- Developers don't have AWS credentials
- All Terraform runs happen in Terraform Cloud
- Terraform Cloud runs OPA policies (cannot be bypassed)
- Sentinel policies enforce compliance (paid feature)

**C. SSO/Temporary Credentials**:
```bash
# Developers use SSO, not long-lived credentials
aws sso login --profile dev

# Credentials expire after 8 hours
# Cannot be used for production deployments
```

**D. Least Privilege IAM**:
- Developers have read-only production access
- Write access only in dev/test environments
- Production changes require approved service account
- Service account credentials only available to CI/CD

### Workaround 3: "I'll modify the GitHub Actions workflow"

**Prevention**:

**A. CODEOWNERS for Workflows**:
```
# .github/CODEOWNERS
.github/workflows/** @your-org/security-team @your-org/devops-leads
```

- Workflow changes require security team approval
- Cannot disable policy checks without approval

**B. Workflow File Protection**:
```yaml
# .github/workflows/policy-enforcement.yml
# This workflow is REQUIRED and cannot be disabled
name: Policy Enforcement (REQUIRED)

on:
  pull_request:
  push:
  workflow_dispatch:  # Allow manual runs only

# Prevent workflow from being skipped
concurrency:
  group: policy-enforcement-${{ github.ref }}
  cancel-in-progress: false
```

**C. GitHub Organization Settings**:
```
Settings > Actions > General
[x] Allow actions created by GitHub
[x] Allow actions by Marketplace verified creators
[x] Allow specified actions and reusable workflows
    - actions/checkout@v4
    - hashicorp/setup-terraform@v3

[ ] Allow all actions and reusable workflows (DISABLED)
```

### Workaround 4: "I'll use a different branch name"

**Prevention**:
```yaml
# Apply branch protection to pattern
Branch protection rule: **
  [x] Require status checks to pass before merging

# Or protect specific patterns
Branch protection rules:
  - main
  - master
  - production
  - staging
  - release/*
  - hotfix/*
```

### Workaround 5: "I'll deploy with a different tool (not Terraform)"

**Prevention**:

**A. CloudTrail Monitoring**:
```python
# Lambda function to detect non-Terraform infrastructure changes
import boto3
import json

def lambda_handler(event, context):
    # Check if resource created without ApprovalTicket tag
    detail = event['detail']

    if detail['eventName'] in ['RunInstances', 'CreateBucket', 'CreateDBInstance']:
        resource_tags = detail.get('requestParameters', {}).get('tagSpecificationSet', [])

        has_approval = any(
            tag['key'] == 'ApprovalTicket'
            for spec in resource_tags
            for tag in spec.get('tags', [])
        )

        if not has_approval:
            # Alert security team
            sns.publish(
                TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
                Subject='ALERT: Unauthorized Infrastructure Change',
                Message=f'Resource created without approval: {json.dumps(detail)}'
            )

            # Optionally: Auto-remediate (delete resource)
            # ec2.terminate_instances(InstanceIds=[instance_id])
```

**B. AWS Config Rules**:
```yaml
# AWS Config rule to enforce tagging
RequiredTags:
  Type: AWS::Config::ConfigRule
  Properties:
    ConfigRuleName: required-tags
    Source:
      Owner: AWS
      SourceIdentifier: REQUIRED_TAGS
    InputParameters:
      tag1Key: Environment
      tag2Key: CostCenter
      tag3Key: Owner
      tag4Key: ApprovalTicket
    Scope:
      ComplianceResourceTypes:
        - AWS::EC2::Instance
        - AWS::S3::Bucket
        - AWS::RDS::DBInstance

# Auto-remediation action
RemediationAction:
  Type: AWS::Config::RemediationConfiguration
  Properties:
    ConfigRuleName: !Ref RequiredTags
    TargetType: SSM_DOCUMENT
    TargetIdentifier: AWS-TerminateEC2Instance
    Automatic: true
```

---

## Terraform Cloud/Enterprise Integration

For regulated industries, **Terraform Cloud** provides the strongest enforcement:

### Setup

```hcl
# terraform.tf
terraform {
  cloud {
    organization = "your-financial-institution"

    workspaces {
      name = "production-infrastructure"
    }
  }
}
```

### Policy Sets (OPA Integration)

```hcl
# Terraform Cloud: Policy Sets
resource "tfe_policy_set" "opa_policies" {
  name         = "financial-compliance-policies"
  description  = "OPA policies for SOX, PCI-DSS, FFIEC, GLBA"
  organization = "your-financial-institution"
  kind         = "opa"  # Use OPA instead of Sentinel

  policies_path = "policies/"

  # Apply to all workspaces
  global = true

  # Or specific workspaces
  workspace_ids = [
    tfe_workspace.production.id,
    tfe_workspace.staging.id,
  ]

  vcs_repo {
    identifier         = "your-org/policy-as-code"
    branch             = "main"
    ingress_submodules = false
    oauth_token_id     = var.oauth_token_id
  }
}
```

### Enforcement Levels

```hcl
# Policy enforcement
resource "tfe_policy" "sox_compliance" {
  name         = "sox-compliance"
  description  = "SOX compliance - HARD FAIL"
  organization = "your-financial-institution"
  kind         = "opa"
  enforce_mode = "hard-mandatory"  # CANNOT be overridden
  policy       = file("policies/aws/compliance/sox.rego")
}

resource "tfe_policy" "cost_limits" {
  name         = "cost-governance"
  description  = "Cost limits - SOFT FAIL"
  organization = "your-financial-institution"
  kind         = "opa"
  enforce_mode = "soft-mandatory"  # Can be overridden with approval
  policy       = file("policies/aws/cost/resource-limits.rego")
}
```

**Enforcement Modes**:
- **hard-mandatory**: Cannot override (compliance policies)
- **soft-mandatory**: Can override with approval (cost policies)
- **advisory**: Warning only (best practices)

### Benefits

1. **Centralized Execution**: Terraform runs in Terraform Cloud, not locally
2. **No Local Credentials**: Developers don't have AWS/Azure credentials
3. **Policy Enforcement**: Policies run automatically, cannot be skipped
4. **Audit Trail**: Every run logged and auditable
5. **Approval Workflow**: Security/compliance team can require approval
6. **State Security**: State files encrypted and access-controlled

---

## Organizational Governance

### 1. Security Team Responsibilities

**Policy Repository Ownership**:
- Security team owns `policy-as-code` repository
- Only security team can merge policy changes
- Policies versioned with semantic versioning
- Breaking changes communicated to all teams

**Code Review Requirements**:
```
# policy-as-code/.github/CODEOWNERS
policies/aws/security/** @security-team @ciso
policies/aws/compliance/** @compliance-team @legal-team
policies/azure/** @security-team @ciso
tests/** @security-team
```

### 2. Compliance Team Responsibilities

**Framework Mapping**:
- Maintain compliance framework mappings (SOX, PCI-DSS, FFIEC, GLBA)
- Review compliance reports weekly
- Audit policy effectiveness quarterly
- Work with auditors to provide evidence

**Compliance Reporting**:
```bash
# Weekly compliance report generation (automated)
make compliance-reports

# Upload to audit platform
aws s3 cp reports/compliance/ s3://audit-evidence-bucket/$(date +%Y-%m-%d)/ --recursive

# Notify compliance team
python scripts/notify-compliance-team.py
```

### 3. Application Team Responsibilities

**Policy Compliance**:
- Application teams MUST use central policies
- Cannot create custom policies without approval
- Must fix violations before merge
- Cannot deploy to production with violations

**Approval Process**:
```
1. Developer creates PR with Terraform changes
2. GitHub Actions runs policy checks automatically
3. If violations: Developer fixes and pushes new commit
4. If passing: Security team reviews PR
5. Security team approves (via CODEOWNERS)
6. PR merged to main
7. Terraform Cloud applies changes (with policies)
8. Compliance report generated and archived
```

### 4. Exception Process

**Policy Exceptions** (rare, documented):

```yaml
# Exception request process
1. Create JIRA ticket with justification
2. Security/compliance team reviews
3. If approved:
   - Add exception to policy (temporary)
   - Set expiration date
   - Add monitoring/alerting
4. Document in compliance reports
5. Review exceptions quarterly
```

**Example Exception**:
```rego
# policies/aws/security/s3-encryption.rego
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not has_encryption(resource)

    # Exception: Legacy bucket JIRA-1234 (expires 2025-12-31)
    not is_exception(resource)

    msg := {...}
}

is_exception(resource) if {
    resource.address == "aws_s3_bucket.legacy_bucket"
    # Exception expires 2025-12-31
}
```

---

## Monitoring and Alerting

### 1. Policy Violations Dashboard

```python
# scripts/policy-dashboard.py
# Aggregate policy violations across all repositories
import requests
import json
from datetime import datetime, timedelta

def get_policy_violations():
    # Query GitHub API for policy check results
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}

    violations = []
    for repo in get_all_repos():
        workflow_runs = requests.get(
            f"https://api.github.com/repos/{repo}/actions/workflows/policy-enforcement.yml/runs",
            headers=headers
        ).json()

        for run in workflow_runs['workflow_runs']:
            if run['conclusion'] == 'failure':
                violations.append({
                    'repo': repo,
                    'date': run['created_at'],
                    'pr': run['pull_requests'][0]['number'],
                    'author': run['actor']['login']
                })

    return violations

# Generate dashboard
violations = get_policy_violations()
print(f"Policy violations in last 30 days: {len(violations)}")

# Alert if violations increasing
if len(violations) > THRESHOLD:
    send_alert_to_security_team(violations)
```

### 2. CloudWatch Alarms (AWS)

```yaml
# CloudWatch alarm for non-compliant resources
PolicyViolationAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: policy-violations-detected
    AlarmDescription: Alert when non-compliant resources detected
    MetricName: PolicyViolations
    Namespace: Compliance
    Statistic: Sum
    Period: 300
    EvaluationPeriods: 1
    Threshold: 0
    ComparisonOperator: GreaterThanThreshold
    AlarmActions:
      - !Ref SecurityTeamSNSTopic
```

### 3. Quarterly Compliance Review

```bash
# Automated quarterly compliance report
# Runs via cron: 0 0 1 */3 * (first day of each quarter)

#!/bin/bash
# scripts/quarterly-compliance-review.sh

QUARTER=$(date +%Y-Q$(($(date +%-m)/3+1)))

# Generate compliance reports for all repositories
for repo in $(get_all_repos); do
    cd $repo
    make compliance-reports
    cp -r reports/compliance/ /audit/evidence/$QUARTER/$repo/
done

# Aggregate results
python scripts/aggregate-compliance.py \
    --input /audit/evidence/$QUARTER/ \
    --output /audit/evidence/$QUARTER/summary.html

# Upload to audit platform
aws s3 cp /audit/evidence/$QUARTER/ \
    s3://audit-evidence/$QUARTER/ --recursive

# Notify compliance team
python scripts/notify-compliance-team.py \
    --report /audit/evidence/$QUARTER/summary.html
```

---

## Real-World Example: Financial Institution

### Architecture

```
Financial Institution
│
├── GitHub Organization: financial-corp
│   ├── policy-as-code (security team owns)
│   ├── banking-app-infra (app team 1)
│   ├── payments-infra (app team 2)
│   └── trading-platform-infra (app team 3)
│
├── Terraform Cloud Organization: financial-corp
│   ├── Workspace: banking-app-prod
│   ├── Workspace: payments-prod
│   └── Workspace: trading-platform-prod
│
├── AWS Organization
│   ├── Security Account (OPA policies stored here)
│   ├── Production Account (SCPs enforce tagging)
│   └── Development Account (relaxed policies)
│
└── Monitoring
    ├── Splunk (audit logs)
    ├── PagerDuty (security alerts)
    └── ServiceNow (exception tracking)
```

### Developer Workflow

```
Developer wants to add S3 bucket for customer data:

1. Create feature branch: git checkout -b feature/customer-data-bucket

2. Add Terraform code:
   resource "aws_s3_bucket" "customer_data" {
     bucket = "financial-corp-customer-data"
     tags = {
       Environment       = "production"
       CostCenter        = "CC-1234"
       Owner             = "team-payments"
       Application       = "payment-processor"
       DataClassification = "NPI"  # Triggers GLBA policies
       VendorCompliance  = "AWS-SOC2-2024"
       ApprovedRegion    = "true"
     }
   }

   resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
     bucket = aws_s3_bucket.customer_data.id
     rule {
       apply_server_side_encryption_by_default {
         sse_algorithm = "AES256"
       }
     }
   }

   # GLBA requires logging for breach detection
   resource "aws_s3_bucket_logging" "customer_data" {
     bucket        = aws_s3_bucket.customer_data.id
     target_bucket = aws_s3_bucket.logs.id
     target_prefix = "customer-data-access/"
   }

3. Open PR: GitHub Actions runs automatically
   - Terraform plan generated
   - OPA policies evaluate plan
   - GLBA policies check:
     [x] Encryption enabled (GLBA-SAFEGUARDS)
     [x] Logging enabled (GLBA-MONITORING)
     [x] No public access (GLBA-ACCESS)
     [x] Vendor compliance tags (GLBA-VENDOR)
     [x] DataClassification=NPI tagged
   - All checks pass

4. Code review:
   - CODEOWNERS: @security-team @compliance-team
   - Security reviews infrastructure change
   - Compliance reviews GLBA requirements
   - Both approve PR

5. Merge to main:
   - Terraform Cloud triggered
   - Policies run again (in Terraform Cloud)
   - Apply happens automatically
   - Compliance report generated
   - Audit evidence archived to S3

6. Post-deployment:
   - AWS Config monitors bucket
   - CloudTrail logs all access
   - Weekly compliance report shows bucket is compliant
```

**If developer tried to skip policies**:
- Cannot push to main (branch protected)
- Cannot bypass GitHub Actions (required check)
- Cannot run Terraform locally (no AWS credentials)
- Cannot modify workflow (CODEOWNERS protects it)
- Cannot deploy without encryption (GLBA policy fails)
- Service Control Policy would deny at AWS level

---

## Summary: Defense in Depth

| Layer | Control | Prevents |
|-------|---------|----------|
| **1. Branch Protection** | Required status checks | Direct pushes, bypassing CI/CD |
| **2. GitHub Actions** | Automated policy checks | Skipping policy validation |
| **3. CODEOWNERS** | Required approvals | Unauthorized infrastructure changes |
| **4. Terraform Cloud** | Centralized execution | Local Terraform runs |
| **5. IAM/SSO** | Least privilege access | Direct AWS console changes |
| **6. Service Control Policies** | AWS account-level | Non-tagged resources |
| **7. AWS Config** | Continuous monitoring | Drift from compliance |
| **8. CloudTrail** | Audit logging | Undetected changes |
| **9. Central Policy Repo** | Single source of truth | Custom/rogue policies |
| **10. Quarterly Reviews** | Human oversight | Long-term drift |

---

## Recommended Enforcement for Financial Services

### Minimum Requirements (Baseline)

1. GitHub branch protection with required checks
2. CODEOWNERS for infrastructure files
3. Central policy repository (security team owns)
4. GitHub Actions workflow enforcement
5. Weekly compliance reporting

### Recommended (Standard)

All of the above, plus:
6. Terraform Cloud/Enterprise
7. Service Control Policies (AWS) or Azure Policy
8. AWS Config continuous monitoring
9. CloudTrail with log file validation
10. Quarterly compliance audits

### Advanced (High Security)

All of the above, plus:
11. Policy violations dashboard
12. Real-time alerting (PagerDuty/Splunk)
13. Auto-remediation for critical violations
14. Exception tracking in ServiceNow/JIRA
15. Monthly security/compliance team reviews

---

## Next Steps

1. **Start with GitHub Actions**: Easiest to implement, immediate value
2. **Add Branch Protection**: Prevent bypasses
3. **Centralize Policies**: Security team controls policies
4. **Migrate to Terraform Cloud**: Strongest enforcement
5. **Add AWS/Azure Account Controls**: Defense in depth
6. **Implement Monitoring**: Continuous compliance

For questions or assistance implementing these controls, contact your security/compliance team.
