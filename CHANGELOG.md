# Changelog

All notable changes to the policy-as-code framework.

## [Unreleased]

### Added
- Enforcement Strategies guide (docs/guides/enforcement-strategies.md) explaining:
  - How to integrate OPA/Rego with existing repositories
  - How to prevent developers from bypassing policies
  - GitHub branch protection and required status checks
  - Terraform Cloud/Enterprise integration
  - Service Control Policies and AWS Config enforcement
  - Real-world example for financial institutions
  - Defense-in-depth approach with 10 enforcement layers
- GLBA compliance policies (policies/aws/compliance/glba.rego) with 10 comprehensive rules covering all 5 control areas:
  - GLBA-SAFEGUARDS: Encryption of customer data (NPI) at rest and in transit
  - GLBA-ACCESS: Access control, MFA, network isolation, public access blocking
  - GLBA-MONITORING: Audit logging and CloudTrail for breach detection
  - GLBA-VENDOR: Third-party oversight with compliance tagging for cloud vendors
  - GLBA-BREACH: 30-day backup retention for breach investigation (2024 FTC Rule)
- GLBA test suite (tests/aws/compliance/glba_test.rego) with 16 comprehensive test cases
- Support for 2024 FTC Breach Notification Rule (30-day requirement for 500+ customers)
- Data classification enforcement via tags (NPI, PII, confidential, restricted)
- CloudTrail requirement for resources storing customer data
- Vendor compliance tagging requirements for approved regions

### Changed
- Enhanced GLBA compliance reporting from 3 to 5 controls in compliance_report.py
- Updated docs/guides/compliance-reporting.md with detailed GLBA section including:
  - Enforcement agencies (FTC, OCC, Federal Reserve, CFPB)
  - 2023 FTC Final Rule and 2024 Breach Notification Rule
  - Expanded focus areas from 4 to 6 detailed requirements
- Updated docs/reference/compliance-summary.md with complete GLBA control mappings
- Updated README.md to include GLBA in:
  - Project description (financial services compliance frameworks)
  - Compliance Framework Policies section with 7 GLBA controls
  - Project structure (compliance/ directory)
- All GLBA controls now map to aws.compliance.glba policy package

### Fixed
- GLBA test failures by adding required vendor compliance tags and CloudTrail resources to test fixtures
- .gitignore now properly excludes reports/compliance/ subdirectory (was only excluding files directly in reports/)
- `make report` target now correctly evaluates policies before generating reports (was passing raw Terraform JSON)
- Reporting CLI now handles violations format from extract-violations.py script

## [1.0.0] - 2025-11-20

### Fixed

#### OPA Policy Syntax Errors
- **policies/aws/security/s3-public-access.rego**
  - Fixed helper function calls: Changed `is_s3_bucket(resource.change.after)` to `is_s3_bucket(resource)`
  - Fixed comprehension: Changed `is_public_access_block(pab.change.after)` to `is_public_access_block(pab)`
  - Root cause: Helper functions check `resource.type` at top level, not in `change.after`

- **policies/aws/security/s3-encryption.rego**
  - Fixed helper function calls: Changed `is_s3_bucket(resource.change.after)` to `is_s3_bucket(resource)`
  - Fixed comprehension: Changed `has_encryption(enc.change.after)` to `has_encryption(enc)`

- **policies/aws/cost/resource-limits.rego**
  - Fixed variable shadowing: Changed `count := count(resources)` to `resource_count := count(resources)`
  - Issue: `count` is a built-in OPA function and cannot be used as a variable name

#### OPA Test Syntax Errors
- **All test files** (tests/aws/security/*.rego, tests/aws/tagging/*.rego)
  - Fixed variable shadowing: Renamed `input` variable to `test_data` throughout all tests
  - Fixed OPA syntax: Updated to use `result := deny with input as test_data` pattern
  - Issue: `input` is a reserved global variable in OPA and cannot be shadowed

#### Python Build Errors
- **pyproject.toml**
  - Changed `requires-python` from ">=3.11" to ">=3.9" for broader compatibility
  - Removed problematic `[build-system]` section that caused hatchling errors
  - Converted `tool.uv.dev-dependencies` to `[dependency-groups]` format

### Added

#### New Scripts
- **scripts/extract-violations.py**
  - Python script to extract policy violations from OPA eval JSON output
  - Converts OPA result format to violations JSON format expected by compliance reports
  - Used in automated workflows for report generation

#### New Makefile Targets
- **evaluate-fixture** - Evaluate test fixtures and extract violations (no cloud credentials needed)
  - Runs OPA policies against test fixtures
  - Extracts violations using extract-violations.py
  - Saves results to reports/violations.json

- Updated **compliance-reports** target to automatically evaluate fixtures first
- Updated **compliance-sox**, **compliance-pci**, **compliance-ffiec**, **compliance-glba** targets
  - All now automatically evaluate fixtures before generating reports
  - No manual violation extraction needed

#### Documentation Improvements
- **README.md**
  - Added "Policy Engine" section explaining OPA and Rego
  - Added Step 4: "Evaluate Policies (No Credentials Needed)"
  - Updated Step 5 to clarify "Scan Live Terraform (Requires Cloud Credentials)"
  - Updated Step 6 compliance report generation instructions
  - Updated prerequisites: Python 3.9+ (was 3.11+), Terraform marked as optional
  - Added extract-violations.py to project structure
  - Updated all make target descriptions with clarity on credential requirements
  - Updated compliance report generation examples
  - Reorganized documentation links to point to docs/ directory
  - Bumped version to 1.0.0

- **docs/guides/getting-started.md** (moved from GETTING_STARTED.md)
  - Added Step 3: "Evaluate Test Fixtures" with expected output
  - Updated Step 4 to explain automatic fixture evaluation
  - Updated "Understanding What You Just Did" section
  - Updated Option A workflow to use make evaluate-fixture
  - Updated Common Commands section
  - Updated Troubleshooting section with evaluate-fixture examples
  - Updated Quick Reference table
  - Removed hardcoded absolute paths

- **docs/guides/compliance-reporting.md**
  - Updated Quick Start to emphasize "No Cloud Credentials Needed"
  - Updated Generate Specific Framework Reports section
  - Updated "Using Real Policy Violations" with extract-violations.py script
  - Added explanation of automatic fixture evaluation

- **docs/reference/compliance-summary.md** (moved from COMPLIANCE_SUMMARY.md)
  - Updated Quick Commands to clarify no cloud credentials needed
  - Added manual workflow showing evaluate-fixture step
  - Split Example Workflow into "Quick Start" and "Production Workflow"
  - Updated all code examples to use extract-violations.py

- **docs/guides/quickstart.md** (moved from QUICKSTART.md)
  - Condensed quick reference guide

- **docs/architecture/project-requirements.md** (moved from project-outline-requirement.md)
  - Original project requirements and specifications

### Changed

#### Workflow Improvements
- Compliance report generation now works completely offline with test fixtures
- No AWS/Azure credentials required for testing and demonstration
- Simplified workflow: `make compliance-reports` does everything automatically
- Clear separation between offline testing (make evaluate-fixture) and live scanning (make scan-terraform)

#### Test Results
- All 13 AWS policy tests now pass (was failing before fixes)
- Test suite validates:
  - 4 S3 encryption tests
  - 4 S3 public access tests
  - 5 tagging requirement tests

#### Report Generation
- Compliance reports now correctly show violations and compliance scores
- Example results from test fixtures:
  - SOX: 65.0% compliance (3 partial controls)
  - PCI-DSS: 82.5% compliance (3 pass, 3 partial)
  - FFIEC: 86.0% compliance (3 pass, 2 partial)
  - GLBA: 65.0% compliance (3 partial controls)

### Technical Details

#### Terraform Plan JSON Structure
The fixes addressed a fundamental misunderstanding of Terraform plan JSON structure:
```json
{
  "resource_changes": [
    {
      "type": "aws_s3_bucket",     // <-- type is at top level
      "address": "...",
      "change": {
        "after": {
          "bucket": "...",          // <-- NOT here
          "acl": "private"
        }
      }
    }
  ]
}
```

Helper functions that check `resource.type` must receive the full resource object, not `resource.change.after`.

#### OPA Best Practices
- Never shadow built-in functions (count, max, min, etc.) or global variables (input)
- Helper functions should operate on the full resource object from resource_changes
- Access nested data (change.after) only when extracting specific field values
- Use `with input as test_data` syntax for testing to avoid shadowing global input

## [0.1.0] - 2025-11-19

### Added
- Initial framework implementation
- AWS and Azure security policies
- Compliance framework support (SOX, PCI-DSS, FFIEC, GLBA)
- Compliance reporting tool
- Test fixtures
- GitHub Actions workflows
- Documentation

[1.0.0]: https://github.com/your-org/policy-as-code/releases/tag/v1.0.0
[0.1.0]: https://github.com/your-org/policy-as-code/releases/tag/v0.1.0
