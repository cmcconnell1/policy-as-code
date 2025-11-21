.PHONY: help install test test-policies lint format check-terraform report clean

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies using uv
	@echo "[OK] Installing Python dependencies with uv..."
	command -v uv >/dev/null 2>&1 || { echo "Error: uv not found. Install from https://github.com/astral-sh/uv"; exit 1; }
	uv sync
	@echo "[OK] Installing OPA..."
	command -v opa >/dev/null 2>&1 || { echo "Warning: OPA not found. Install from https://www.openpolicyagent.org/docs/latest/#running-opa"; }
	@echo "[OK] Installation complete"

test:  ## Run all tests (Rego policies + Python)
	@echo "[OK] Running OPA policy tests..."
	@$(MAKE) test-policies
	@echo "[OK] Running Python tests..."
	uv run pytest tests/ -v
	@echo "[OK] All tests passed"

test-policies:  ## Run OPA/Rego policy tests
	@echo "[OK] Testing AWS policies..."
	opa test policies/aws/ tests/aws/ -v
	@echo "[OK] Testing Azure policies..."
	opa test policies/azure/ tests/azure/ -v
	@echo "[OK] All policy tests passed"

lint:  ## Lint Python code with ruff
	@echo "[OK] Linting Python code..."
	uv run ruff check reporting/ scripts/
	@echo "[OK] Linting complete"

format:  ## Format Python code with ruff
	@echo "[OK] Formatting Python code..."
	uv run ruff format reporting/ scripts/
	@echo "[OK] Formatting complete"

check-terraform:  ## Validate example Terraform configurations
	@echo "[OK] Checking compliant Terraform example..."
	cd examples/aws/compliant && terraform init -backend=false && terraform validate
	@echo "[OK] Terraform validation passed"

scan-terraform:  ## Scan Terraform with OPA policies (requires AWS credentials)
	@echo "[OK] Scanning non-compliant example..."
	@./scripts/check-terraform.sh examples/aws/non-compliant/
	@echo "[OK] Scan complete"

evaluate-fixture:  ## Evaluate test fixture and extract violations (no credentials needed)
	@echo "[OK] Evaluating test fixture..."
	@mkdir -p reports
	@opa eval -d policies/aws/ -i tests/test-fixtures/aws/s3-non-compliant.json 'data.aws' --format json | \
		python3 scripts/extract-violations.py > reports/violations.json
	@echo "[OK] Found $$(python3 -c "import json; print(len(json.load(open('reports/violations.json'))['violations']))" ) violations"
	@echo "[OK] Violations saved to reports/violations.json"

report:  ## Generate sample policy report
	@echo "[OK] Generating sample report..."
	uv run python -m reporting.cli generate \
		--input tests/test-fixtures/aws/s3-non-compliant.json \
		--output reports \
		--format html --format json --format csv
	@echo "[OK] Reports generated in reports/"

compliance-reports:  ## Generate all compliance framework reports
	@echo "[OK] Evaluating policies and extracting violations..."
	@$(MAKE) evaluate-fixture
	@echo "[OK] Generating compliance reports..."
	@mkdir -p reports/compliance
	python reporting/compliance_report.py \
		--framework all \
		--input reports/violations.json \
		--output-dir reports/compliance
	@echo "[OK] Compliance reports generated in reports/compliance/"

compliance-sox:  ## Generate SOX compliance report
	@echo "[OK] Evaluating policies and extracting violations..."
	@$(MAKE) evaluate-fixture
	@echo "[OK] Generating SOX compliance report..."
	python reporting/compliance_report.py \
		--framework sox \
		--input reports/violations.json \
		--output reports/sox-compliance.html
	@echo "[OK] SOX report: reports/sox-compliance.html"

compliance-pci:  ## Generate PCI DSS compliance report
	@echo "[OK] Evaluating policies and extracting violations..."
	@$(MAKE) evaluate-fixture
	@echo "[OK] Generating PCI DSS compliance report..."
	python reporting/compliance_report.py \
		--framework pci \
		--input reports/violations.json \
		--output reports/pci-compliance.html
	@echo "[OK] PCI DSS report: reports/pci-compliance.html"

compliance-ffiec:  ## Generate FFIEC compliance report
	@echo "[OK] Evaluating policies and extracting violations..."
	@$(MAKE) evaluate-fixture
	@echo "[OK] Generating FFIEC compliance report..."
	python reporting/compliance_report.py \
		--framework ffiec \
		--input reports/violations.json \
		--output reports/ffiec-compliance.html
	@echo "[OK] FFIEC report: reports/ffiec-compliance.html"

compliance-glba:  ## Generate GLBA compliance report
	@echo "[OK] Evaluating policies and extracting violations..."
	@$(MAKE) evaluate-fixture
	@echo "[OK] Generating GLBA compliance report..."
	python reporting/compliance_report.py \
		--framework glba \
		--input reports/violations.json \
		--output reports/glba-compliance.html
	@echo "[OK] GLBA report: reports/glba-compliance.html"

clean:  ## Clean generated files
	@echo "[OK] Cleaning generated files..."
	rm -rf reports/*.html reports/*.json reports/*.csv
	rm -rf reports/compliance/
	rm -rf examples/aws/compliant/.terraform examples/aws/compliant/.terraform.lock.hcl
	rm -rf examples/aws/non-compliant/.terraform examples/aws/non-compliant/.terraform.lock.hcl
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "[OK] Clean complete"

validate-all:  ## Run all validation checks
	@echo "[OK] Running comprehensive validation..."
	@$(MAKE) test-policies
	@$(MAKE) lint
	@$(MAKE) check-terraform
	@echo "[OK] All validations passed"
