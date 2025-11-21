#!/usr/bin/env bash
# Script to check Terraform plans against OPA policies

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <terraform-directory>"
    echo "Example: $0 examples/aws/non-compliant/"
    exit 1
fi

TERRAFORM_DIR="$1"

if [ ! -d "$TERRAFORM_DIR" ]; then
    echo "Error: Directory $TERRAFORM_DIR does not exist"
    exit 1
fi

echo "[OK] Checking Terraform configuration: $TERRAFORM_DIR"

# Check if terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "Error: Terraform is not installed"
    exit 1
fi

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed"
    echo "Install from: https://www.openpolicyagent.org/docs/latest/#running-opa"
    exit 1
fi

# Change to terraform directory
cd "$TERRAFORM_DIR"

# Initialize Terraform (without backend)
echo "[OK] Initializing Terraform..."
terraform init -backend=false > /dev/null 2>&1

# Generate plan
echo "[OK] Generating Terraform plan..."
terraform plan -out=tfplan > /dev/null 2>&1

# Convert plan to JSON
echo "[OK] Converting plan to JSON..."
terraform show -json tfplan > tfplan.json

# Evaluate with OPA
echo "[OK] Evaluating policies..."

POLICIES_DIR="$(cd ../../../policies && pwd)"
VIOLATIONS_FILE="policy-violations.json"

# Run OPA evaluation
opa eval \
    --data "$POLICIES_DIR" \
    --input tfplan.json \
    --format pretty \
    'data.aws.deny' > "$VIOLATIONS_FILE" 2>&1 || true

# Check for violations
VIOLATION_COUNT=$(cat "$VIOLATIONS_FILE" | grep -c "policy" || echo "0")

if [ "$VIOLATION_COUNT" -gt 0 ]; then
    echo "[WARNING] Found policy violations:"
    cat "$VIOLATIONS_FILE"

    # Clean up
    rm -f tfplan tfplan.json "$VIOLATIONS_FILE"

    echo ""
    echo "[FAILED] Policy validation failed with $VIOLATION_COUNT violation(s)"
    exit 1
else
    echo "[OK] No policy violations found!"

    # Clean up
    rm -f tfplan tfplan.json "$VIOLATIONS_FILE"
    exit 0
fi
