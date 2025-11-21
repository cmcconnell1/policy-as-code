#!/usr/bin/env bash
# Setup script for policy-as-code project

set -e

echo "================================================"
echo "  Policy-as-Code Setup"
echo "================================================"
echo ""

# Check for required tools
echo "[OK] Checking for required tools..."

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "  [OK] $1 found: $(command -v $1)"
        return 0
    else
        echo "  [WARNING] $1 not found"
        return 1
    fi
}

MISSING_TOOLS=0

check_tool "python3" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "uv" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "opa" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "terraform" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "git" || MISSING_TOOLS=$((MISSING_TOOLS + 1))

echo ""

if [ $MISSING_TOOLS -gt 0 ]; then
    echo "[WARNING] $MISSING_TOOLS required tool(s) missing"
    echo ""
    echo "Installation instructions:"
    echo "  - Python 3.11+: https://www.python.org/downloads/"
    echo "  - uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "  - OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
    echo "  - Terraform: https://www.terraform.io/downloads"
    echo ""
fi

# Install Python dependencies
echo "[OK] Installing Python dependencies..."
uv sync

# Make scripts executable
echo "[OK] Making scripts executable..."
chmod +x scripts/*.sh

# Create reports directory
echo "[OK] Creating reports directory..."
mkdir -p reports

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Run policy tests:        make test-policies"
echo "  2. Scan Terraform:          make scan-terraform"
echo "  3. Generate report:         make report"
echo "  4. View all commands:       make help"
echo ""
