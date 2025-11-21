#!/usr/bin/env bash
# Script to run OPA policy tests

set -e

echo "[OK] Validating OPA/Rego policies..."

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed"
    echo "Install from: https://www.openpolicyagent.org/docs/latest/#running-opa"
    exit 1
fi

# Test AWS policies
echo "[OK] Testing AWS policies..."
opa test policies/aws/ tests/aws/ -v

# Test Azure policies
echo "[OK] Testing Azure policies..."
opa test policies/azure/ tests/azure/ -v

echo "[OK] All policy tests passed!"
