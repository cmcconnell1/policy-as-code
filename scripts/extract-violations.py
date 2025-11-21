#!/usr/bin/env python3
"""Extract policy violations from OPA eval JSON output."""

import json
import sys


def extract_violations(obj):
    """Recursively extract all 'deny' arrays from OPA result."""
    violations = []

    if isinstance(obj, dict):
        if 'deny' in obj and isinstance(obj['deny'], list):
            violations.extend(obj['deny'])
        for value in obj.values():
            violations.extend(extract_violations(value))
    elif isinstance(obj, list):
        for item in obj:
            violations.extend(extract_violations(item))

    return violations


def main():
    """Read OPA eval JSON from stdin and output violations JSON."""
    try:
        data = json.load(sys.stdin)

        # Extract the result value
        if 'result' in data and len(data['result']) > 0:
            result_value = data['result'][0]['expressions'][0]['value']
            violations = extract_violations(result_value)
        else:
            violations = []

        # Output violations in expected format
        output = {'violations': violations}
        print(json.dumps(output, indent=2))

    except Exception as e:
        print(f"Error extracting violations: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
