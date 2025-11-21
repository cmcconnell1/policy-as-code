"""JSON report generator for policy violations"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class JSONReportGenerator:
    """Generates JSON reports from policy evaluation results"""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, violations: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> Path:
        """
        Generate JSON report from policy violations

        Args:
            violations: List of policy violations
            metadata: Optional metadata about the scan

        Returns:
            Path to generated JSON file
        """
        if metadata is None:
            metadata = {}

        report_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tool": "policy-as-code",
                "version": "0.1.0",
                **metadata,
            },
            "summary": self._generate_summary(violations),
            "violations": violations,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"policy-violations-{timestamp}.json"

        with output_file.open("w") as f:
            json.dump(report_data, f, indent=2)

        return output_file

    def _generate_summary(self, violations: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate summary statistics from violations"""
        if not violations:
            return {
                "total_violations": 0,
                "by_severity": {},
                "by_policy": {},
                "by_cloud": {},
            }

        by_severity = {}
        by_policy = {}
        by_cloud = {}

        for violation in violations:
            # Count by severity
            severity = violation.get("severity", "UNKNOWN")
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # Count by policy
            policy = violation.get("policy", "unknown")
            by_policy[policy] = by_policy.get(policy, 0) + 1

            # Count by cloud provider
            if policy.startswith("aws."):
                by_cloud["AWS"] = by_cloud.get("AWS", 0) + 1
            elif policy.startswith("azure."):
                by_cloud["Azure"] = by_cloud.get("Azure", 0) + 1

        return {
            "total_violations": len(violations),
            "by_severity": by_severity,
            "by_policy": by_policy,
            "by_cloud": by_cloud,
        }
