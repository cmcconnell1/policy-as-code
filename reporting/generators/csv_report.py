"""CSV report generator for policy violations"""

import csv
from datetime import datetime
from pathlib import Path
from typing import Any


class CSVReportGenerator:
    """Generates CSV reports from policy evaluation results"""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, violations: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> Path:
        """
        Generate CSV report from policy violations

        Args:
            violations: List of policy violations
            metadata: Optional metadata about the scan

        Returns:
            Path to generated CSV file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"policy-violations-{timestamp}.csv"

        if not violations:
            with output_file.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["No violations found"])
            return output_file

        fieldnames = ["policy", "resource", "severity", "message", "remediation", "compliance"]

        with output_file.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for violation in violations:
                writer.writerow({
                    "policy": violation.get("policy", ""),
                    "resource": violation.get("resource", ""),
                    "severity": violation.get("severity", ""),
                    "message": violation.get("message", ""),
                    "remediation": violation.get("remediation", ""),
                    "compliance": violation.get("compliance", "N/A"),
                })

        return output_file
