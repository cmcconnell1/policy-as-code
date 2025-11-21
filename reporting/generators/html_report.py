"""HTML report generator for policy violations"""

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader


class HTMLReportGenerator:
    """Generates HTML dashboard reports from policy evaluation results"""

    def __init__(self, output_dir: Path, template_dir: Path | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "templates"

        self.env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def generate(self, violations: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> Path:
        """
        Generate HTML report from policy violations

        Args:
            violations: List of policy violations
            metadata: Optional metadata about the scan

        Returns:
            Path to generated HTML file
        """
        if metadata is None:
            metadata = {}

        summary = self._generate_summary(violations)
        grouped_violations = self._group_violations(violations)

        template = self.env.get_template("policy-report.html")
        html_content = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            summary=summary,
            grouped_violations=grouped_violations,
            metadata=metadata,
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"policy-report-{timestamp}.html"

        with output_file.open("w") as f:
            f.write(html_content)

        return output_file

    def _generate_summary(self, violations: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate summary statistics from violations"""
        if not violations:
            return {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "by_cloud": {},
                "by_category": {},
            }

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cloud_counts = {}
        category_counts = {}

        for violation in violations:
            severity = violation.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            policy = violation.get("policy", "")
            if policy.startswith("aws."):
                cloud_counts["AWS"] = cloud_counts.get("AWS", 0) + 1
                parts = policy.split(".")
                if len(parts) > 2:
                    category = parts[1]
                    category_counts[category] = category_counts.get(category, 0) + 1
            elif policy.startswith("azure."):
                cloud_counts["Azure"] = cloud_counts.get("Azure", 0) + 1
                parts = policy.split(".")
                if len(parts) > 2:
                    category = parts[1]
                    category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total": len(violations),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "by_cloud": cloud_counts,
            "by_category": category_counts,
        }

    def _group_violations(self, violations: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Group violations by severity"""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for violation in violations:
            severity = violation.get("severity", "UNKNOWN")
            if severity in grouped:
                grouped[severity].append(violation)
            else:
                grouped["MEDIUM"].append(violation)

        return grouped
