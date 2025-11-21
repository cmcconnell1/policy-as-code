#!/usr/bin/env python3
"""
Policy-as-Code Compliance Reporting Tool

This tool generates automated compliance reports for banking industry frameworks
by mapping policy violations to specific compliance controls.

SUPPORTED COMPLIANCE FRAMEWORKS:

1. SOX (Sarbanes-Oxley Act)
   Purpose: Financial reporting integrity and internal controls
   Industry: Public companies (especially financial services)
   Controls: SOX-302, SOX-404, SOX-ITGC
   Focus: Access controls, audit trails, segregation of duties, change management

2. FFIEC (Federal Financial Institutions Examination Council)
   Purpose: Cybersecurity Assessment Tool for financial institutions
   Industry: Banks, credit unions, financial institutions
   Controls: 5 Domains (D1-D5) covering cyber risk management to incident resilience
   Focus: Cybersecurity maturity, threat intelligence, controls, external dependencies

3. GLBA (Gramm-Leach-Bliley Act)
   Purpose: Financial privacy and consumer data protection
   Industry: Financial services (banks, insurance, investment)
   Controls: Safeguards Rule, Access Control, Security Monitoring
   Focus: Privacy safeguards, access restrictions, monitoring, employee training

4. PCI DSS (Payment Card Industry Data Security Standard)
   Purpose: Payment card data security
   Industry: Any organization that accepts, processes, or stores payment cards
   Controls: Requirements 2, 7, 8, 10 (IAM-specific)
   Focus: Access restriction, authentication, unique IDs, logging/monitoring

USAGE EXAMPLES:

    # Generate SOX compliance report from policy violations
    python reporting/compliance_report.py \\
        --framework sox \\
        --input reports/policy-violations.json \\
        --output reports/sox-compliance.html

    # Generate FFIEC report
    python reporting/compliance_report.py \\
        --framework ffiec \\
        --input reports/policy-violations.json \\
        --output reports/ffiec-compliance.html

    # Generate PCI DSS report
    python reporting/compliance_report.py \\
        --framework pci \\
        --input reports/policy-violations.json \\
        --output reports/pci-compliance.html

    # Generate all frameworks
    python reporting/compliance_report.py \\
        --framework all \\
        --input reports/policy-violations.json \\
        --output-dir reports/compliance/

OUTPUT:
    - HTML reports with pass/fail status per control
    - Overall compliance score (0-100%)
    - Specific findings mapped to violations
    - Remediation recommendations
    - Evidence for audit purposes
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Compliance framework control mappings
FRAMEWORK_CONTROLS = {
    "sox": {
        "name": "SOX (Sarbanes-Oxley Act)",
        "description": "Financial reporting integrity and internal controls",
        "controls": {
            "SOX-302": {
                "title": "Management Assessment of Internal Controls",
                "description": "CEO/CFO certification of internal controls over financial reporting",
                "policy_mappings": [
                    "aws.security.iam_mfa",
                    "aws.compliance.sox",
                    "azure.security.key_vault",
                ],
            },
            "SOX-404": {
                "title": "Internal Control Assessment",
                "description": "Document and assess effectiveness of internal controls",
                "policy_mappings": [
                    "aws.security.s3_encryption",
                    "aws.compliance.sox",
                    "azure.security.storage_encryption",
                ],
            },
            "SOX-ITGC": {
                "title": "IT General Controls",
                "description": "IT controls supporting financial reporting systems",
                "policy_mappings": [
                    "aws.security.kms_encryption",
                    "aws.compliance.sox",
                    "aws.tagging.required_tags",
                ],
            },
        },
    },
    "pci": {
        "name": "PCI DSS",
        "description": "Payment Card Industry Data Security Standard",
        "controls": {
            "PCI-REQ-1": {
                "title": "Install and Maintain Firewall Configuration",
                "description": "Protect cardholder data with firewall and router configuration",
                "policy_mappings": [
                    "aws.security.ec2_security_groups",
                    "azure.security.network_security",
                ],
            },
            "PCI-REQ-2": {
                "title": "Do Not Use Vendor-Supplied Defaults",
                "description": "Change default passwords and security parameters",
                "policy_mappings": [
                    "aws.compliance.pci_dss",
                ],
            },
            "PCI-REQ-3": {
                "title": "Protect Stored Cardholder Data",
                "description": "Encrypt transmission of cardholder data",
                "policy_mappings": [
                    "aws.security.s3_encryption",
                    "aws.security.kms_encryption",
                    "azure.security.storage_encryption",
                    "aws.compliance.pci_dss",
                ],
            },
            "PCI-REQ-7": {
                "title": "Restrict Access by Business Need-to-Know",
                "description": "Limit access to cardholder data by business need to know",
                "policy_mappings": [
                    "aws.security.s3_public_access",
                    "aws.security.iam_mfa",
                    "aws.compliance.pci_dss",
                ],
            },
            "PCI-REQ-8": {
                "title": "Identify and Authenticate Access",
                "description": "Assign unique ID to each person with computer access",
                "policy_mappings": [
                    "aws.security.iam_mfa",
                    "aws.compliance.pci_dss",
                ],
            },
            "PCI-REQ-10": {
                "title": "Track and Monitor Access",
                "description": "Track and monitor all access to network resources and cardholder data",
                "policy_mappings": [
                    "aws.compliance.pci_dss",
                    "aws.compliance.sox",
                ],
            },
        },
    },
    "ffiec": {
        "name": "FFIEC Cybersecurity Assessment",
        "description": "Federal Financial Institutions Examination Council - Cybersecurity maturity",
        "controls": {
            "FFIEC-D1": {
                "title": "Cyber Risk Management and Oversight",
                "description": "Establish cybersecurity governance",
                "policy_mappings": [
                    "aws.tagging.required_tags",
                    "aws.compliance.ffiec",
                ],
            },
            "FFIEC-D2": {
                "title": "Threat Intelligence and Collaboration",
                "description": "Monitor and respond to cyber threats",
                "policy_mappings": [
                    "aws.compliance.ffiec",
                ],
            },
            "FFIEC-D3": {
                "title": "Cybersecurity Controls",
                "description": "Implement preventative and detective controls",
                "policy_mappings": [
                    "aws.security.s3_encryption",
                    "aws.security.kms_encryption",
                    "aws.security.ec2_security_groups",
                    "azure.security.storage_encryption",
                    "azure.security.network_security",
                    "aws.compliance.ffiec",
                ],
            },
            "FFIEC-D4": {
                "title": "External Dependency Management",
                "description": "Manage third-party and supply chain risks",
                "policy_mappings": [
                    "aws.compliance.ffiec",
                ],
            },
            "FFIEC-D5": {
                "title": "Cyber Incident Management and Resilience",
                "description": "Detect, respond, and recover from incidents",
                "policy_mappings": [
                    "aws.compliance.ffiec",
                ],
            },
        },
    },
    "glba": {
        "name": "GLBA",
        "description": "Gramm-Leach-Bliley Act - Financial privacy and consumer data protection (Updated for 2023 FTC Final Rule and 2024 Breach Notification Rule)",
        "controls": {
            "GLBA-SAFEGUARDS": {
                "title": "Safeguards Rule - Data Protection",
                "description": "Administrative, technical, and physical safeguards to protect nonpublic personal information (NPI)",
                "policy_mappings": [
                    "aws.compliance.glba",
                    "aws.security.s3_encryption",
                    "aws.security.kms_encryption",
                    "azure.security.storage_encryption",
                ],
            },
            "GLBA-ACCESS": {
                "title": "Access Control - Limit NPI Access",
                "description": "Limit access to customer information to authorized personnel only",
                "policy_mappings": [
                    "aws.compliance.glba",
                    "aws.security.s3_public_access",
                    "aws.security.iam_mfa",
                    "aws.security.ec2_security_groups",
                    "azure.security.key_vault",
                    "azure.security.network_security",
                ],
            },
            "GLBA-MONITORING": {
                "title": "Security Monitoring - Continuous Oversight",
                "description": "Monitor systems, detect unauthorized access, and adapt to emerging threats",
                "policy_mappings": [
                    "aws.compliance.glba",
                    "aws.compliance.sox",
                    "aws.compliance.ffiec",
                ],
            },
            "GLBA-VENDOR": {
                "title": "Third-Party Oversight - Cloud/Hybrid Security",
                "description": "Ensure cloud service providers maintain adequate data protection controls",
                "policy_mappings": [
                    "aws.compliance.glba",
                    "aws.tagging.required_tags",
                ],
            },
            "GLBA-BREACH": {
                "title": "Breach Notification - 30-Day Requirement",
                "description": "Report data breaches affecting 500+ customers within 30 days (2024 FTC Rule)",
                "policy_mappings": [
                    "aws.compliance.glba",
                    "aws.compliance.sox",
                ],
            },
        },
    },
}


class ComplianceReporter:
    """Generate compliance reports from policy violations"""

    def __init__(self):
        self.frameworks = FRAMEWORK_CONTROLS

    def load_violations(self, file_path: Path) -> list[dict[str, Any]]:
        """Load policy violations from JSON file"""
        try:
            with file_path.open() as f:
                data = json.load(f)

            # Handle different JSON formats
            if isinstance(data, dict):
                if "violations" in data:
                    return data["violations"]
                elif "deny" in data:
                    return list(data["deny"])
                elif "results" in data:
                    # Conftest format
                    violations = []
                    for result in data["results"]:
                        for failure in result.get("failures", []):
                            if isinstance(failure.get("msg"), dict):
                                violations.append(failure["msg"])
                    return violations
            elif isinstance(data, list):
                return data

            return []
        except Exception as e:
            print(f"Error loading violations from {file_path}: {e}", file=sys.stderr)
            return []

    def evaluate_framework(
        self, framework_name: str, violations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Evaluate compliance framework against violations"""

        framework = self.frameworks.get(framework_name)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_name}")

        results = {
            "framework": framework["name"],
            "description": framework["description"],
            "controls": [],
            "overall_score": 0,
            "pass_count": 0,
            "partial_count": 0,
            "fail_count": 0,
        }

        # Evaluate each control
        for control_id, control in framework["controls"].items():
            control_result = self._evaluate_control(control_id, control, violations)
            results["controls"].append(control_result)

            if control_result["status"] == "PASS":
                results["pass_count"] += 1
            elif control_result["status"] == "PARTIAL":
                results["partial_count"] += 1
            else:
                results["fail_count"] += 1

        # Calculate overall score
        total_controls = len(results["controls"])
        if total_controls > 0:
            total_score = sum(c["score"] for c in results["controls"])
            results["overall_score"] = round(total_score / total_controls, 1)

        return results

    def _evaluate_control(
        self, control_id: str, control: dict[str, Any], violations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Evaluate a single control"""

        result = {
            "control_id": control_id,
            "title": control["title"],
            "description": control["description"],
            "status": "PASS",
            "score": 100,
            "findings": [],
            "evidence": [],
        }

        # Find violations that map to this control
        mapped_violations = []
        for violation in violations:
            policy = violation.get("policy", "")
            for mapping in control["policy_mappings"]:
                if policy.startswith(mapping):
                    mapped_violations.append(violation)
                    break

        # Determine status based on violations
        if len(mapped_violations) == 0:
            result["status"] = "PASS"
            result["score"] = 100
            result["evidence"].append("No policy violations found for this control")
        elif len(mapped_violations) <= 2:
            result["status"] = "PARTIAL"
            result["score"] = 65
            result["findings"] = [
                f"{v.get('severity', 'MEDIUM')}: {v.get('message', 'No message')}"
                for v in mapped_violations
            ]
        else:
            result["status"] = "FAIL"
            result["score"] = 25
            result["findings"] = [
                f"{v.get('severity', 'MEDIUM')}: {v.get('message', 'No message')}"
                for v in mapped_violations
            ]

        return result

    def generate_html_report(self, framework_results: dict[str, Any], output_path: Path):
        """Generate HTML compliance report"""

        score = framework_results["overall_score"]
        score_color = "#27ae60" if score >= 80 else "#e67e22" if score >= 60 else "#e74c3c"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{framework_results['framework']} Compliance Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
        }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .summary {{
            padding: 30px;
            border-bottom: 2px solid #eee;
        }}
        .score-card {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .score-value {{
            font-size: 64px;
            font-weight: bold;
            color: {score_color};
        }}
        .score-label {{ font-size: 18px; color: #666; margin-top: 10px; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .stat {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-pass {{ color: #27ae60; }}
        .stat-partial {{ color: #e67e22; }}
        .stat-fail {{ color: #e74c3c; }}
        .controls {{
            padding: 30px;
        }}
        .control {{
            background: #f8f9fa;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 5px solid;
        }}
        .control.pass {{ border-left-color: #27ae60; }}
        .control.partial {{ border-left-color: #e67e22; }}
        .control.fail {{ border-left-color: #e74c3c; }}
        .control-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .control-title {{ font-size: 20px; font-weight: bold; color: #2c3e50; }}
        .status-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: bold;
            color: white;
        }}
        .status-badge.pass {{ background: #27ae60; }}
        .status-badge.partial {{ background: #e67e22; }}
        .status-badge.fail {{ background: #e74c3c; }}
        .control-description {{ color: #666; margin-bottom: 15px; }}
        .findings {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        .findings.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .findings h4 {{ margin-bottom: 10px; color: #856404; }}
        .findings.critical h4 {{ color: #721c24; }}
        .findings ul {{ margin-left: 20px; }}
        .findings li {{ margin-bottom: 5px; }}
        .evidence {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        .evidence h4 {{ margin-bottom: 10px; color: #155724; }}
        .footer {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-radius: 0 0 8px 8px;
            text-align: center;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{framework_results['framework']} Compliance Report</h1>
            <p>{framework_results['description']}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>

        <div class="summary">
            <div class="score-card">
                <div class="score-value">{score}%</div>
                <div class="score-label">Overall Compliance Score</div>
            </div>

            <div class="stats">
                <div class="stat">
                    <div class="stat-value stat-pass">{framework_results['pass_count']}</div>
                    <div>Passing Controls</div>
                </div>
                <div class="stat">
                    <div class="stat-value stat-partial">{framework_results['partial_count']}</div>
                    <div>Partial Compliance</div>
                </div>
                <div class="stat">
                    <div class="stat-value stat-fail">{framework_results['fail_count']}</div>
                    <div>Failing Controls</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{len(framework_results['controls'])}</div>
                    <div>Total Controls</div>
                </div>
            </div>
        </div>

        <div class="controls">
            <h2 style="margin-bottom: 20px;">Control Assessment Results</h2>
"""

        for control in framework_results["controls"]:
            status_class = control["status"].lower()
            findings_class = "critical" if control["score"] < 50 else ""

            html += f"""
            <div class="control {status_class}">
                <div class="control-header">
                    <div class="control-title">{control['control_id']}: {control['title']}</div>
                    <div>
                        <span class="status-badge {status_class}">{control['status']}</span>
                        <span style="margin-left: 10px; font-weight: bold; color: #666;">
                            Score: {control['score']}%
                        </span>
                    </div>
                </div>
                <div class="control-description">{control['description']}</div>
"""

            if control["findings"]:
                html += f"""
                <div class="findings {findings_class}">
                    <h4>Findings ({len(control['findings'])})</h4>
                    <ul>
"""
                for finding in control["findings"]:
                    html += f"                        <li>{finding}</li>\n"
                html += """                    </ul>
                </div>
"""

            if control["evidence"]:
                html += """
                <div class="evidence">
                    <h4>Evidence</h4>
                    <ul>
"""
                for evidence in control["evidence"]:
                    html += f"                        <li>{evidence}</li>\n"
                html += """                    </ul>
                </div>
"""

            html += "            </div>\n"

        html += """
        </div>

        <div class="footer">
            <p>This report was generated by the Policy-as-Code compliance reporting tool.</p>
            <p>For questions or concerns, please contact your DevSecOps team.</p>
        </div>
    </div>
</body>
</html>
"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            f.write(html)

        print(f"[OK] Generated compliance report: {output_path}")

    def generate_report(self, framework_name: str, input_file: Path, output_path: Path):
        """Generate compliance report for a framework"""

        print(f"[OK] Generating {framework_name.upper()} compliance report...")

        violations = self.load_violations(input_file)
        print(f"[OK] Loaded {len(violations)} policy violations")

        results = self.evaluate_framework(framework_name, violations)
        print(f"[OK] Compliance score: {results['overall_score']}%")
        print(f"    Pass: {results['pass_count']}, "
              f"Partial: {results['partial_count']}, "
              f"Fail: {results['fail_count']}")

        self.generate_html_report(results, output_path)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Policy-as-Code Compliance Reporting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--framework",
        required=True,
        choices=["sox", "pci", "ffiec", "glba", "all"],
        help="Compliance framework to report on",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input JSON file with policy violations",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output HTML report path (for single framework)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for reports (for all frameworks)",
    )

    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    reporter = ComplianceReporter()

    if args.framework == "all":
        output_dir = args.output_dir or Path("reports/compliance")
        output_dir.mkdir(parents=True, exist_ok=True)

        for framework in ["sox", "pci", "ffiec", "glba"]:
            output_file = output_dir / f"{framework}-compliance-report.html"
            reporter.generate_report(framework, args.input, output_file)
    else:
        output_file = args.output or Path(f"reports/{args.framework}-compliance-report.html")
        reporter.generate_report(args.framework, args.input, output_file)

    print("\n[OK] Compliance reporting complete!")


if __name__ == "__main__":
    main()
