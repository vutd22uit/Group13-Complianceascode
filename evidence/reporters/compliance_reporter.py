#!/usr/bin/env python3
"""
Compliance Reporter - Generate Audit-Ready Reports

This script generates comprehensive compliance reports from evidence data
for auditors and stakeholders.
"""

import json
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ComplianceReporter:
    """Generate compliance reports from evidence"""

    def __init__(self, evidence_bucket: str):
        """
        Initialize compliance reporter

        Args:
            evidence_bucket: S3 bucket containing evidence
        """
        self.evidence_bucket = evidence_bucket
        self.s3_client = boto3.client('s3')

    def generate_daily_report(self, date: str = None) -> Dict[str, Any]:
        """
        Generate daily compliance report

        Args:
            date: Date in YYYY-MM-DD format (defaults to today)

        Returns:
            Report dictionary
        """
        if date is None:
            date = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        logger.info(f"Generating daily compliance report for {date}")

        # Load snapshot
        snapshot = self._load_snapshot(date)

        if not snapshot:
            logger.warning(f"No snapshot found for {date}")
            return {}

        # Generate report
        report = {
            "report_id": f"daily-{date}",
            "report_type": "daily_compliance",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "reporting_period": {
                "start": f"{date}T00:00:00Z",
                "end": f"{date}T23:59:59Z"
            },

            "executive_summary": self._generate_executive_summary(snapshot),
            "compliance_details": self._generate_compliance_details(snapshot),
            "top_violations": snapshot.get('top_violations', []),
            "recommendations": self._generate_recommendations(snapshot),

            "metadata": {
                "snapshot_id": snapshot.get('snapshot_id'),
                "evidence_bucket": self.evidence_bucket
            }
        }

        logger.info(f"Daily report generated: {report['report_id']}")
        return report

    def generate_audit_report(self, control_id: str, date_range: tuple = None) -> Dict[str, Any]:
        """
        Generate audit report for specific control

        Args:
            control_id: CIS control ID (e.g., 'CIS-AWS-2.1.4')
            date_range: Tuple of (start_date, end_date) in YYYY-MM-DD format

        Returns:
            Audit report dictionary
        """
        logger.info(f"Generating audit report for {control_id}")

        if date_range is None:
            # Default to last 30 days
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=30)
            date_range = (start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d'))

        # Collect evidence for control
        findings = self._collect_findings_for_control(control_id, date_range)
        remediations = self._collect_remediations_for_control(control_id, date_range)

        report = {
            "report_id": f"audit-{control_id}-{date_range[1]}",
            "report_type": "control_audit",
            "generated_at": datetime.now(timezone.utc).isoformat(),

            "control": {
                "id": control_id,
                "title": findings[0]['control']['title'] if findings else "Unknown",
                "standard": findings[0]['control']['standard'] if findings else "CIS Benchmark",
                "section": findings[0]['control']['section'] if findings else "Unknown"
            },

            "reporting_period": {
                "start": f"{date_range[0]}T00:00:00Z",
                "end": f"{date_range[1]}T23:59:59Z"
            },

            "summary": {
                "total_findings": len(findings),
                "failed_findings": sum(1 for f in findings if f['status'] == 'FAIL'),
                "passed_findings": sum(1 for f in findings if f['status'] == 'PASS'),
                "total_remediations": len(remediations),
                "auto_remediations": sum(1 for r in remediations if r['remediation']['triggered_by'] == 'auto'),
                "manual_remediations": sum(1 for r in remediations if r['remediation']['triggered_by'] == 'manual')
            },

            "findings_detail": self._format_findings_for_audit(findings),
            "remediation_history": self._format_remediations_for_audit(remediations),

            "compliance_timeline": self._generate_compliance_timeline(control_id, date_range),

            "evidence_references": {
                "raw_scans": self._list_scan_evidence(date_range),
                "normalized_findings": f"s3://{self.evidence_bucket}/normalized-findings/",
                "remediation_logs": f"s3://{self.evidence_bucket}/remediations/"
            },

            "auditor_notes": {
                "verification_method": "Automated scanning via InSpec CIS AWS Benchmark profile",
                "scan_frequency": "Hourly for CRITICAL controls",
                "remediation_sla": "4 hours for CRITICAL, 24 hours for HIGH",
                "evidence_retention": "7 years in immutable S3 bucket"
            }
        }

        logger.info(f"Audit report generated for {control_id}")
        logger.info(f"  Total findings: {report['summary']['total_findings']}")
        logger.info(f"  Failed: {report['summary']['failed_findings']}")
        logger.info(f"  Remediations: {report['summary']['total_remediations']}")

        return report

    def generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """
        Generate markdown formatted report

        Args:
            report: Report dictionary

        Returns:
            Markdown string
        """
        if report['report_type'] == 'daily_compliance':
            return self._generate_daily_markdown(report)
        elif report['report_type'] == 'control_audit':
            return self._generate_audit_markdown(report)
        else:
            return "# Unknown Report Type\n"

    def _generate_daily_markdown(self, report: Dict[str, Any]) -> str:
        """Generate daily report in markdown format"""

        md = f"""# Daily Compliance Report

**Report ID**: {report['report_id']}
**Generated**: {report['generated_at']}
**Period**: {report['reporting_period']['start']} to {report['reporting_period']['end']}

---

## Executive Summary

{report['executive_summary']['summary_text']}

### Key Metrics

- **Overall Compliance Score**: {report['executive_summary']['compliance_score']}%
- **Total Controls Checked**: {report['executive_summary']['total_controls']}
- **Controls Passed**: {report['executive_summary']['controls_passed']} ✅
- **Controls Failed**: {report['executive_summary']['controls_failed']} ❌

---

## Compliance by Severity

| Severity | Total | Passed | Failed | Compliance % |
|----------|-------|--------|--------|--------------|
"""

        for severity, stats in report['compliance_details']['by_severity'].items():
            status_icon = "✅" if stats['compliance_percentage'] >= 90 else ("⚠️" if stats['compliance_percentage'] >= 70 else "❌")
            md += f"| **{severity}** {status_icon} | {stats['total']} | {stats['passed']} | {stats['failed']} | {stats['compliance_percentage']}% |\n"

        md += "\n---\n\n"
        md += "## Top Violations\n\n"

        for i, violation in enumerate(report.get('top_violations', [])[:5], 1):
            md += f"### {i}. {violation['title']}\n\n"
            md += f"- **Control ID**: `{violation['control_id']}`\n"
            md += f"- **Severity**: {violation['severity']}\n"
            md += f"- **Affected Resources**: {violation['affected_resources']}\n\n"

        md += "---\n\n"
        md += "## Recommendations\n\n"

        for rec in report.get('recommendations', []):
            md += f"- {rec}\n"

        md += "\n---\n\n"
        md += f"**Evidence Location**: `s3://{self.evidence_bucket}/snapshots/daily/`\n"
        md += f"**Snapshot ID**: `{report['metadata']['snapshot_id']}`\n"

        return md

    def _generate_audit_markdown(self, report: Dict[str, Any]) -> str:
        """Generate audit report in markdown format"""

        md = f"""# Compliance Audit Report

## Control: {report['control']['id']}

**Title**: {report['control']['title']}
**Standard**: {report['control']['standard']}
**Section**: {report['control']['section']}

**Report ID**: {report['report_id']}
**Generated**: {report['generated_at']}
**Period**: {report['reporting_period']['start']} to {report['reporting_period']['end']}

---

## Summary

- **Total Findings**: {report['summary']['total_findings']}
- **Failed Findings**: {report['summary']['failed_findings']} ❌
- **Passed Findings**: {report['summary']['passed_findings']} ✅
- **Total Remediations**: {report['summary']['total_remediations']}
  - Auto-remediated: {report['summary']['auto_remediations']}
  - Manual remediation: {report['summary']['manual_remediations']}

---

## Findings Detail

"""

        for i, finding in enumerate(report['findings_detail'][:10], 1):  # Show first 10
            status_icon = "✅" if finding['status'] == 'PASS' else "❌"
            md += f"### {i}. {status_icon} {finding['resource_name']}\n\n"
            md += f"- **Resource**: `{finding['resource_id']}`\n"
            md += f"- **Status**: {finding['status']}\n"
            md += f"- **Found At**: {finding['timestamp']}\n"

            if finding['status'] == 'FAIL':
                md += f"- **Evidence**: {finding['evidence_message']}\n"

            md += "\n"

        md += "---\n\n"
        md += "## Remediation History\n\n"

        for i, rem in enumerate(report['remediation_history'][:10], 1):  # Show first 10
            md += f"### {i}. Remediation on {rem['completed_at']}\n\n"
            md += f"- **Resource**: `{rem['resource_id']}`\n"
            md += f"- **Method**: {rem['method']}\n"
            md += f"- **Triggered By**: {rem['triggered_by']}\n"
            md += f"- **Duration**: {rem['duration_seconds']}s\n"
            md += f"- **Result**: {'✅ Success' if rem['success'] else '❌ Failed'}\n\n"

        md += "---\n\n"
        md += "## Auditor Notes\n\n"

        for key, value in report['auditor_notes'].items():
            md += f"- **{key.replace('_', ' ').title()}**: {value}\n"

        md += "\n---\n\n"
        md += "## Evidence References\n\n"

        for key, value in report['evidence_references'].items():
            md += f"- **{key.replace('_', ' ').title()}**: `{value}`\n"

        return md

    def save_report(self, report: Dict[str, Any], format: str = 'json'):
        """
        Save report to S3

        Args:
            report: Report dictionary
            format: Output format ('json' or 'markdown')
        """
        report_id = report['report_id']
        report_type = report['report_type']

        # Determine S3 key
        timestamp = datetime.now(timezone.utc)
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')

        if report_type == 'daily_compliance':
            s3_key = f"reports/daily/{year}/{month}/{report_id}.{format}"
        elif report_type == 'control_audit':
            s3_key = f"reports/audit/{year}/{month}/{report_id}.{format}"
        else:
            s3_key = f"reports/other/{year}/{month}/{report_id}.{format}"

        # Convert to appropriate format
        if format == 'json':
            content = json.dumps(report, indent=2, sort_keys=True)
            content_type = 'application/json'
        elif format == 'markdown':
            content = self.generate_markdown_report(report)
            content_type = 'text/markdown'
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Upload to S3
        logger.info(f"Saving report to s3://{self.evidence_bucket}/{s3_key}")

        try:
            self.s3_client.put_object(
                Bucket=self.evidence_bucket,
                Key=s3_key,
                Body=content.encode('utf-8'),
                ContentType=content_type,
                ServerSideEncryption='aws:kms',
                Metadata={
                    'report-id': report_id,
                    'report-type': report_type,
                    'generated-at': timestamp.isoformat()
                }
            )
            logger.info(f"Report saved successfully: {s3_key}")
            return s3_key

        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise

    def _load_snapshot(self, date: str) -> Dict[str, Any]:
        """Load compliance snapshot for date"""
        year, month, day = date.split('-')
        s3_key = f"snapshots/daily/{year}/{month}/snap-{date}-daily.json"

        try:
            response = self.s3_client.get_object(
                Bucket=self.evidence_bucket,
                Key=s3_key
            )
            snapshot = json.loads(response['Body'].read().decode('utf-8'))
            return snapshot

        except Exception as e:
            logger.error(f"Failed to load snapshot: {e}")
            return {}

    def _generate_executive_summary(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from snapshot"""

        overall = snapshot.get('overall', {})
        by_severity = snapshot.get('by_severity', {})

        # Generate summary text
        score = overall.get('compliance_score', 0)

        if score >= 90:
            status = "EXCELLENT"
            trend = "maintaining strong compliance posture"
        elif score >= 75:
            status = "GOOD"
            trend = "compliance is acceptable but has room for improvement"
        elif score >= 60:
            status = "FAIR"
            trend = "requires attention to improve compliance"
        else:
            status = "POOR"
            trend = "immediate action required to address compliance gaps"

        summary_text = f"""
Compliance Status: {status}

The organization's CIS Benchmark compliance score is {score}%, {trend}.
CRITICAL controls are at {by_severity.get('CRITICAL', {}).get('compliance_percentage', 0)}% compliance.
"""

        return {
            "summary_text": summary_text.strip(),
            "compliance_score": score,
            "status": status,
            "total_controls": overall.get('total_controls', 0),
            "controls_passed": overall.get('controls_passed', 0),
            "controls_failed": overall.get('controls_failed', 0)
        }

    def _generate_compliance_details(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed compliance breakdown"""

        return {
            "by_severity": snapshot.get('by_severity', {}),
            "by_standard": snapshot.get('by_standard', {}),
            "by_section": snapshot.get('by_section', {})
        }

    def _generate_recommendations(self, snapshot: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on violations"""

        recommendations = []

        # Check CRITICAL compliance
        critical = snapshot.get('by_severity', {}).get('CRITICAL', {})
        if critical.get('compliance_percentage', 100) < 100:
            recommendations.append(
                f"Address {critical.get('failed', 0)} CRITICAL control failures immediately. "
                "These pose the highest security risk."
            )

        # Check top violations
        top_violations = snapshot.get('top_violations', [])
        if len(top_violations) > 0:
            top = top_violations[0]
            recommendations.append(
                f"Focus on {top['control_id']} ({top['title']}) which affects "
                f"{top['affected_resources']} resources."
            )

        # General recommendations
        recommendations.append(
            "Enable auto-remediation for controls that support it to reduce MTTR."
        )

        recommendations.append(
            "Review exception requests and ensure they have proper justification and expiration dates."
        )

        return recommendations

    def _collect_findings_for_control(self, control_id: str, date_range: tuple) -> List[Dict[str, Any]]:
        """Collect findings for specific control (simplified)"""
        # In real implementation, query S3/Elasticsearch
        return []

    def _collect_remediations_for_control(self, control_id: str, date_range: tuple) -> List[Dict[str, Any]]:
        """Collect remediations for specific control (simplified)"""
        # In real implementation, query S3
        return []

    def _format_findings_for_audit(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings for audit report"""
        return [
            {
                "resource_id": f.get('resource', {}).get('id', 'unknown'),
                "resource_name": f.get('resource', {}).get('name', 'unknown'),
                "status": f.get('status', 'UNKNOWN'),
                "timestamp": f.get('timestamp', ''),
                "evidence_message": f.get('evidence', {}).get('message', '')
            }
            for f in findings
        ]

    def _format_remediations_for_audit(self, remediations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format remediations for audit report"""
        return [
            {
                "resource_id": r.get('resource', {}).get('id', 'unknown'),
                "method": r.get('remediation', {}).get('method', 'unknown'),
                "triggered_by": r.get('remediation', {}).get('triggered_by', 'unknown'),
                "completed_at": r.get('timeline', {}).get('remediation_completed', ''),
                "duration_seconds": r.get('timeline', {}).get('total_duration_seconds', 0),
                "success": r.get('outcome', {}).get('success', False)
            }
            for r in remediations
        ]

    def _generate_compliance_timeline(self, control_id: str, date_range: tuple) -> List[Dict[str, Any]]:
        """Generate compliance timeline (simplified)"""
        return []

    def _list_scan_evidence(self, date_range: tuple) -> str:
        """List scan evidence for date range"""
        return f"s3://{self.evidence_bucket}/raw-scans/inspec/{date_range[0]} to {date_range[1]}"


def main():
    """Main function for testing"""

    import argparse

    parser = argparse.ArgumentParser(description='Generate compliance reports')
    parser.add_argument('--bucket', required=True, help='S3 evidence bucket name')
    parser.add_argument('--type', choices=['daily', 'audit'], default='daily', help='Report type')
    parser.add_argument('--date', help='Date for daily report (YYYY-MM-DD)')
    parser.add_argument('--control', help='Control ID for audit report')
    parser.add_argument('--format', choices=['json', 'markdown'], default='markdown', help='Output format')
    parser.add_argument('--save', action='store_true', help='Save report to S3')

    args = parser.parse_args()

    # Initialize reporter
    reporter = ComplianceReporter(evidence_bucket=args.bucket)

    # Generate report
    if args.type == 'daily':
        report = reporter.generate_daily_report(date=args.date)
    elif args.type == 'audit' and args.control:
        report = reporter.generate_audit_report(control_id=args.control)
    else:
        print("Error: --control required for audit report")
        return

    # Output report
    if args.format == 'json':
        print(json.dumps(report, indent=2))
    elif args.format == 'markdown':
        md = reporter.generate_markdown_report(report)
        print(md)

    # Save to S3
    if args.save and report:
        reporter.save_report(report, format=args.format)


if __name__ == '__main__':
    main()
