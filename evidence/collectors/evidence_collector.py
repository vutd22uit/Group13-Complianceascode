#!/usr/bin/env python3
"""
Evidence Collector for OpenStack CIS Benchmark Compliance

This script collects, normalizes, and stores compliance evidence
from various scanners (InSpec, OpenSCAP, Ansible).
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Collects and processes OpenStack compliance evidence"""

    def __init__(self, evidence_path: str = None):
        """
        Initialize evidence collector

        Args:
            evidence_path: Local path for evidence storage (default: ./evidence_store)
        """
        self.evidence_path = evidence_path or os.path.join(os.getcwd(), 'evidence_store')
        Path(self.evidence_path).mkdir(parents=True, exist_ok=True)

    def collect_inspec_scan(self, inspec_json_path: str) -> Dict[str, Any]:
        """
        Collect InSpec scan results and create evidence

        Args:
            inspec_json_path: Path to InSpec JSON output file

        Returns:
            Evidence dictionary
        """
        logger.info(f"Collecting InSpec scan from {inspec_json_path}")

        with open(inspec_json_path, 'r') as f:
            inspec_data = json.load(f)

        # Create evidence ID
        evidence_id = self._generate_evidence_id('inspec')

        # Calculate SHA-256
        content_hash = self._calculate_hash(json.dumps(inspec_data, sort_keys=True))

        # Determine profile type
        profile_name = inspec_data.get('profiles', [{}])[0].get('name', 'unknown')
        
        if 'openstack' in profile_name.lower():
            standard = 'CIS OpenStack Foundations Benchmark'
        elif 'linux' in profile_name.lower():
            standard = 'CIS Linux Benchmark'
        else:
            standard = 'CIS Benchmark'

        # Create evidence structure
        evidence = {
            "evidence_type": "scan_result",
            "evidence_id": evidence_id,
            "scanner": "inspec",
            "scanner_version": inspec_data.get('version', 'unknown'),
            "profile": {
                "name": profile_name,
                "version": inspec_data.get('profiles', [{}])[0].get('version', '1.0.0'),
                "title": inspec_data.get('profiles', [{}])[0].get('title', standard)
            },
            "target": {
                "platform": "openstack",
                "hostname": inspec_data.get('platform', {}).get('name', 'unknown'),
                "target_id": inspec_data.get('platform', {}).get('target_id', 'unknown')
            },
            "scan_metadata": {
                "start_time": inspec_data.get('statistics', {}).get('start_time', datetime.now(timezone.utc).isoformat()),
                "duration_seconds": inspec_data.get('statistics', {}).get('duration', 0)
            },
            "statistics": self._calculate_statistics(inspec_data),
            "controls": inspec_data.get('profiles', [{}])[0].get('controls', []),
            "sha256": content_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"InSpec evidence collected: {evidence_id}")
        logger.info(f"  Controls: {evidence['statistics']['total_controls']}")
        logger.info(f"  Passed: {evidence['statistics']['passed']}")
        logger.info(f"  Failed: {evidence['statistics']['failed']}")

        return evidence

    def _calculate_statistics(self, inspec_data: Dict[str, Any]) -> Dict[str, int]:
        """Calculate control statistics from InSpec data"""
        controls = inspec_data.get('profiles', [{}])[0].get('controls', [])
        
        passed = 0
        failed = 0
        skipped = 0
        
        for control in controls:
            results = control.get('results', [])
            if not results:
                skipped += 1
                continue
            
            # Check if any result failed
            has_failure = any(r.get('status') == 'failed' for r in results)
            has_pass = any(r.get('status') == 'passed' for r in results)
            
            if has_failure:
                failed += 1
            elif has_pass:
                passed += 1
            else:
                skipped += 1
        
        return {
            "total_controls": len(controls),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "compliance_percentage": round((passed / len(controls) * 100), 2) if controls else 0
        }

    def normalize_findings(self, raw_evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize raw scan results to canonical finding format

        Args:
            raw_evidence: Raw evidence dictionary

        Returns:
            List of normalized findings
        """
        logger.info(f"Normalizing findings from {raw_evidence['evidence_id']}")

        normalized_findings = []
        scanner = raw_evidence['scanner']

        if scanner == 'inspec':
            normalized_findings = self._normalize_inspec(raw_evidence)
        elif scanner == 'openscap':
            normalized_findings = self._normalize_openscap(raw_evidence)
        else:
            logger.warning(f"Unknown scanner type: {scanner}")

        logger.info(f"Normalized {len(normalized_findings)} findings")
        return normalized_findings

    def _normalize_inspec(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize InSpec evidence to canonical format"""

        findings = []

        for control in evidence.get('controls', []):
            for result in control.get('results', []):
                if result.get('status') in ['failed', 'passed']:
                    # Determine control category
                    control_id = control.get('id', 'unknown')
                    
                    if control_id.startswith('os-identity'):
                        section = '1. Identity (Keystone)'
                        service = 'keystone'
                    elif control_id.startswith('os-compute'):
                        section = '2. Compute (Nova)'
                        service = 'nova'
                    elif control_id.startswith('os-networking'):
                        section = '3. Networking (Neutron)'
                        service = 'neutron'
                    elif control_id.startswith('os-storage'):
                        section = '4. Storage (Cinder/Swift)'
                        service = 'cinder'
                    elif control_id.startswith('os-image'):
                        section = '5. Image (Glance)'
                        service = 'glance'
                    elif control_id.startswith('os-dashboard'):
                        section = '6. Dashboard (Horizon)'
                        service = 'horizon'
                    elif control_id.startswith('os-orchestration'):
                        section = '7. Orchestration (Heat)'
                        service = 'heat'
                    elif control_id.startswith('cis-'):
                        section = 'Linux CIS Benchmark'
                        service = 'linux'
                    else:
                        section = 'Other'
                        service = 'unknown'

                    finding = {
                        "finding_id": self._generate_finding_id(),
                        "evidence_id": evidence['evidence_id'],
                        "timestamp": datetime.now(timezone.utc).isoformat(),

                        "control": {
                            "id": control_id,
                            "title": control.get('title', ''),
                            "standard": control.get('tags', {}).get('standard', 'CIS OpenStack Benchmark'),
                            "section": section,
                            "description": control.get('desc', '')
                        },

                        "severity": self._determine_severity(control),
                        "status": "FAIL" if result.get('status') == 'failed' else "PASS",

                        "resource": {
                            "type": service,
                            "id": result.get('resource', 'unknown'),
                            "config_file": self._extract_config_file(result.get('resource', '')),
                            "hostname": evidence.get('target', {}).get('hostname', 'unknown')
                        },

                        "evidence": {
                            "scanner": "inspec",
                            "message": result.get('message', ''),
                            "code_desc": result.get('code_desc', ''),
                            "actual_value": self._extract_actual_value(result),
                            "expected_value": self._extract_expected_value(result)
                        },

                        "remediation": {
                            "available": self._is_auto_remediable(control_id),
                            "method": self._get_remediation_method(control_id),
                            "playbook": self._get_remediation_playbook(control_id),
                            "status": "pending"
                        },

                        "metadata": {
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                            "false_positive": False,
                            "exception_id": None
                        }
                    }

                    findings.append(finding)

        return findings

    def _normalize_openscap(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize OpenSCAP evidence to canonical format"""
        findings = []
        # Implementation for OpenSCAP normalization
        return findings

    def _determine_severity(self, control: Dict[str, Any]) -> str:
        """Determine severity from control tags or impact"""
        severity = control.get('tags', {}).get('severity', '').upper()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            return severity
        
        impact = control.get('impact', 0.5)
        if impact >= 0.9:
            return 'CRITICAL'
        elif impact >= 0.7:
            return 'HIGH'
        elif impact >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _extract_config_file(self, resource: str) -> str:
        """Extract config file path from resource"""
        if '/etc/' in resource:
            return resource
        elif 'keystone' in resource.lower():
            return '/etc/keystone/keystone.conf'
        elif 'nova' in resource.lower():
            return '/etc/nova/nova.conf'
        elif 'neutron' in resource.lower():
            return '/etc/neutron/neutron.conf'
        elif 'cinder' in resource.lower():
            return '/etc/cinder/cinder.conf'
        else:
            return 'unknown'

    def _extract_actual_value(self, result: Dict[str, Any]) -> Any:
        """Extract actual value from result"""
        message = result.get('message', '')
        # Parse message to extract actual value
        return message

    def _extract_expected_value(self, result: Dict[str, Any]) -> Any:
        """Extract expected value from result"""
        code_desc = result.get('code_desc', '')
        # Parse code_desc to extract expected value
        return code_desc

    def store_evidence(self, evidence: Dict[str, Any], evidence_type: str) -> str:
        """
        Store evidence to local filesystem

        Args:
            evidence: Evidence dictionary
            evidence_type: Type of evidence (raw-scans, normalized-findings, etc.)

        Returns:
            Path to stored evidence file
        """
        timestamp = datetime.now(timezone.utc)
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')

        scanner = evidence.get('scanner', 'unknown')
        evidence_id = evidence.get('evidence_id', 'unknown')

        # Build path
        evidence_dir = Path(self.evidence_path) / evidence_type / scanner / year / month / day
        evidence_dir.mkdir(parents=True, exist_ok=True)

        file_path = evidence_dir / f"{evidence_id}.json"

        logger.info(f"Storing evidence to {file_path}")

        # Convert to JSON and save
        with open(file_path, 'w') as f:
            json.dump(evidence, f, indent=2, sort_keys=True)

        logger.info(f"Evidence stored successfully: {file_path}")
        return str(file_path)

    def store_normalized_findings(self, findings: List[Dict[str, Any]]) -> str:
        """
        Store normalized findings as NDJSON

        Args:
            findings: List of normalized finding dictionaries

        Returns:
            Path to stored findings file
        """
        if not findings:
            logger.warning("No findings to store")
            return ""

        timestamp = datetime.now(timezone.utc)
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')
        hour = timestamp.strftime('%H')
        minute = timestamp.strftime('%M')

        # Build path
        findings_dir = Path(self.evidence_path) / "normalized-findings" / year / month / day
        findings_dir.mkdir(parents=True, exist_ok=True)

        file_path = findings_dir / f"findings-{year}-{month}-{day}-{hour}-{minute}.ndjson"

        logger.info(f"Storing {len(findings)} normalized findings to {file_path}")

        # Convert to NDJSON
        with open(file_path, 'w') as f:
            for finding in findings:
                f.write(json.dumps(finding, sort_keys=True) + '\n')

        logger.info(f"Normalized findings stored successfully: {file_path}")
        return str(file_path)

    def create_compliance_snapshot(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create compliance snapshot from current findings

        Args:
            findings: List of current findings

        Returns:
            Compliance snapshot dictionary
        """
        logger.info(f"Creating compliance snapshot from {len(findings)} findings")

        if not findings:
            return {}

        total_controls = len(set(f['control']['id'] for f in findings))
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')

        snapshot = {
            "snapshot_id": self._generate_snapshot_id(),
            "snapshot_type": "daily",
            "platform": "openstack",
            "timestamp": datetime.now(timezone.utc).isoformat(),

            "overall": {
                "compliance_score": round((passed / len(findings) * 100), 2) if findings else 0,
                "total_controls": total_controls,
                "controls_passed": passed,
                "controls_failed": failed
            },

            "by_severity": self._calculate_by_severity(findings),
            "by_section": self._calculate_by_section(findings),
            "top_violations": self._get_top_violations(findings, limit=10)
        }

        logger.info(f"Snapshot created: {snapshot['snapshot_id']}")
        logger.info(f"  Compliance Score: {snapshot['overall']['compliance_score']}%")

        return snapshot

    def _calculate_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance by severity level"""
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        by_severity = {}

        for severity in severities:
            severity_findings = [f for f in findings if f['severity'] == severity]
            total = len(severity_findings)
            passed = sum(1 for f in severity_findings if f['status'] == 'PASS')

            by_severity[severity] = {
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "compliance_percentage": round((passed / total * 100), 2) if total > 0 else 0
            }

        return by_severity

    def _calculate_by_section(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance by section"""
        by_section = {}

        for finding in findings:
            section = finding['control']['section']
            if section not in by_section:
                by_section[section] = {"total": 0, "passed": 0, "failed": 0}

            by_section[section]['total'] += 1
            if finding['status'] == 'PASS':
                by_section[section]['passed'] += 1
            else:
                by_section[section]['failed'] += 1

        # Calculate percentages
        for section in by_section:
            total = by_section[section]['total']
            passed = by_section[section]['passed']
            by_section[section]['compliance_percentage'] = round((passed / total * 100), 2) if total > 0 else 0

        return by_section

    def _get_top_violations(self, findings: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top violations by occurrence count"""
        violations = {}
        for f in findings:
            if f['status'] == 'FAIL':
                control_id = f['control']['id']
                if control_id not in violations:
                    violations[control_id] = {
                        "control_id": control_id,
                        "title": f['control']['title'],
                        "severity": f['severity'],
                        "section": f['control']['section'],
                        "affected_resources": 0
                    }
                violations[control_id]['affected_resources'] += 1

        top_violations = sorted(violations.values(), key=lambda x: x['affected_resources'], reverse=True)
        return top_violations[:limit]

    @staticmethod
    def _generate_evidence_id(scanner: str) -> str:
        """Generate unique evidence ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        return f"scan-{timestamp}-{scanner}-{unique_id}"

    @staticmethod
    def _generate_finding_id() -> str:
        """Generate unique finding ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        return f"find-{timestamp}-{unique_id}"

    @staticmethod
    def _generate_snapshot_id() -> str:
        """Generate snapshot ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
        return f"snap-{timestamp}-daily"

    @staticmethod
    def _calculate_hash(content: str) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    @staticmethod
    def _is_auto_remediable(control_id: str) -> bool:
        """Check if control has auto-remediation available"""
        auto_remediable_controls = [
            'os-identity-1.1',   # Keystone file permissions
            'os-identity-1.2',
            'os-compute-2.1',    # Nova file permissions
            'os-compute-2.2',
            'os-networking-3.1', # Neutron file permissions
            'os-networking-3.2',
            'os-storage-4.1',    # Cinder file permissions
            'os-storage-4.2',
        ]
        return control_id in auto_remediable_controls

    @staticmethod
    def _get_remediation_method(control_id: str) -> str:
        """Get remediation method for control"""
        if control_id.startswith('os-'):
            return 'ansible'
        elif control_id.startswith('cis-'):
            return 'ansible'
        else:
            return 'manual'

    @staticmethod
    def _get_remediation_playbook(control_id: str) -> str:
        """Get remediation playbook for control"""
        if control_id.startswith('os-'):
            return 'remediation/ansible/cis-openstack-remediation.yml'
        elif control_id.startswith('cis-'):
            return 'remediation/ansible/cis-linux-remediation.yml'
        else:
            return ''


def main():
    """Main function for testing"""
    import argparse

    parser = argparse.ArgumentParser(description='Collect OpenStack compliance evidence')
    parser.add_argument('--inspec-json', help='Path to InSpec JSON output')
    parser.add_argument('--evidence-path', default='./evidence_store', help='Local evidence storage path')
    parser.add_argument('--store', action='store_true', help='Store evidence locally')

    args = parser.parse_args()

    # Initialize collector
    collector = EvidenceCollector(evidence_path=args.evidence_path)

    # Collect InSpec scan
    if args.inspec_json:
        evidence = collector.collect_inspec_scan(args.inspec_json)

        # Normalize findings
        findings = collector.normalize_findings(evidence)

        # Store evidence
        if args.store:
            collector.store_evidence(evidence, 'raw-scans')
            collector.store_normalized_findings(findings)

            # Create snapshot
            snapshot = collector.create_compliance_snapshot(findings)
            collector.store_evidence(snapshot, 'snapshots/daily')

        # Print summary
        print(f"\n{'='*60}")
        print(f"OpenStack Compliance Evidence Collection Summary")
        print(f"{'='*60}")
        print(f"Evidence ID: {evidence['evidence_id']}")
        print(f"Platform: OpenStack")
        print(f"Total Controls: {evidence['statistics']['total_controls']}")
        print(f"Passed: {evidence['statistics']['passed']}")
        print(f"Failed: {evidence['statistics']['failed']}")
        print(f"Compliance: {evidence['statistics']['compliance_percentage']}%")
        print(f"Normalized Findings: {len(findings)}")
        print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
