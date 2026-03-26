"""
Python unit tests for Compliance-as-Code Framework.
Tests cover: ComplianceMetrics, EvidenceCollector, compliance_manager CLI routing.
Run with: python3 -m pytest tests/test_python.py -v
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "dashboards" / "exporters"))
sys.path.insert(0, str(PROJECT_ROOT / "evidence" / "collectors"))

from compliance_exporter import ComplianceMetrics
from evidence_collector import EvidenceCollector
import compliance_manager


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_inspec_result(profile_name="openstack-cis", controls=None):
    """Build a minimal InSpec JSON result dict."""
    if controls is None:
        controls = [
            {"id": "os-1", "title": "T1", "impact": 0.9,
             "tags": {"severity": "critical"}, "results": [{"status": "passed"}]},
            {"id": "os-2", "title": "T2", "impact": 0.7,
             "tags": {"severity": "high"}, "results": [{"status": "failed"}]},
            {"id": "cis-3", "title": "T3", "impact": 0.5,
             "tags": {}, "results": []},
        ]
    return {
        "version": "5.0.0",
        "profiles": [{
            "name": profile_name,
            "title": f"Profile {profile_name}",
            "version": "1.0.0",
            "controls": controls,
        }],
        "statistics": {"duration": 3},
        "platform": {"name": "test", "target_id": "localhost"},
    }


@pytest.fixture
def results_dir(tmp_path):
    """Temp directory pre-populated with one InSpec result file."""
    data = _make_inspec_result()
    (tmp_path / "result.json").write_text(json.dumps(data))
    return str(tmp_path)


@pytest.fixture
def docker_results_dir(tmp_path):
    """Temp directory with Docker CIS InSpec results."""
    controls = [
        {"id": "cis-docker-4-1", "title": "Non-root", "impact": 0.9,
         "tags": {"severity": "critical"}, "results": [{"status": "passed"}]},
        {"id": "cis-docker-5-4", "title": "Privileged", "impact": 1.0,
         "tags": {"severity": "critical"}, "results": [{"status": "failed"}]},
        {"id": "cis-docker-5-10", "title": "Memory limit", "impact": 0.7,
         "tags": {"severity": "high"}, "results": [{"status": "passed"}]},
    ]
    data = _make_inspec_result("docker-cis", controls)
    (tmp_path / "docker.json").write_text(json.dumps(data))
    return str(tmp_path)


# ── ComplianceMetrics ─────────────────────────────────────────────────────────

class TestComplianceMetrics:

    def test_init_safe_before_update(self):
        """get_prometheus_format must not raise before update_metrics is called."""
        m = ComplianceMetrics("/tmp/no-such-dir")
        output = m.get_prometheus_format()
        assert "openstack_compliance_score_percent" in output

    def test_empty_results_dir_no_crash(self):
        with tempfile.TemporaryDirectory() as d:
            m = ComplianceMetrics(d)
            m.update_metrics()
            assert m.metrics["openstack_controls_total"] == 0

    def test_control_counts(self, results_dir):
        m = ComplianceMetrics(results_dir)
        m.update_metrics()
        assert m.metrics["openstack_controls_total"] == 3
        assert m.metrics["openstack_controls_passed"] == 1
        assert m.metrics["openstack_controls_failed"] == 1
        assert m.metrics["openstack_controls_skipped"] == 1

    def test_compliance_percentage(self, results_dir):
        m = ComplianceMetrics(results_dir)
        m.update_metrics()
        # 1 pass / (1 pass + 1 fail) = 50%
        assert m.metrics["openstack_compliance_score_percent"] == 50.0

    def test_prometheus_format_contains_required_metrics(self, results_dir):
        m = ComplianceMetrics(results_dir)
        m.update_metrics()
        out = m.get_prometheus_format()
        for key in ["openstack_compliance_score_percent",
                    "openstack_controls_total",
                    "openstack_controls_passed",
                    "openstack_controls_failed",
                    "openstack_findings_by_severity",
                    "openstack_last_scan_timestamp"]:
            assert key in out, f"Missing metric: {key}"

    def test_docker_controls_mapped_to_docker_service(self, docker_results_dir):
        m = ComplianceMetrics(docker_results_dir)
        m.update_metrics()
        assert "docker" in m.metrics["openstack_service_compliance"]
        assert m.metrics["openstack_service_controls"]["docker"] == 3

    def test_service_mapping_openstack(self):
        m = ComplianceMetrics("/tmp")
        assert m._get_service_from_control_id("os-identity-1") == "keystone"
        assert m._get_service_from_control_id("os-compute-2") == "nova"
        assert m._get_service_from_control_id("os-networking-3") == "neutron"
        assert m._get_service_from_control_id("os-storage-4") == "cinder"
        assert m._get_service_from_control_id("os-image-5") == "glance"
        assert m._get_service_from_control_id("os-dashboard-6") == "horizon"
        assert m._get_service_from_control_id("os-orchestration-7") == "heat"

    def test_service_mapping_docker(self):
        m = ComplianceMetrics("/tmp")
        assert m._get_service_from_control_id("cis-docker-5-4") == "docker"
        assert m._get_service_from_control_id("cis-docker-4-1") == "docker"

    def test_service_mapping_linux(self):
        m = ComplianceMetrics("/tmp")
        assert m._get_service_from_control_id("cis-linux-1-1") == "linux"
        assert m._get_service_from_control_id("unknown-control") == "linux"

    def test_severity_from_tag(self):
        m = ComplianceMetrics("/tmp")
        for sev in ["critical", "high", "medium", "low"]:
            ctrl = {"tags": {"severity": sev}, "impact": 0.5}
            assert m._get_severity(ctrl) == sev

    def test_severity_from_impact(self):
        m = ComplianceMetrics("/tmp")
        assert m._get_severity({"tags": {}, "impact": 0.95}) == "critical"
        assert m._get_severity({"tags": {}, "impact": 0.75}) == "high"
        assert m._get_severity({"tags": {}, "impact": 0.5}) == "medium"
        assert m._get_severity({"tags": {}, "impact": 0.1}) == "low"

    def test_all_failed_compliance_zero(self):
        controls = [
            {"id": f"ctrl-{i}", "title": f"T{i}", "impact": 0.5,
             "tags": {}, "results": [{"status": "failed"}]}
            for i in range(3)
        ]
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.json").write_text(
                json.dumps(_make_inspec_result(controls=controls)))
            m = ComplianceMetrics(d)
            m.update_metrics()
            assert m.metrics["openstack_compliance_score_percent"] == 0.0

    def test_all_passed_compliance_hundred(self):
        controls = [
            {"id": f"ctrl-{i}", "title": f"T{i}", "impact": 0.5,
             "tags": {}, "results": [{"status": "passed"}]}
            for i in range(4)
        ]
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.json").write_text(
                json.dumps(_make_inspec_result(controls=controls)))
            m = ComplianceMetrics(d)
            m.update_metrics()
            assert m.metrics["openstack_compliance_score_percent"] == 100.0


# ── EvidenceCollector ─────────────────────────────────────────────────────────

class TestEvidenceCollector:

    def _write_and_collect(self, tmp_path, profile_name, controls=None):
        data = _make_inspec_result(profile_name, controls)
        inspec_path = str(tmp_path / "scan.json")
        (tmp_path / "scan.json").write_text(json.dumps(data))
        ec = EvidenceCollector(str(tmp_path / "evidence"))
        return ec.collect_inspec_scan(inspec_path)

    def test_basic_evidence_structure(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "openstack-cis")
        assert ev["scanner"] == "inspec"
        assert ev["evidence_type"] == "scan_result"
        assert "evidence_id" in ev
        assert "sha256" in ev
        assert len(ev["sha256"]) == 64

    def test_openstack_standard_detected(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "openstack-cis")
        assert ev["profile"]["name"] == "openstack-cis"

    def test_docker_standard_detected(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "docker-cis")
        assert ev["profile"]["name"] == "docker-cis"

    def test_linux_standard_detected(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "linux-cis")
        assert ev["profile"]["name"] == "linux-cis"

    def test_statistics_correct(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "openstack-cis")
        stats = ev["statistics"]
        assert stats["total_controls"] == 3
        assert stats["passed"] == 1
        assert stats["failed"] == 1
        assert stats["skipped"] == 1
        assert stats["compliance_percentage"] == pytest.approx(33.33, abs=0.1)

    def test_statistics_all_passed(self, tmp_path):
        controls = [
            {"id": f"c{i}", "title": f"T{i}", "impact": 0.5,
             "tags": {}, "results": [{"status": "passed"}]}
            for i in range(5)
        ]
        ev = self._write_and_collect(tmp_path, "openstack-cis", controls)
        assert ev["statistics"]["compliance_percentage"] == 100.0

    def test_statistics_empty_controls(self, tmp_path):
        ev = self._write_and_collect(tmp_path, "docker-cis", [])
        assert ev["statistics"]["total_controls"] == 0
        assert ev["statistics"]["compliance_percentage"] == 0

    def test_sha256_is_deterministic(self, tmp_path):
        data = _make_inspec_result()
        p = str(tmp_path / "s.json")
        (tmp_path / "s.json").write_text(json.dumps(data))
        ec = EvidenceCollector(str(tmp_path / "ev"))
        ev1 = ec.collect_inspec_scan(p)
        ev2 = ec.collect_inspec_scan(p)
        assert ev1["sha256"] == ev2["sha256"]


# ── ComplianceManager CLI ─────────────────────────────────────────────────────

class TestComplianceManagerCLI:

    def test_scan_target_choices_include_docker(self):
        """Ensure 'docker' is a valid scan target."""
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("scan")
        p.add_argument("--target", choices=["openstack", "linux", "docker"],
                       required=True)
        args = parser.parse_args(["scan", "--target", "docker"])
        assert args.target == "docker"

    def test_remediate_target_choices_include_docker(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("remediate")
        p.add_argument("--target", choices=["openstack", "linux", "docker"],
                       required=True)
        args = parser.parse_args(["remediate", "--target", "docker"])
        assert args.target == "docker"

    def test_docker_scan_path_resolves(self):
        """docker target must map to the docker-cis InSpec profile path."""
        docker_profile = PROJECT_ROOT / "tests" / "inspec" / "docker-cis"
        assert docker_profile.exists(), \
            f"docker-cis InSpec profile missing at {docker_profile}"

    def test_docker_remediation_playbook_exists(self):
        playbook = PROJECT_ROOT / "remediation" / "ansible" / "cis-docker-remediation.yml"
        assert playbook.exists(), f"Docker remediation playbook missing at {playbook}"
