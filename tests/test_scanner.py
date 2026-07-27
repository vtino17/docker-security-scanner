import json
import sys
import os
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from dss.scanner import ContainerFinding, ScanResult, scan_container


def test_container_finding_defaults():
    f = ContainerFinding(check="test", status="OK", severity="INFO", detail="x", recommendation="")
    assert f.check == "test"
    assert f.severity == "INFO"


def test_scan_result_initial_healthy():
    r = ScanResult(container_id="abc123", image="nginx:latest")
    assert r.healthy is True
    assert len(r.findings) == 0


def test_scan_result_critical_marks_unhealthy():
    r = ScanResult(container_id="abc", image="img")
    r.add(ContainerFinding(check="priv", status="PRIVILEGED", severity="CRITICAL", detail="", recommendation=""))
    assert r.healthy is False


def test_scan_result_high_marks_unhealthy():
    r = ScanResult(container_id="abc", image="img")
    r.add(ContainerFinding(check="root", status="ROOT", severity="HIGH", detail="", recommendation=""))
    assert r.healthy is False


def test_scan_result_pass_keeps_healthy():
    r = ScanResult(container_id="abc", image="img")
    r.add(ContainerFinding(check="test", status="OK", severity="PASS", detail="", recommendation=""))
    assert r.healthy is True


def test_scan_result_low_keeps_healthy():
    r = ScanResult(container_id="abc", image="img")
    r.add(ContainerFinding(check="test", status="STOPPED", severity="LOW", detail="", recommendation=""))
    assert r.healthy is True


def test_scan_result_medium_keeps_healthy():
    r = ScanResult(container_id="abc", image="img")
    r.add(ContainerFinding(check="test", status="CAPS", severity="MEDIUM", detail="", recommendation=""))
    assert r.healthy is True


def test_scan_container_no_docker():
    with patch("dss.scanner._run_json", return_value=[]):
        r = scan_container("nonexistent")
    assert r.healthy is False
    assert r.image == "unknown"


def test_scan_container_mocked_inspect():
    mock_inspect = [{
        "State": {"Status": "running", "Running": True},
        "Config": {"Image": "nginx:latest", "User": ""},
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "default",
            "CapAdd": [],
            "Binds": ["/host/data:/data"],
            "Memory": 0,
            "CpuShares": 0,
            "CpuQuota": 0,
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {}
        }
    }]
    def fake_run_json(cmd):
        return mock_inspect if "inspect" in cmd else []

    with patch("dss.scanner._run_json", side_effect=fake_run_json):
        r = scan_container("test123")

    assert r.image == "nginx:latest"
    severities = {f.severity for f in r.findings}
    assert "HIGH" in severities
    assert "INFO" in severities
