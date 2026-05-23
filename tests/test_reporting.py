import pytest
import os
import time
from pathlib import Path
from reporting.pdf_report_generator import PDFReportGenerator
from reporting.markdown_report_generator import MarkdownReportGenerator
from reporting.compliance_reporter import ComplianceReporter
from reporting.incident_exporter import IncidentExporter
from reporting.timeline_reporter import TimelineReporter
from audit.compliance_engine import ComplianceEngine
from storage.audit_store import AuditStore

def test_pdf_report_generation():
    pdf_path = Path("data/reports/test_incident_report.pdf")
    if pdf_path.exists():
        pdf_path.unlink()
        
    report_data = {
        "report_id": "REP-TEST",
        "generated_at": time.time(),
        "summary": {
            "campaign_id": "camp_test_123",
            "attacker_ip": "185.112.144.5",
            "severity": "CRITICAL",
            "risk_score": 95.5,
            "status": "CONTAINED",
            "assigned_analyst": "CISO Agent"
        },
        "timeline": [
            {"timestamp": time.time() - 100, "action": "Anomalous PowerShell execution", "tactic": "Execution"},
            {"timestamp": time.time(), "action": "Host container network socket block", "tactic": "Containment"}
        ],
        "mitigations": [
            {"action_type": "BLOCK_IP", "host_id": "WS-01", "status": "SUCCESS"}
        ],
        "notes": [
            {"author": "analyst", "timestamp": time.time(), "note": "Investigating lateral movements"}
        ]
    }
    
    generator = PDFReportGenerator()
    generator.generate_incident_report(report_data, str(pdf_path))
    
    assert pdf_path.exists() is True
    assert pdf_path.stat().st_size > 0
    
    # Cleanup PDF
    if pdf_path.exists():
        pdf_path.unlink()

def test_pdf_compliance_report_generation():
    pdf_path = Path("data/reports/test_compliance_report.pdf")
    if pdf_path.exists():
        pdf_path.unlink()
        
    compliance_data = {
        "frameworks": {
            "SOC2": {"completed": 4, "total": 5, "score": 0.8, "status": "PARTIALLY_COMPLIANT"},
            "ISO27001": {"completed": 4, "total": 4, "score": 1.0, "status": "COMPLIANT"}
        },
        "gaps": [
            {"control_id": "SOC2-CC6.3", "description": "Continuous monitoring gap", "recommendation": "Deploy sensors"}
        ]
    }
    
    generator = PDFReportGenerator()
    generator.generate_compliance_report(compliance_data, str(pdf_path))
    
    assert pdf_path.exists() is True
    assert pdf_path.stat().st_size > 0
    
    # Cleanup
    if pdf_path.exists():
        pdf_path.unlink()

def test_markdown_report_generation():
    md_path = Path("data/reports/test_incident.md")
    if md_path.exists():
        md_path.unlink()
        
    report_data = {
        "report_id": "REP-TEST",
        "generated_at": time.time(),
        "summary": {
            "campaign_id": "camp_test_123",
            "attacker_ip": "185.112.144.5",
            "severity": "CRITICAL",
            "risk_score": 95.5,
            "status": "CONTAINED",
            "assigned_analyst": "CISO Agent"
        },
        "timeline": [
            {"timestamp": time.time(), "action": "Process block", "tactic": "Defense"}
        ],
        "mitigations": [],
        "notes": []
    }
    
    generator = MarkdownReportGenerator()
    content = generator.generate_incident_markdown(report_data, str(md_path))
    
    assert md_path.exists() is True
    assert "# IMMUNEX" in content
    
    if md_path.exists():
        md_path.unlink()

def test_incident_stix_exporter():
    exporter = IncidentExporter()
    report_data = {
        "campaign_id": "camp_1234",
        "generated_at": time.time(),
        "summary": {
            "attacker_ip": "198.51.100.42",
            "severity": "High",
            "risk_score": 85.0,
            "assigned_analyst": "CISO Agent"
        },
        "mitigations": [
            {"action_type": "BLOCK_IP", "host_id": "WS-01", "status": "SUCCESS"}
        ]
    }
    
    stix = exporter.export_as_stix(report_data)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) > 0
    assert any(obj["type"] == "incident" for obj in stix["objects"])

def test_timeline_reporter():
    reporter = TimelineReporter()
    raw_events = [
        {"timestamp": 2000.0, "action": "Second action", "tactic": "Defense"},
        {"timestamp": 1000.0, "action": "First action", "tactic": "Execution"}
    ]
    
    chain = reporter.build_chronological_chain(raw_events)
    assert len(chain) == 2
    # Check proper sorting
    assert chain[0]["timestamp"] == 1000.0
    assert chain[1]["timestamp"] == 2000.0
    
    text = reporter.render_text_timeline(chain)
    assert "First action" in text
