"""
IMMUNEX Compliance Control Mapper
===================================
Phase 5 — Maps threat detections to SOC2, ISO27001, NIST 800-53, PCI-DSS, HIPAA controls.

Full offline control databases with remediation guidance.
Air-gapped & CPU-only compatible. Zero external dependencies.
"""

from __future__ import annotations

from typing import Any

from utils.logger import log


# ─── Compliance Framework Databases ──────────────────────────────────────────

_CONTROLS = {
    "SOC2": [
        {"control_id": "CC6.1", "control_name": "Logical and Physical Access Controls", "description": "Restrict access to information assets.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement MFA, review access policies, enforce least-privilege."},
        {"control_id": "CC6.2", "control_name": "System Access Authorization", "description": "Authorize system access before granting.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Review user provisioning, implement access request workflows."},
        {"control_id": "CC6.3", "control_name": "Access Removal", "description": "Remove access when no longer needed.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Automate deprovisioning, audit dormant accounts."},
        {"control_id": "CC6.6", "control_name": "System Boundaries", "description": "Restrict transmission of data outside system boundaries.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement DLP, monitor egress traffic, block unauthorized transfers."},
        {"control_id": "CC6.8", "control_name": "Malicious Software Prevention", "description": "Implement controls to prevent malicious software.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Deploy EDR, update signatures, enable behavioral detection."},
        {"control_id": "CC7.1", "control_name": "Monitoring Activities", "description": "Monitor system components for anomalies.", "severity_mapping": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Deploy SIEM, configure alert thresholds, review monitoring gaps."},
        {"control_id": "CC7.2", "control_name": "Anomaly Detection", "description": "Identify and report security anomalies.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Tune anomaly detection models, reduce false positives, escalation procedures."},
        {"control_id": "CC7.3", "control_name": "Incident Response", "description": "Respond to identified security incidents.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Activate IR playbook, contain threat, notify stakeholders."},
        {"control_id": "CC7.4", "control_name": "Incident Recovery", "description": "Recover from identified security incidents.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Execute recovery procedures, validate system integrity, post-mortem."},
        {"control_id": "CC8.1", "control_name": "Change Management", "description": "Authorize and test changes before implementation.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Review change management process, validate pre-deployment testing."},
    ],
    "ISO27001": [
        {"control_id": "A.5.1", "control_name": "Information Security Policies", "description": "Policies for information security.", "severity_mapping": ["LOW", "MEDIUM"], "remediation_guidance": "Review and update security policies annually."},
        {"control_id": "A.6.1", "control_name": "Organization of Information Security", "description": "Internal organization security framework.", "severity_mapping": ["MEDIUM"], "remediation_guidance": "Define security roles and responsibilities clearly."},
        {"control_id": "A.8.1", "control_name": "Asset Management", "description": "Identify and manage information assets.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Maintain asset inventory, classify data sensitivity."},
        {"control_id": "A.9.1", "control_name": "Access Control Policy", "description": "Business requirements for access control.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Enforce role-based access, review permissions quarterly."},
        {"control_id": "A.9.4", "control_name": "System Access Control", "description": "Prevent unauthorized system access.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement strong authentication, session management."},
        {"control_id": "A.12.2", "control_name": "Protection from Malware", "description": "Ensure protection against malware.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Update AV/EDR, restrict executable execution."},
        {"control_id": "A.12.4", "control_name": "Logging and Monitoring", "description": "Record and monitor activities.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Centralize logging, set retention policies, review logs."},
        {"control_id": "A.13.1", "control_name": "Network Security Management", "description": "Manage and control networks.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Segment networks, deploy IDS/IPS, monitor traffic."},
        {"control_id": "A.16.1", "control_name": "Incident Management", "description": "Consistent approach to security incidents.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Maintain IR plan, conduct tabletop exercises, document incidents."},
        {"control_id": "A.18.2", "control_name": "Information Security Reviews", "description": "Independent review of security approach.", "severity_mapping": ["LOW", "MEDIUM"], "remediation_guidance": "Schedule regular security audits and penetration tests."},
    ],
    "NIST_800_53": [
        {"control_id": "AC-2", "control_name": "Account Management", "description": "Manage information system accounts.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Review accounts, disable inactive, enforce policies."},
        {"control_id": "AC-3", "control_name": "Access Enforcement", "description": "Enforce approved authorizations.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement RBAC, verify access controls."},
        {"control_id": "AU-6", "control_name": "Audit Record Review", "description": "Review and analyze audit records.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Automate log analysis, correlate events across sources."},
        {"control_id": "CA-7", "control_name": "Continuous Monitoring", "description": "Develop continuous monitoring strategy.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Deploy real-time monitoring, track security metrics."},
        {"control_id": "IR-4", "control_name": "Incident Handling", "description": "Implement incident handling capability.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Follow NIST IR lifecycle: prep, detect, contain, eradicate, recover."},
        {"control_id": "IR-5", "control_name": "Incident Monitoring", "description": "Track and document incidents.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Log all incidents, track resolution metrics."},
        {"control_id": "RA-5", "control_name": "Vulnerability Monitoring", "description": "Monitor and remediate vulnerabilities.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Run regular vulnerability scans, prioritize patching."},
        {"control_id": "SC-7", "control_name": "Boundary Protection", "description": "Monitor and control network boundaries.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Deploy firewalls, configure egress filtering."},
        {"control_id": "SI-3", "control_name": "Malicious Code Protection", "description": "Implement malicious code protection.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Deploy EDR/AV, enable real-time scanning."},
        {"control_id": "SI-4", "control_name": "System Monitoring", "description": "Monitor the information system.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Deploy IDS/IPS, SIEM, behavioral analytics."},
    ],
    "PCI_DSS": [
        {"control_id": "1.1", "control_name": "Firewall Configuration Standards", "description": "Establish firewall and router configuration standards.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Review firewall rules, restrict inbound/outbound traffic."},
        {"control_id": "2.1", "control_name": "Vendor Default Passwords", "description": "Change vendor-supplied defaults.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Change all default passwords, disable unnecessary accounts."},
        {"control_id": "3.4", "control_name": "PAN Rendering Unreadable", "description": "Render PAN unreadable during storage.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Encrypt stored cardholder data, use tokenization."},
        {"control_id": "5.1", "control_name": "Anti-virus Software", "description": "Deploy anti-virus on all systems.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Ensure AV is deployed, updated, and generating logs."},
        {"control_id": "6.5", "control_name": "Secure Coding", "description": "Develop applications based on secure coding guidelines.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Train developers, conduct code reviews, SAST/DAST."},
        {"control_id": "7.1", "control_name": "Access Control Systems", "description": "Limit access to system components.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement need-to-know access, review ACLs."},
        {"control_id": "8.2", "control_name": "User Authentication", "description": "Proper user identification and authentication.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Enforce MFA, strong passwords, account lockout."},
        {"control_id": "10.2", "control_name": "Audit Trails", "description": "Implement automated audit trails.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Log all access to cardholder data environments."},
        {"control_id": "11.4", "control_name": "IDS/IPS", "description": "Use IDS/IPS to detect intrusions.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Deploy and tune IDS/IPS, review alerts daily."},
        {"control_id": "12.10", "control_name": "Incident Response Plan", "description": "Implement an incident response plan.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Maintain IR plan, test annually, train staff."},
    ],
    "HIPAA": [
        {"control_id": "164.308(a)(1)", "control_name": "Security Management Process", "description": "Implement security management process.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Conduct risk analysis, implement security measures."},
        {"control_id": "164.308(a)(3)", "control_name": "Workforce Security", "description": "Implement workforce security policies.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Background checks, access authorization procedures."},
        {"control_id": "164.308(a)(4)", "control_name": "Information Access Management", "description": "Implement access management policies.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Role-based access, access review, least privilege."},
        {"control_id": "164.308(a)(5)", "control_name": "Security Awareness Training", "description": "Security awareness and training program.", "severity_mapping": ["LOW", "MEDIUM"], "remediation_guidance": "Conduct regular security training, phishing simulations."},
        {"control_id": "164.308(a)(6)", "control_name": "Security Incident Procedures", "description": "Implement security incident procedures.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Document IR procedures, report breaches within 60 days."},
        {"control_id": "164.310(a)(1)", "control_name": "Facility Access Controls", "description": "Limit physical access to facilities.", "severity_mapping": ["MEDIUM", "HIGH"], "remediation_guidance": "Implement badge access, visitor logs, surveillance."},
        {"control_id": "164.312(a)(1)", "control_name": "Access Control", "description": "Technical access controls for ePHI.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Unique user IDs, emergency access procedures, encryption."},
        {"control_id": "164.312(b)", "control_name": "Audit Controls", "description": "Implement audit controls for ePHI systems.", "severity_mapping": ["MEDIUM", "HIGH", "CRITICAL"], "remediation_guidance": "Log access to PHI systems, review audit logs."},
        {"control_id": "164.312(c)(1)", "control_name": "Integrity Controls", "description": "Protect ePHI from improper alteration.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Implement data integrity checks, digital signatures."},
        {"control_id": "164.312(e)(1)", "control_name": "Transmission Security", "description": "Protect ePHI during transmission.", "severity_mapping": ["HIGH", "CRITICAL"], "remediation_guidance": "Encrypt data in transit, use TLS/VPN."},
    ],
}


class ComplianceControlMapper:
    """Maps threat detections to compliance framework controls."""

    def __init__(self):
        self._controls = _CONTROLS
        log.info("ComplianceControlMapper initialized",
                 frameworks=list(self._controls.keys()))

    def map_threat(self, decision) -> dict:
        """
        Maps a DetectionDecision to relevant controls across all frameworks.
        """
        severity = getattr(decision, "severity", "MEDIUM")
        matched = {}

        for framework, controls in self._controls.items():
            framework_matches = []
            for ctrl in controls:
                if severity in ctrl["severity_mapping"]:
                    framework_matches.append({
                        "control_id": ctrl["control_id"],
                        "control_name": ctrl["control_name"],
                        "framework": framework,
                        "description": ctrl["description"],
                        "remediation_guidance": ctrl["remediation_guidance"],
                    })
            if framework_matches:
                matched[framework] = framework_matches

        return {
            "event_id": getattr(decision, "event_id", "unknown"),
            "severity": severity,
            "total_controls_matched": sum(len(v) for v in matched.values()),
            "frameworks": matched,
        }

    def get_framework_controls(self, framework: str) -> list[dict]:
        """List all controls for a specific compliance framework."""
        normalized = framework.upper().replace("-", "_").replace(" ", "_")
        controls = self._controls.get(normalized, [])
        return [{"framework": normalized, **c} for c in controls]

    def assess_compliance_impact(self, decisions: list) -> dict:
        """Aggregate compliance risk assessment across multiple decisions."""
        framework_impact = {}
        total_controls = 0

        for decision in decisions:
            mapping = self.map_threat(decision)
            for fw, controls in mapping.get("frameworks", {}).items():
                if fw not in framework_impact:
                    framework_impact[fw] = {"controls_triggered": set(), "total_events": 0}
                framework_impact[fw]["total_events"] += 1
                for c in controls:
                    framework_impact[fw]["controls_triggered"].add(c["control_id"])

        # Convert sets to counts
        result = {}
        for fw, data in framework_impact.items():
            total_fw_controls = len(self._controls.get(fw, []))
            triggered = len(data["controls_triggered"])
            total_controls += triggered
            result[fw] = {
                "total_controls": total_fw_controls,
                "controls_triggered": triggered,
                "compliance_score": round(100 * (1 - triggered / max(total_fw_controls, 1)), 1),
                "events_impacting": data["total_events"],
                "triggered_ids": sorted(data["controls_triggered"]),
            }

        overall_total = sum(len(c) for c in self._controls.values())
        return {
            "overall_compliance_score": round(100 * (1 - total_controls / max(overall_total, 1)), 1),
            "total_controls_triggered": total_controls,
            "events_analyzed": len(decisions),
            "frameworks": result,
        }

    def generate_compliance_report(self, decisions: list) -> str:
        """Generate a markdown compliance report."""
        assessment = self.assess_compliance_impact(decisions)
        report = "# IMMUNEX Compliance Impact Report\n\n"
        report += f"**Events Analyzed:** {assessment['events_analyzed']}\n"
        report += f"**Overall Compliance Score:** {assessment['overall_compliance_score']}%\n"
        report += f"**Total Controls Triggered:** {assessment['total_controls_triggered']}\n\n"

        for fw, data in assessment["frameworks"].items():
            report += f"## {fw}\n"
            report += f"- Score: {data['compliance_score']}%\n"
            report += f"- Controls Triggered: {data['controls_triggered']}/{data['total_controls']}\n"
            report += f"- Events Impacting: {data['events_impacting']}\n"
            if data["triggered_ids"]:
                report += f"- Control IDs: {', '.join(data['triggered_ids'])}\n"
            report += "\n"

        return report
