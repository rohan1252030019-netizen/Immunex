import os
import time
from typing import Dict, Any, List, Optional

class MarkdownReportGenerator:
    """
    Formulates incident details, campaign sequences, and SOC activities into structured Markdown formats.
    """
    def generate_incident_markdown(self, report_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Builds a beautiful Markdown document from incident telemetry.
        If output_path is provided, writes the content to disk.
        """
        summary = report_data.get("summary", {})
        gen_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report_data.get('generated_at', time.time())))
        
        md = []
        md.append(f"# IMMUNEX Automated Defense Incident Report: {report_data.get('report_id', 'REP-UNKNOWN')}")
        md.append(f"**Generated At:** {gen_time}\n")
        md.append("## 1. Executive Incident Overview\n")
        md.append("| Property | Detail |")
        md.append("| :--- | :--- |")
        md.append(f"| **Campaign ID** | `{summary.get('campaign_id', 'N/A')}` |")
        md.append(f"| **Primary Attacker IP** | `{summary.get('attacker_ip', 'N/A')}` |")
        md.append(f"| **Severity** | `{summary.get('severity', 'N/A')}` |")
        md.append(f"| **Risk Score Index** | `{summary.get('risk_score', 0.0):.2f} / 100.0` |")
        md.append(f"| **Mitigation Status** | `{summary.get('status', 'N/A')}` |")
        md.append(f"| **Assigned Analyst** | `{summary.get('assigned_analyst', 'Unassigned')}` |\n")
        
        md.append("## 2. Forensic Attack Timeline\n")
        timeline = report_data.get("timeline", [])
        if not timeline:
            md.append("No timeline log events registered for this campaign.\n")
        else:
            md.append("| Timestamp | Event / Action | Tactic / Metadata |")
            md.append("| :--- | :--- | :--- |")
            for ev in timeline:
                ts = ev.get("timestamp", "")
                if isinstance(ts, float):
                    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                action = ev.get("action", ev.get("details", ""))
                tactic = ev.get("tactic", ev.get("metadata", "N/A"))
                md.append(f"| {ts} | {action} | {tactic} |")
            md.append("")
            
        md.append("## 3. Autonomous Mitigation Responses\n")
        mitigations = report_data.get("mitigations", [])
        if not mitigations:
            md.append("No active automated mitigations were triggered.\n")
        else:
            md.append("| Mitigation Action | Target Host / Entity | Execution Status |")
            md.append("| :--- | :--- | :--- |")
            for mit in mitigations:
                act = mit.get("action_type", mit.get("action", "Containment"))
                tgt = mit.get("host_id", mit.get("target", "Global"))
                status = mit.get("status", "SUCCESS")
                md.append(f"| {act} | `{tgt}` | `{status}` |")
            md.append("")

        md.append("## 4. Analyst Notes & Annotations\n")
        notes = report_data.get("notes", [])
        if not notes:
            md.append("No analyst annotations have been registered on this case.\n")
        else:
            for note in notes:
                author = note.get("author", "System")
                ts = note.get("timestamp", time.time())
                if isinstance(ts, (int, float)):
                    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                content = note.get("note", note.get("content", ""))
                md.append(f"* **{author}** ({ts}): {content}")
            md.append("")

        full_md = "\n".join(md)
        
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(full_md)
                
        return full_md

    def generate_compliance_markdown(self, compliance_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Builds a beautiful Markdown document summarizing framework readiness.
        """
        gen_time = time.strftime('%Y-%m-%d %H:%M:%S')
        md = []
        md.append("# IMMUNEX Compliance & Audit Readiness Report")
        md.append(f"**Generated At:** {gen_time}\n")
        md.append("## 1. Compliance Framework Readiness Overview\n")
        md.append("| Framework | Completed Controls | Total Controls | Score |")
        md.append("| :--- | :--- | :--- | :--- |")
        
        frameworks = compliance_data.get("frameworks", {})
        for name, info in frameworks.items():
            score = info.get("score", 0.0)
            md.append(f"| **{name}** | {info.get('completed', 0)} | {info.get('total', 0)} | {score*100:.1f}% |")
        md.append("")
        
        md.append("## 2. Remediation Gaps & Recommended Actions\n")
        gaps = compliance_data.get("gaps", [])
        if not gaps:
            md.append("All framework parameters satisfy strict compliance metrics. No gap actions requested.\n")
        else:
            for gap in gaps:
                md.append(f"### Control Gap: {gap.get('control_id', 'N/A')}")
                md.append(f"* **Description:** {gap.get('description', '')}")
                md.append(f"* **Recommended Action:** {gap.get('recommendation', '')}\n")
                
        full_md = "\n".join(md)
        
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(full_md)
                
        return full_md
