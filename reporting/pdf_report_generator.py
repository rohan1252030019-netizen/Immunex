import os
import time
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

class PDFReportGenerator:
    """
    Enterprise PDF Report Generator using ReportLab.
    Creates high-impact, professional, stylized SOC operations and incident reports.
    """
    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        # Create enterprise theme styles
        self.title_style = ParagraphStyle(
            name='EnterpriseTitle',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=colors.HexColor('#0f172a'),  # Dark Slate
            alignment=TA_LEFT,
            spaceAfter=15
        )
        
        self.subtitle_style = ParagraphStyle(
            name='EnterpriseSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#475569'),  # Muted Slate
            alignment=TA_LEFT,
            spaceAfter=25
        )

        self.h1_style = ParagraphStyle(
            name='EnterpriseH1',
            parent=self.styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#1e3a8a'),  # Navy Blue
            spaceBefore=15,
            spaceAfter=10,
            keepWithNext=True
        )

        self.h2_style = ParagraphStyle(
            name='EnterpriseH2',
            parent=self.styles['Heading3'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#0f766e'),  # Teal
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True
        )

        self.body_style = ParagraphStyle(
            name='EnterpriseBody',
            parent=self.styles['BodyText'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceAfter=8
        )

        self.body_bold_style = ParagraphStyle(
            name='EnterpriseBodyBold',
            parent=self.body_style,
            fontName='Helvetica-Bold'
        )

        self.meta_style = ParagraphStyle(
            name='EnterpriseMeta',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#94a3b8'),
            alignment=TA_RIGHT
        )

        self.th_style = ParagraphStyle(
            name='EnterpriseTableHeader',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=12,
            textColor=colors.white
        )

        self.td_style = ParagraphStyle(
            name='EnterpriseTableCell',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )

    def generate_incident_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """
        Generates a comprehensive dynamic incident PDF report.
        """
        # Ensure directories exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
        )
        
        story = []

        # --- Header Block ---
        story.append(Paragraph("IMMUNEX AUTOMATED DEFENSE PLATFORM", self.meta_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Incident Case File: {report_data.get('report_id', 'REP-UNKNOWN')}", self.title_style))
        story.append(Paragraph(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report_data.get('generated_at', time.time())))}", self.subtitle_style))
        
        # Horizontal Rule
        hr = Table([['']], colWidths=[504], rowHeights=[2])
        hr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#3b82f6')),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(hr)
        story.append(Spacer(1, 15))

        # --- Executive Summary Table ---
        story.append(Paragraph("1. Executive Incident Overview", self.h1_style))
        summary = report_data.get("summary", {})
        
        overview_data = [
            [Paragraph("Campaign ID", self.body_bold_style), Paragraph(str(summary.get("campaign_id", "N/A")), self.body_style)],
            [Paragraph("Primary Attacker IP", self.body_bold_style), Paragraph(str(summary.get("attacker_ip", "N/A")), self.body_style)],
            [Paragraph("Severity Level", self.body_bold_style), Paragraph(str(summary.get("severity", "N/A")), self.body_style)],
            [Paragraph("Risk Score Index", self.body_bold_style), Paragraph(f"{summary.get('risk_score', 0.0):.2f} / 100.0", self.body_style)],
            [Paragraph("Mitigation Status", self.body_bold_style), Paragraph(str(summary.get("status", "N/A")), self.body_style)],
            [Paragraph("Assigned SOC Analyst", self.body_bold_style), Paragraph(str(summary.get("assigned_analyst", "N/A")), self.body_style)],
        ]
        
        t_overview = Table(overview_data, colWidths=[150, 354])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_overview)
        story.append(Spacer(1, 15))

        # --- Chronological Timeline ---
        story.append(Paragraph("2. Forensic Attack Timeline", self.h1_style))
        timeline = report_data.get("timeline", [])
        if not timeline:
            story.append(Paragraph("No timeline logs recorded for this campaign.", self.body_style))
        else:
            timeline_rows = [[
                Paragraph("Timestamp", self.th_style), 
                Paragraph("Event / Action Taken", self.th_style),
                Paragraph("Tactics / Details", self.th_style)
            ]]
            
            for ev in timeline:
                ts_str = ev.get("timestamp", "")
                if isinstance(ts_str, float):
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_str))
                timeline_rows.append([
                    Paragraph(str(ts_str), self.td_style),
                    Paragraph(str(ev.get("action", ev.get("details", ""))), self.td_style),
                    Paragraph(str(ev.get("tactic", ev.get("metadata", "N/A"))), self.td_style)
                ])

            t_timeline = Table(timeline_rows, colWidths=[120, 204, 180])
            t_timeline.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t_timeline)
        
        story.append(Spacer(1, 15))

        # --- Mitigations and Defenses Applied ---
        story.append(Paragraph("3. Autonomous Mitigation Responses", self.h1_style))
        mitigations = report_data.get("mitigations", [])
        if not mitigations:
            story.append(Paragraph("No defensive mitigations required or applied.", self.body_style))
        else:
            mit_rows = [[
                Paragraph("Mitigation Action", self.th_style),
                Paragraph("Target Host / ID", self.th_style),
                Paragraph("Execution Status", self.th_style)
            ]]
            for mit in mitigations:
                mit_rows.append([
                    Paragraph(str(mit.get("action_type", mit.get("action", "Containment"))), self.td_style),
                    Paragraph(str(mit.get("host_id", mit.get("target", "Global"))), self.td_style),
                    Paragraph(str(mit.get("status", "SUCCESS")), self.td_style)
                ])
            t_mit = Table(mit_rows, colWidths=[180, 180, 144])
            t_mit.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f766e')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0fdfa')]),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t_mit)

        story.append(Spacer(1, 15))

        # --- Analyst Notes ---
        story.append(Paragraph("4. Incident Investigation Notes", self.h1_style))
        notes = report_data.get("notes", [])
        if not notes:
            story.append(Paragraph("No analyst notes filed under this case.", self.body_style))
        else:
            for note in notes:
                author = note.get("author", "System")
                timestamp = note.get("timestamp", time.time())
                if isinstance(timestamp, (int, float)):
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
                content = note.get("note", note.get("content", ""))
                
                note_para = f"<b>{author}</b> ({timestamp}): {content}"
                story.append(Paragraph(note_para, self.body_style))
                story.append(Spacer(1, 4))
                
        doc.build(story)

    def generate_compliance_report(self, compliance_data: Dict[str, Any], output_path: str) -> None:
        """
        Generates a stylized PDF containing compliance framework readiness summaries (SOC2, NIST, ISO27001).
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
        )
        
        story = []
        
        story.append(Paragraph("IMMUNEX AUTOMATED AUDIT SYSTEM", self.meta_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Enterprise Cybersecurity Compliance Report", self.title_style))
        story.append(Paragraph(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}", self.subtitle_style))
        
        hr = Table([['']], colWidths=[504], rowHeights=[2])
        hr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0f766e')),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(hr)
        story.append(Spacer(1, 15))

        story.append(Paragraph("1. Framework Readiness Overview", self.h1_style))
        
        table_rows = [[
            Paragraph("Framework Standard", self.th_style),
            Paragraph("Completed Controls", self.th_style),
            Paragraph("Total Controls Evaluated", self.th_style),
            Paragraph("Readiness Score", self.th_style)
        ]]

        frameworks = compliance_data.get("frameworks", {})
        for name, info in frameworks.items():
            score = info.get("score", 0.0)
            table_rows.append([
                Paragraph(str(name), self.td_style),
                Paragraph(str(info.get("completed", 0)), self.td_style),
                Paragraph(str(info.get("total", 0)), self.td_style),
                Paragraph(f"{score * 100:.1f}%", self.td_style)
            ])

        t_frameworks = Table(table_rows, colWidths=[150, 118, 118, 118])
        t_frameworks.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_frameworks)
        story.append(Spacer(1, 15))

        story.append(Paragraph("2. Detailed Control Gaps & Action Items", self.h1_style))
        gaps = compliance_data.get("gaps", [])
        if not gaps:
            story.append(Paragraph("All active controls are fully compliant. No gap corrective actions required.", self.body_style))
        else:
            for gap in gaps:
                story.append(Paragraph(f"<b>[GAP] Control {gap.get('control_id', 'UNKNOWN')}</b>: {gap.get('description', '')}", self.body_style))
                story.append(Paragraph(f"<i>Recommendation</i>: {gap.get('recommendation', 'Deploy additional endpoint sensors or enable logging.')}", self.body_style))
                story.append(Spacer(1, 5))
                
        doc.build(story)
