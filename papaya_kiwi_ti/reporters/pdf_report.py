"""
PDF Report Generator for Papaya Kiwi TI.

Generates branded, professional threat intelligence reports in PDF
format using the Papaya Kiwi pastel visual identity.

Requires: pip install reportlab
"""

from __future__ import annotations
import os
import logging
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)

from papaya_kiwi_ti.models import ThreatReport, Severity, IOCType

logger = logging.getLogger("papaya_kiwi_ti.reporters")

# Brand colors
PAPAYA = colors.HexColor('#FF9F6B')
KIWI = colors.HexColor('#7AC74F')
KIWI_DARK = colors.HexColor('#4A8C2A')
DARK = colors.HexColor('#2D3748')
MED = colors.HexColor('#4A5568')
PAPAYA_LIGHT = colors.HexColor('#FFF0E6')
KIWI_LIGHT = colors.HexColor('#F0FAE8')
WHITE = colors.white
CORAL = colors.HexColor('#FF6B6B')
BORDER_LIGHT = colors.HexColor('#E2E8F0')

# Styles
S_TITLE = ParagraphStyle('PKTitle', fontName='Helvetica-Bold',
    fontSize=20, textColor=DARK, spaceAfter=4, alignment=TA_CENTER)
S_SUB = ParagraphStyle('PKSub', fontName='Helvetica',
    fontSize=10, textColor=MED, spaceAfter=14, alignment=TA_CENTER)
S_H1 = ParagraphStyle('PKH1', fontName='Helvetica-Bold',
    fontSize=14, textColor=PAPAYA, spaceBefore=16, spaceAfter=8)
S_H2 = ParagraphStyle('PKH2', fontName='Helvetica-Bold',
    fontSize=11, textColor=KIWI_DARK, spaceBefore=12, spaceAfter=6)
S_BODY = ParagraphStyle('PKBody', fontName='Helvetica',
    fontSize=9, textColor=DARK, spaceAfter=5, leading=12.5)
S_BODY_BOLD = ParagraphStyle('PKBodyB', fontName='Helvetica-Bold',
    fontSize=9, textColor=DARK, spaceAfter=5, leading=12.5)
S_SMALL = ParagraphStyle('PKSmall', fontName='Helvetica',
    fontSize=7.5, textColor=MED, spaceAfter=3, leading=10)
S_BULLET = ParagraphStyle('PKBullet', fontName='Helvetica',
    fontSize=9, textColor=DARK, leftIndent=18, bulletIndent=6, spaceAfter=3, leading=12.5)

W, H = letter


def _header_footer(canvas_obj, doc):
    """Draw branded header and footer on every page."""
    canvas_obj.saveState()
    # Header
    canvas_obj.setFillColor(PAPAYA)
    canvas_obj.rect(0, H - 32, W, 32, fill=True, stroke=False)
    canvas_obj.setFillColor(WHITE)
    canvas_obj.setFont("Helvetica-Bold", 8)
    canvas_obj.drawString(30, H - 22, "Papaya Kiwi Consulting LLC")
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawRightString(W - 30, H - 17, "Securing Your Cloud, One Sweet Byte at a Time")
    canvas_obj.drawRightString(W - 30, H - 27, f"Generated {datetime.utcnow().strftime('%B %d, %Y')}")
    # Footer
    canvas_obj.setFillColor(KIWI)
    canvas_obj.rect(0, 0, W, 18, fill=True, stroke=False)
    canvas_obj.setFillColor(WHITE)
    canvas_obj.setFont("Helvetica", 6.5)
    canvas_obj.drawString(30, 5, "Papaya Kiwi TI — Open Source Threat Intelligence Toolkit")
    canvas_obj.drawRightString(W - 30, 5, f"Page {doc.page}")
    canvas_obj.restoreState()


def _box(story, text, bg=PAPAYA_LIGHT, border=PAPAYA):
    """Add a colored info box."""
    t = Table([[Paragraph(text, S_BODY)]], colWidths=[6.3 * inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg),
        ('BOX', (0, 0), (-1, -1), 1.2, border),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def _severity_color(sev: str):
    m = {"critical": CORAL, "high": colors.HexColor('#E67E22'),
         "medium": colors.HexColor('#F39C12'), "low": KIWI, "informational": MED}
    return m.get(sev, MED)


class PDFReporter:
    """
    Generates branded Papaya Kiwi PDF threat intelligence reports.

    Produces a professional, dual-layer PDF with executive summary
    and full technical IOC details. Outputs to a specified directory.

    Usage:
        reporter = PDFReporter(output_dir="docs")
        filepath = reporter.generate(report)
    """

    def __init__(self, output_dir: str = "docs"):
        self.output_dir = output_dir

    def generate(self, report: ThreatReport) -> str:
        """Generate a branded PDF report and return the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() or c in (' ', '-', '_') else '' for c in report.title)
        safe_title = safe_title.replace(' ', '_')[:50]
        filename = f"TI_Report_{safe_title}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=letter,
            topMargin=50, bottomMargin=35, leftMargin=50, rightMargin=50)

        story = self._build_story(report)
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)

        logger.info(f"PDF report saved to {filepath}")
        return filepath

    def _build_story(self, report: ThreatReport) -> list:
        story = []

        # === COVER / TITLE ===
        story.append(Spacer(1, 40))
        story.append(Paragraph(report.title, S_TITLE))
        story.append(Paragraph(
            f"Threat Intelligence Report | {report.tlp.value} | "
            f"{report.created.strftime('%B %d, %Y %H:%M UTC')}", S_SUB))

        # Metadata box
        meta_data = [
            ['Severity', report.severity.value.upper(),
             'Confidence', report.confidence.value.upper()],
            ['IOCs Analyzed', str(len(report.iocs)),
             'ATT&CK Techniques', str(len(report.mitre_techniques))],
            ['Threat Actors', str(len(report.threat_actors)),
             'Classification', report.tlp.value],
        ]
        meta_t = Table(meta_data, colWidths=[1.3 * inch, 1.8 * inch, 1.5 * inch, 1.7 * inch])
        meta_t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTNAME', (3, 0), (3, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), PAPAYA),
            ('TEXTCOLOR', (2, 0), (2, -1), PAPAYA),
            ('TEXTCOLOR', (1, 0), (1, -1), DARK),
            ('TEXTCOLOR', (3, 0), (3, -1), DARK),
            ('BACKGROUND', (0, 0), (-1, -1), PAPAYA_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, PAPAYA),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_t)
        story.append(Spacer(1, 10))

        # === EXECUTIVE SUMMARY ===
        story.append(Paragraph("Executive Summary", S_H1))
        story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

        crit = sum(1 for i in report.iocs if i.severity == Severity.CRITICAL)
        high = sum(1 for i in report.iocs if i.severity == Severity.HIGH)
        med = sum(1 for i in report.iocs if i.severity == Severity.MEDIUM)
        low = sum(1 for i in report.iocs if i.severity == Severity.LOW)

        summary = report.summary or f"Analysis of {len(report.iocs)} indicators of compromise."
        story.append(Paragraph(summary, S_BODY))

        if crit > 0:
            _box(story,
                f"<b>IMMEDIATE ACTION REQUIRED:</b> {crit} critical-severity indicators detected "
                f"that indicate active or imminent risk to your environment.",
                PAPAYA_LIGHT, CORAL)

        # Severity breakdown table
        sev_data = [['Severity', 'Count', 'Action Required']]
        if crit: sev_data.append(['CRITICAL', str(crit), 'Immediate triage and containment'])
        if high: sev_data.append(['HIGH', str(high), 'Prompt investigation within 24 hours'])
        if med:  sev_data.append(['MEDIUM', str(med), 'Monitor and assess exposure'])
        if low:  sev_data.append(['LOW', str(low), 'Track for situational awareness'])

        if len(sev_data) > 1:
            story.append(Paragraph("Severity Breakdown", S_H2))
            sev_t = Table(sev_data, colWidths=[1.2 * inch, 0.8 * inch, 4.3 * inch])
            sev_t.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8.5),
                ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
                ('BACKGROUND', (0, 0), (-1, 0), KIWI_DARK),
                ('BACKGROUND', (0, 1), (-1, -1), KIWI_LIGHT),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(sev_t)
            story.append(Spacer(1, 8))

        # === MITRE ATT&CK MAPPING ===
        if report.mitre_techniques:
            story.append(Paragraph("MITRE ATT&amp;CK Mapping", S_H1))
            story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

            from papaya_kiwi_ti.analyzers.mitre import ATTACK_TECHNIQUES

            tech_data = [['Technique', 'Name', 'Tactics']]
            for tid in report.mitre_techniques:
                tech_info = ATTACK_TECHNIQUES.get(tid, {})
                name = tech_info.get('name', 'Unknown')
                tactics = ', '.join(tech_info.get('tactic', [])) if tech_info else ''
                tech_data.append([tid, name, tactics])

            if len(tech_data) > 1:
                tech_t = Table(tech_data, colWidths=[0.9 * inch, 2 * inch, 3.4 * inch])
                tech_t.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
                    ('BACKGROUND', (0, 0), (-1, 0), PAPAYA),
                    ('BACKGROUND', (0, 1), (-1, -1), PAPAYA_LIGHT),
                    ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(tech_t)
                story.append(Spacer(1, 8))

        # === INDICATORS OF COMPROMISE ===
        story.append(Paragraph("Indicators of Compromise", S_H1))
        story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

        # Group by type
        by_type: dict[str, list] = {}
        for ioc in report.iocs:
            t = ioc.ioc_type.value
            by_type.setdefault(t, []).append(ioc)

        for ioc_type, iocs in by_type.items():
            story.append(Paragraph(f"{ioc_type} ({len(iocs)})", S_H2))
            ioc_data = [['Value', 'Severity', 'Source', 'ATT&CK']]
            for ioc in sorted(iocs, key=lambda x: x.severity.value)[:30]:
                val = ioc.value if len(ioc.value) <= 50 else ioc.value[:47] + '...'
                techs = ', '.join(ioc.mitre_techniques[:3]) if ioc.mitre_techniques else '-'
                ioc_data.append([val, ioc.severity.value.upper(), ioc.source[:25], techs])

            ioc_t = Table(ioc_data, colWidths=[2.5 * inch, 0.8 * inch, 1.7 * inch, 1.3 * inch])
            ioc_t.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
                ('BACKGROUND', (0, 0), (-1, 0), KIWI_DARK),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, KIWI_LIGHT]),
            ]))
            story.append(ioc_t)
            story.append(Spacer(1, 6))

        # === ENRICHMENT HIGHLIGHTS ===
        enriched = [i for i in report.iocs if i.enrichment]
        if enriched:
            story.append(PageBreak())
            story.append(Paragraph("Enrichment Highlights", S_H1))
            story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

            for ioc in enriched[:15]:
                story.append(Paragraph(f"<b>{ioc.ioc_type.value}:</b> {ioc.value}", S_BODY_BOLD))
                for provider, data in ioc.enrichment.items():
                    if isinstance(data, dict):
                        details = []
                        for k, v in data.items():
                            if v and v != 0 and v != "":
                                details.append(f"{k}: {v}")
                        if details:
                            detail_str = ' | '.join(details[:6])
                            story.append(Paragraph(
                                f"<font color='#4A8C2A'><b>{provider}:</b></font> {detail_str}", S_SMALL))
                story.append(Spacer(1, 4))

        # === RECOMMENDATIONS ===
        if report.recommendations:
            story.append(Paragraph("Recommendations", S_H1))
            story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

            for i, rec in enumerate(report.recommendations, 1):
                # Highlight priority items
                if rec.startswith("IMMEDIATE") or rec.startswith("PRIORITY"):
                    _box(story, f"<b>{i}.</b> {rec}", PAPAYA_LIGHT, CORAL)
                else:
                    story.append(Paragraph(f"<b>{i}.</b> {rec}", S_BULLET))

        # === THREAT ACTORS ===
        if report.threat_actors:
            story.append(Paragraph("Threat Actor Profiles", S_H1))
            story.append(HRFlowable(width="100%", thickness=1.2, color=PAPAYA, spaceAfter=6))

            for ta in report.threat_actors:
                ta_data = [
                    ['Name', ta.name],
                    ['Aliases', ', '.join(ta.aliases) if ta.aliases else '-'],
                    ['Motivation', ta.motivation or '-'],
                    ['Sophistication', ta.sophistication or '-'],
                    ['Target Sectors', ', '.join(ta.target_sectors) if ta.target_sectors else '-'],
                    ['TTPs', ', '.join(ta.ttps) if ta.ttps else '-'],
                    ['Known Tools', ', '.join(ta.known_tools) if ta.known_tools else '-'],
                    ['Confidence', ta.confidence.value.upper()],
                ]
                ta_t = Table(ta_data, colWidths=[1.5 * inch, 4.8 * inch])
                ta_t.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8.5),
                    ('TEXTCOLOR', (0, 0), (0, -1), PAPAYA),
                    ('BACKGROUND', (0, 0), (-1, -1), PAPAYA_LIGHT),
                    ('BOX', (0, 0), (-1, -1), 1, PAPAYA),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER_LIGHT),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(ta_t)
                story.append(Spacer(1, 8))

        # === FOOTER ===
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=1, color=KIWI, spaceAfter=6))
        story.append(Paragraph(
            f"Report ID: {report.id} | Papaya Kiwi TI v0.1.0 | papayakiwi.com", S_SMALL))
        story.append(Paragraph(
            "This report was generated by the Papaya Kiwi TI open-source toolkit. "
            "Indicators should be validated in your environment before taking action.", S_SMALL))

        return story
