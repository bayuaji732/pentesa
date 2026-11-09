"""Report rendering engine compiling HTML and generating signed PDF documents."""

import hashlib
import os
import uuid
from typing import Optional, Tuple
import jinja2
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from packages.schemas.report import ReportContext


class ReportRenderer:
    """Renders strongly-typed report contexts into standalone interactive HTML or signed PDF files."""

    def __init__(self, templates_dir: Optional[str] = None, output_dir: Optional[str] = None):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.templates_dir = templates_dir or os.path.join(current_dir, "templates")
        self.output_dir = output_dir or os.path.join(os.getcwd(), "data", "reports")
        os.makedirs(self.output_dir, exist_ok=True)

        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.templates_dir),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True
        )

    def render_html(self, context: ReportContext, template_name: str = "ptes_standard.html") -> Tuple[str, str]:
        """Compile Jinja2 template into standalone HTML and calculate SHA-256."""
        if not template_name.endswith(".html"):
            template_name += ".html"

        template = self.jinja_env.get_template(template_name)
        html_content = template.render(ctx=context)

        report_id = str(uuid.uuid4())
        file_name = f"report_{context.project_id}_{report_id[:8]}.html"
        file_path = os.path.join(self.output_dir, file_name)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        file_hash = hashlib.sha256(html_content.encode("utf-8")).hexdigest()
        return file_path, file_hash

    def render_pdf(self, context: ReportContext) -> Tuple[str, str]:
        """Compile formal PDF deliverable using ReportLab and calculate SHA-256."""
        report_id = str(uuid.uuid4())
        file_name = f"report_{context.project_id}_{report_id[:8]}.pdf"
        file_path = os.path.join(self.output_dir, file_name)

        doc = SimpleDocTemplate(
            file_path,
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        normal.fontSize = 9
        normal.leading = 12

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
            spaceAfter=10
        )

        subtitle_style = ParagraphStyle(
            "CoverSubtitle",
            parent=normal,
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#475569"),
            spaceAfter=25
        )

        h1_style = ParagraphStyle(
            "SectionH1",
            parent=styles["Heading1"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True
        )

        code_style = ParagraphStyle(
            "CodeBlock",
            parent=normal,
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a")
        )

        story = []

        # -------------------------------------------------------------
        # PAGE 1: COVER PAGE
        # -------------------------------------------------------------
        story.append(Paragraph(f"<b>{context.classification}</b>", ParagraphStyle("Badge", parent=normal, textColor=colors.HexColor("#dc2626"), fontSize=9)))
        story.append(Spacer(1, 15))
        story.append(Paragraph(context.report_title, title_style))
        story.append(Paragraph("Penetration Testing Execution Standard (PTES) & OWASP WSTG v4.2 Assessment", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#3b82f6"), spaceAfter=20))

        meta_data = [
            [Paragraph("<b>Client Organization:</b>", normal), Paragraph(context.client_name, normal)],
            [Paragraph("<b>Target Scope:</b>", normal), Paragraph(context.project_name, normal)],
            [Paragraph("<b>Assessment Period:</b>", normal), Paragraph(f"{context.start_date} to {context.end_date}", normal)],
            [Paragraph("<b>Lead Security Auditor:</b>", normal), Paragraph(context.lead_tester, normal)],
            [Paragraph("<b>Testing Methodology:</b>", normal), Paragraph("OWASP WSTG v4.2 / PTES", normal)],
            [Paragraph("<b>Generated Timestamp:</b>", normal), Paragraph(context.generated_at, normal)]
        ]
        meta_table = Table(meta_data, colWidths=[55 * mm, 120 * mm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 40))
        story.append(Paragraph("<b>Confidentiality Notice:</b> This document contains proprietary security analysis and forensic vulnerability findings. Dissemination is strictly limited to authorized personnel.", ParagraphStyle("Notice", parent=normal, fontSize=8, textColor=colors.HexColor("#64748b"))))
        story.append(PageBreak())

        # -------------------------------------------------------------
        # PAGE 2: EXECUTIVE SUMMARY & RISK POSTURE
        # -------------------------------------------------------------
        story.append(Paragraph("1. Executive Summary & Security Posture", h1_style))
        story.append(Paragraph(context.executive_narrative, normal))
        story.append(Spacer(1, 10))

        # Risk Summary Table
        risk_data = [
            [
                Paragraph("<b>Critical</b>", normal),
                Paragraph("<b>High</b>", normal),
                Paragraph("<b>Medium</b>", normal),
                Paragraph("<b>Low</b>", normal),
                Paragraph("<b>Informational</b>", normal)
            ],
            [
                Paragraph(f"<font color='#dc2626' size=14><b>{context.critical_findings}</b></font>", normal),
                Paragraph(f"<font color='#ea580c' size=14><b>{context.high_findings}</b></font>", normal),
                Paragraph(f"<font color='#ca8a04' size=14><b>{context.medium_findings}</b></font>", normal),
                Paragraph(f"<font color='#16a34a' size=14><b>{context.low_findings}</b></font>", normal),
                Paragraph(f"<font color='#475569' size=14><b>{context.info_findings}</b></font>", normal)
            ]
        ]
        risk_table = Table(risk_data, colWidths=[35 * mm] * 5)
        risk_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))

        # Scope Summary
        story.append(Paragraph("2. Assessment Scope & Methodology", h1_style))
        scope_text = f"<b>Authorized Targets:</b> {', '.join(context.target_scope)}<br/>"
        if context.excluded_scope:
            scope_text += f"<b>Explicit Exclusions:</b> {', '.join(context.excluded_scope)}<br/>"
        scope_text += f"<b>Discovered Surface:</b> {context.discovered_endpoints_count} endpoints across {context.discovered_domains_count} hostnames.<br/>"
        scope_text += f"<b>WSTG v4.2 Testing Coverage:</b> {context.coverage_score:.1f}%"
        story.append(Paragraph(scope_text, normal))
        story.append(Spacer(1, 15))

        # Findings Summary Table
        story.append(Paragraph("3. Findings Summary Matrix", h1_style))
        findings_table_data = [
            [
                Paragraph("<b>ID</b>", normal),
                Paragraph("<b>Title</b>", normal),
                Paragraph("<b>Severity</b>", normal),
                Paragraph("<b>CVSS</b>", normal),
                Paragraph("<b>CWE</b>", normal)
            ]
        ]
        for f in context.findings:
            sev_color = "#dc2626" if f.severity == "Critical" else ("#ea580c" if f.severity == "High" else "#ca8a04")
            findings_table_data.append([
                Paragraph(f"<b>{f.id}</b>", normal),
                Paragraph(f.title, normal),
                Paragraph(f"<font color='{sev_color}'><b>{f.severity}</b></font>", normal),
                Paragraph(str(f.cvss_score or "N/A"), normal),
                Paragraph(f.cwe_id or "N/A", normal)
            ])

        if len(findings_table_data) == 1:
            findings_table_data.append([Paragraph("No confirmed findings.", normal), Paragraph("", normal), Paragraph("", normal), Paragraph("", normal), Paragraph("", normal)])

        f_table = Table(findings_table_data, colWidths=[25 * mm, 75 * mm, 25 * mm, 20 * mm, 30 * mm])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(f_table)
        story.append(PageBreak())

        # -------------------------------------------------------------
        # PAGE 3+: DETAILED TECHNICAL FINDINGS & EVIDENCE
        # -------------------------------------------------------------
        story.append(Paragraph("4. Detailed Technical Findings & Evidence", h1_style))
        for f in context.findings:
            finding_blocks = []
            finding_blocks.append(Paragraph(f"<b>{f.id}: {f.title}</b>", h2_style))
            prop_data = [
                [Paragraph("<b>Endpoint:</b>", normal), Paragraph(f"<code>{f.http_method} {f.endpoint_url}</code>", normal)],
                [Paragraph("<b>Severity / CVSS:</b>", normal), Paragraph(f"{f.severity} (Score: {f.cvss_score or 'N/A'}) - <code>{f.cvss_vector or 'N/A'}</code>", normal)],
                [Paragraph("<b>CWE Taxonomy:</b>", normal), Paragraph(f"{f.cwe_id}", normal)],
                [Paragraph("<b>Controllable Param:</b>", normal), Paragraph(f"{f.affected_parameter or 'None / Path'}", normal)]
            ]
            prop_table = Table(prop_data, colWidths=[35 * mm, 140 * mm])
            prop_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            finding_blocks.append(prop_table)
            finding_blocks.append(Spacer(1, 6))

            finding_blocks.append(Paragraph("<b>Vulnerability Description:</b>", normal))
            finding_blocks.append(Paragraph(f.description, normal))
            finding_blocks.append(Spacer(1, 4))

            finding_blocks.append(Paragraph("<b>Business Impact:</b>", normal))
            finding_blocks.append(Paragraph(f.business_impact or "Operational integrity risk.", normal))
            finding_blocks.append(Spacer(1, 4))

            finding_blocks.append(Paragraph("<b>Remediation Guidance:</b>", normal))
            finding_blocks.append(Paragraph(f.remediation_guidance or "Sanitize inputs and enforce authorization.", normal))
            finding_blocks.append(Spacer(1, 4))

            if f.reproduction_curl:
                finding_blocks.append(Paragraph("<b>Reproduction Command:</b>", normal))
                finding_blocks.append(Paragraph(f"<code>{f.reproduction_curl}</code>", code_style))
                finding_blocks.append(Spacer(1, 4))

            if f.request_hash_sha256:
                finding_blocks.append(Paragraph(f"<b>Forensic Evidence SHA-256:</b> <code>{f.request_hash_sha256}</code>", normal))

            finding_blocks.append(Spacer(1, 12))
            story.append(KeepTogether(finding_blocks))

        # -------------------------------------------------------------
        # FINAL SECTION: REMEDIATION ROADMAP & INTEGRITY SEAL
        # -------------------------------------------------------------
        story.append(Spacer(1, 10))
        story.append(Paragraph("5. Prioritized Remediation Roadmap", h1_style))
        roadmap_data = [
            [Paragraph("<b>Horizon</b>", normal), Paragraph("<b>Target Actions</b>", normal)],
            [Paragraph("<b>Immediate (1–7 Days)</b>", normal), Paragraph("<br/>".join([f"• {a}" for a in context.immediate_actions]), normal)],
            [Paragraph("<b>Near-Term (30 Days)</b>", normal), Paragraph("<br/>".join([f"• {a}" for a in context.near_term_actions]), normal)],
            [Paragraph("<b>Long-Term (90 Days)</b>", normal), Paragraph("<br/>".join([f"• {a}" for a in context.long_term_actions]), normal)]
        ]
        road_table = Table(roadmap_data, colWidths=[45 * mm, 130 * mm])
        road_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(road_table)
        story.append(Spacer(1, 20))

        seal_text = (
            f"<b>CRYPTOGRAPHIC INTEGRITY SEAL</b><br/>"
            f"Rendered by Pentesa Autonomous Security Platform | Methodology: PTES & OWASP WSTG v4.2<br/>"
            f"Verification Endpoint: <code>POST /api/v1/reports/verify</code>"
        )
        story.append(Paragraph(seal_text, ParagraphStyle("Seal", parent=normal, fontSize=8, alignment=1, textColor=colors.HexColor("#64748b"))))

        # Build document
        doc.build(story)

        # Calculate file SHA-256 hash
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        return file_path, file_hash

