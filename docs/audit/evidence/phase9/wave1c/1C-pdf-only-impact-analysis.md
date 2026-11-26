# Phase 9 Wave 1c: PDF-Only Template Architecture & Impact Analysis

> **Document Identifier:** `PENTESA-AUDIT-P9-1C-IMPACT-V2.0`  
> **Evaluation Date:** `2026-11-26`  
> **Scope:** Architecture decision: PDF-only reporting pipeline (retirement of HTML reporting engine)  
> **Auditors:** Principal Software Architect, Security QA Engineer  
> **Status:** APPROVED ARCHITECTURAL DIRECTION  

---

## 1. Executive Summary & Architecture Decision

The platform transitions exclusively to a **PDF-only reporting pipeline**. All proposals for `corporate_standard.html` and the `template` selection parameter are **DELETED**. 
- The HTML report renderer (`ReportRenderer.render_html`) and `ptes_standard.html` are deprecated and will be removed at implementation after formal approval (permanently archived via git tag).
- PDF is established as the sole authoritative deliverable format for penetration testing engagements.
- HTML-based fidelity checks in the frozen Phase 7 scorer (`score_p7.py`) become **N/A** (Not Applicable) post-deprecation.

---

## 2. Impact Analysis & Resolution Matrix

| Dimension | Impact of PDF-Only Decision | Resolution & Implementation Plan |
|---|---|---|
| **HTML Renderer Retirement** | Legacy Jinja2 HTML renderer and `ptes_standard.html` become obsolete technical debt. | Safely remove `render_html()` and HTML template files post-approval. The legacy implementation is preserved and traceable via git tag `archive-html-renderer`. |
| **Scorer Parity (`p7_html_pdf_fidelity`)** | Frozen Phase 7 scorer evaluated 24 HTML + 24 PDF reports. HTML evaluation will no longer apply. | HTML-based assertions in frozen P7 scorer are classified as **N/A (Retired)**. Modern reporting fidelity is governed exclusively by `benchmark/p7b/score_p7b_template.py` targeting PDF deliverables. |
| **Single Engine Maintenance** | Eliminates dual-engine formatting drift, layout contradictions, and divergent CSS/ReportLab rendering bugs. | All styling, geometry, tables, and typography are maintained solely within `ReportLab` flowables in `services/reporting_engine/renderer.py`. |
| **API Simplification** | Eliminates need for `template` parameter or format negotiation query flags. | `POST /api/v1/reports/generate` generates standardized corporate PDF output directly. |

---

## 3. Data Flow & Fallback Neutrality Rules

1. **No Tech Stack Narrative Fallback:**
   - **Application Description:** Renders `"Not provided"` if absent from `Project.description`.
   - **Application Purpose:** Renders `"Not provided"` if absent from report parameters. No speculative tech stack descriptions or crawler logs are synthesized.
2. **Sign-Off Table Personnel Mapping:**
   - The 4 sign-off roles (`Pentester`, `Reviewer 1`, `PIC / Project Manager`, `Reviewer 2`) come strictly from explicit report parameters (`ReportGenerateRequest`) or dedicated project report metadata.
   - They do **NOT** fallback to `ProjectMember` roles.
   - Pre-filled names from Word templates (e.g., `"Devin Gunadi Tampuboon"`, `"Ferdinand Winaya"`, `"Yuan Yudistira"`) are **NEVER** used as defaults. Unassigned roles render blank / `"-"`.
3. **Neutral Zero-Finding Posture (`DEFECT-REP-01`):**
   - Projects with 0 confirmed findings state: *"No vulnerabilities were confirmed within the tested scope and rules of engagement."* (Zero claims of "strong security posture").
