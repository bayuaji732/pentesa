# Phase 9 Wave 1c: PDF-Only Template Adoption Impact Analysis

> **Document Identifier:** `PENTESA-AUDIT-P9-1C-IMPACT-V1.0`  
> **Evaluation Date:** `2026-11-26`  
> **Scope:** Risk and architectural analysis of adopting the new report template in PDF only vs dual HTML/PDF  
> **Auditors:** Principal Software Architect, Security QA Engineer  

---

## 1. Executive Summary

If the new corporate report template (`docs/assets/Report Pentest (nama aplikasi).docx` / `.pdf`) is implemented exclusively within the PDF rendering engine (`ReportRenderer.render_pdf`) while retaining the legacy 17-section PTES layout in the HTML engine (`ReportRenderer.render_html` with `ptes_standard.html`), several technical and governance discrepancies emerge. This document catalogs those impacts and provides an architectural mitigation plan.

---

## 2. Identified Impacts & Risks

| Impact Category | Severity | Observed Risk / Divergence | Mitigation / Recommendation |
|---|:---:|---|---|
| **Phase 7 Scorer Regression (`p7_html_pdf_fidelity`)** | **High** | The existing test harness (`benchmark/p7/test_runner_p7.py`) asserts section and finding parity between HTML and PDF deliverables. A layout divergence causes HTML/PDF text and section matching checks to fail. | Introduce template-aware scoring in `score_p7b_template.py` evaluating both formats against `template_spec.yaml`. |
| **User Deliverable Inconsistency** | **Medium** | End users downloading HTML interactive reports will view an extensive 17-section technical report, whereas users downloading PDF will receive a 3–4 page concise executive sign-off document. | Provide parity by authoring `corporate_standard.html` matching the new PDF template layout. |
| **Sign-Off Table Absence in HTML** | **Low** | The 4-column approval and sign-off table (`Role`, `Nama Perusahaan`, `Nama Individu`, `TTD`) would exist only in PDF exports, leaving web viewers unable to verify sign-off state. | Include the sign-off component in the HTML template. |
| **CVSS Version Divergence** | **High** | If PDF displays CVSS v4.0 vectors (`CVSS:4.0/...`) while HTML continues displaying CVSS v3.1 or raw severity labels, risk metrics will contradict between deliverables. | Synchronize CVSS v4.0 across `FindingResponse` schema, HTML template, and PDF flowables in Wave 1b. |
| **Zero-Finding Neutrality Invariance** | **Critical** | Both formats must strictly adhere to `DEFECT-REP-01`. Updating PDF without auditing HTML could risk regression of the neutral security posture rule. | Enforce `policies.neutral_zero_finding: true` across both HTML and PDF engines. |

---

## 3. Recommended Architectural Strategy

To eliminate format fragmentation while honoring client requirements:
1. **Template Engine Decoupling:** Introduce a `template: str = "corporate_standard"` field in `ReportGenerateRequest` (supporting `"corporate_standard"` as default, with legacy `"ptes_standard"` preserved for exhaustive technical compliance).
2. **Dual-Format Parity:** In Wave 1c, implement `templates/corporate_standard.html` alongside the ReportLab flowables, ensuring that HTML and PDF views share identical typography, color schemes (`#D9D9D9`, `#FFC000`), table structures, and personnel metadata.
