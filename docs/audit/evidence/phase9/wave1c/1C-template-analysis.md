# Phase 9 Wave 1c: Pentest Report Template Forensic Analysis & Measurement Report

> **Document Identifier:** `PENTESA-AUDIT-P9-1C-ANALYSIS-V1.0`  
> **Evaluation Date:** `2026-11-26`  
> **Target Assets:** `docs/assets/Report Pentest (nama aplikasi).docx`, `.pdf`, `.md`, `Picture1.png`  
> **Auditors:** Principal Software Architect, Senior Security QA Engineer  
> **Status:** Completed Forensic Template Analysis  

---

## 1. Executive Summary

This forensic analysis establishes the exact physical geometry, typographic specifications, tabular layouts, color palettes, and data contracts extracted directly from the reference corporate penetration test reporting assets provided in `docs/assets/`. These empirical measurements serve as the authoritative foundation for `benchmark/p7b/template_spec.yaml`, the fidelity scoring harness (`score_p7b_template.py`), and the ReportLab PDF rendering engine enhancements planned for Wave 1c.

---

## 2. Physical Page Geometry & Margins

Measurements were extracted from OpenXML `word/document.xml` (`w:pgSz`, `w:pgMar`) and corroborated via PDF catalog dictionary (`/MediaBox`):

| Geometric Attribute | OpenXML Raw Units | Standard Metric | PostScript Points | PDF MediaBox Coordinates |
|---|---|---|---|---|
| **Page Format** | ISO 216 Standard | **A4 Standard** | - | `[0 0 595.28 841.89]` |
| **Page Width** | `11,906 dxa` | **210.0 mm** | 595.28 pt | 595.28 pt |
| **Page Height** | `16,838 dxa` | **297.0 mm** | 841.89 pt | 841.89 pt |
| **Top Margin** | `1,440 dxa` | **25.40 mm (1.00 in)** | 72.00 pt | `y = 769.89 pt` |
| **Bottom Margin** | `1,440 dxa` | **25.40 mm (1.00 in)** | 72.00 pt | `y = 72.00 pt` |
| **Left Margin** | `1,440 dxa` | **25.40 mm (1.00 in)** | 72.00 pt | `x = 72.00 pt` |
| **Right Margin** | `1,440 dxa` | **25.40 mm (1.00 in)** | 72.00 pt | `x = 523.28 pt` |
| **Printable Width** | `9,026 dxa` | **159.20 mm** | 451.28 pt | 451.28 pt |
| **Printable Height**| `13,958 dxa`| **246.20 mm** | 697.89 pt | 697.89 pt |

---

## 3. Image Asset Specifications (`Picture1.png`)

Extracted via PIL analysis and raw image header parsing:

- **File Format:** PNG (Portable Network Graphics) with alpha channel (`RGBA`)
- **Pixel Resolution:** 1178 pixels wide $\times$ 437 pixels high
- **Pixel Density / DPI:** $119.99 \times 119.99$ DPI (~120 DPI)
- **Aspect Ratio:** $2.70 : 1$ (width-to-height)
- **Native Unscaled Dimensions:** $249.5 \text{ mm} \times 92.5 \text{ mm}$ ($707.0 \text{ pt} \times 262.3 \text{ pt}$)
- **Scaled Layout Dimensions (ReportLab Flowable):** To fit within the 159.2 mm printable width while preserving white margin breathing room, the asset must be scaled to **$120.0 \text{ mm} \times 44.4 \text{ mm}$** ($340.2 \text{ pt} \times 125.9 \text{ pt}$).
- **Content Description:** Corporate logo and healthcare organizational branding banner.

---

## 4. Color Palette Specifications

Extracted from `w:shd` (table shading), `w:color` (font colors), and PDF stream graphics state:

| Role / Element | Hex Color Code | RGB Tuple (0-255) | ReportLab Color Constant |
|---|---|---|---|
| **Table Header Shading** | `#D9D9D9` | `rgb(217, 217, 217)` | `colors.HexColor("#D9D9D9")` |
| **Detail Vulnerability Banner** | `#D9D9D9` | `rgb(217, 217, 217)` | `colors.HexColor("#D9D9D9")` |
| **Severity Cell Highlight (High)** | `#FFC000` | `rgb(255, 192, 0)` | `colors.HexColor("#FFC000")` |
| **Primary Text Color** | `#000000` | `rgb(0, 0, 0)` | `colors.HexColor("#000000")` |
| **Muted Metadata / Badges** | `#64748B` | `rgb(100, 116, 139)` | `colors.HexColor("#64748B")` |
| **Code / POC Background** | `#F1F5F9` | `rgb(241, 245, 249)` | `colors.HexColor("#F1F5F9")` |
| **Table Grid & Border Lines** | `#000000` | `rgb(0, 0, 0)` | `colors.HexColor("#000000")` (0.5 pt solid) |

---

## 5. Typography Hierarchy

Extracted from `w:styles.xml`, `w:document.xml` (`w:rPr/w:sz`), and PDF font descriptors:

| Template Section | Font Family | Size (pt) | Weight | Alignment | Spacing / Leading |
|---|---|---|---|---|---|
| **Confidential Badge** | Helvetica / Calibri | 9.0 pt | Regular | Left | 12 pt leading, 6 pt after |
| **Document Title ("Report Pentest")** | Helvetica-Bold / Calibri | 18.0 pt | **Bold** | Center | 22 pt leading, 4 pt after |
| **Application Name ("[Nama Aplikasi]")** | Helvetica-Bold / Calibri | 18.0 pt | **Bold** | Center | 22 pt leading, 14 pt after |
| **Pentester Label ("Pentester:")** | Helvetica-Bold / Calibri | 14.0 pt | **Bold** | Center | 18 pt leading, 4 pt after |
| **Pentester Name ("[Nama Pentester]")** | Helvetica-Bold / Calibri | 20.0 pt | **Bold** | Center | 24 pt leading, 16 pt after |
| **Section Headings (H1)** | Helvetica-Bold / Calibri | 14.0 pt | **Bold** | Left | 18 pt leading, 12 pt before, 6 pt after |
| **Body Narratives / Descriptions** | Helvetica / Calibri | 11.0 pt | Regular | Left | 15 pt leading, 6 pt after |
| **Table Header Row** | Helvetica-Bold / Calibri | 10.0 pt | **Bold** | Center | 13 pt leading, 4 pt padding |
| **Table Data Cells** | Helvetica / Calibri | 10.0 pt | Regular | Left/Center | 13 pt leading, 4 pt padding |
| **Finding Detail Title** | Helvetica-Bold / Calibri | 11.0 pt | **Bold** | Left | 15 pt leading, 4 pt after |
| **POC Code Blocks** | Courier | 8.5 pt | Regular | Left | 11 pt leading, `#F1F5F9` box |

---

## 6. Table Geometry & Structural Breakdown

### 6.1 Table 1: Assessment Dates Table
- **Dimensions:** 2 rows $\times$ 2 columns
- **Border Style:** 0.5 pt solid black (`#000000`) all around and interior grid.
- **Column Widths:**
  - Column 1 (`Pentest Completion Date`): 60.0 mm (170.1 pt / 3402 dxa)
  - Column 2 (`Date Value / Retest`): 99.2 mm (281.2 pt / 5624 dxa)
  - **Total Table Width:** 159.2 mm (100% of printable width)

### 6.2 Table 2: Findings Summary Table
- **Dimensions:** 5 rows (1 header + 4 findings) $\times$ 5 columns
- **Header Shading:** Background `#D9D9D9`
- **Border Style:** 0.5 pt solid black (`#000000`)
- **Column Breakdown:**
  - Col 1 (`No`): 15.0 mm (42.5 pt / 851 dxa) — Centered
  - Col 2 (`Temuan`): 76.0 mm (215.4 pt / 4309 dxa) — Left-aligned
  - Col 3 (`Severity`): 26.8 mm (76.0 pt / 1546 dxa) — Centered, Background `#FFC000` (Amber)
  - Col 4 (`Method`): 20.7 mm (58.7 pt / 1174 dxa) — Centered
  - Col 5 (`Status`): 20.7 mm (58.7 pt / 1174 dxa) — Centered
  - **Total Table Width:** 159.2 mm

### 6.3 Table 3: Sign-Off & Reviewer Approval Table
- **Dimensions:** 5 rows (1 header + 4 signatories) $\times$ 4 columns
- **Header Shading:** Background `#D9D9D9`
- **Border Style:** 0.5 pt solid black (`#000000`)
- **Column Breakdown:**
  - Col 1 (`Role`): 30.0 mm (85.0 pt / 1701 dxa)
  - Col 2 (`Nama Perusahaan/Nama Individu`): 60.0 mm (170.1 pt / 3402 dxa)
  - Col 3 (`Nama Individu`): 42.0 mm (119.1 pt / 2381 dxa)
  - Col 4 (`TTD`): 27.2 mm (77.1 pt / 1542 dxa) — Blank signature cell
  - **Total Table Width:** 159.2 mm

### 6.4 Table 4: Detail Vulnerability Section Banner
- **Dimensions:** 1 row $\times$ 1 column
- **Header Shading:** Background `#D9D9D9`
- **Border Style:** 0.5 pt solid black (`#000000`)
- **Height / Padding:** 6 pt top/bottom padding
- **Text:** `Detail Vulnerability` (12.0 pt Bold, Centered)
- **Width:** 159.2 mm

---

## 7. Finding Item Contract & CVSS v4.0 Layout

In the reference template (`Report Pentest (nama aplikasi).docx` & `.md`), each vulnerability item follows this exact standardized format:

1. **Title Block:** `<Number>. <Vulnerability Title> (<CVSS_v4_VECTOR>) Description:`
   - Example from asset: `1. Broken Access Control (CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N) Description:`
2. **Body Narrative:** High-level architectural and exploit description.
3. **Subsections (Strict Order):**
   - `The affected URL endpoints are:` (List of HTTP methods and URIs)
   - `Impact:` (Confidentiality, Integrity, Availability consequences)
   - `Mitigation:` (Remediation guidance and secure coding advice)
   - `Reference:` (WSTG, CWE, CAPEC, CVE cross-references)
   - `POC:` (Step-by-step reproduction guide and sanitized cURL commands)
