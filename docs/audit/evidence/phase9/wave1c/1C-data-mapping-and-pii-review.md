# Phase 9 Wave 1c: Data Mapping Table & Truthfulness/PII Policy Review

> **Document Identifier:** `PENTESA-AUDIT-P9-1C-MAPPING-V1.0`  
> **Evaluation Date:** `2026-11-26`  
> **Target:** Integration of corporate report template into Pentesa reporting engine  
> **Auditors:** Principal Software Architect, Senior Security QA Engineer  
> **Status:** Specification Complete  

---

## 1. Master Data Mapping Table

This matrix maps every field and structural element from the target corporate report template to Pentesa's internal data model (`database.models`), schemas (`packages.schemas.report.ReportContext`), and identifies schema migration or options requirements for Waves 1b/1c:

| Template Element / Field | Target Template Format | Pentesa Data Source | Current State | Remediation / Wave Target |
|---|---|---|---|---|
| **Cover Title** | `"Report Pentest"` | Static Report Type Literal | Exists (`context.report_title`) | Wave 1c-i (Template styling) |
| **Application Name** | `"[Nama Aplikasi]"` | `Project.name` | Exists (`context.project_name`) | Direct mapping |
| **Corporate Logo** | Banner Image (Aspect 2.70:1) | Dynamic Tenant Logo / Config | Exists as optional flowable | Configurable `logo_path` in `ReportGenerateRequest` |
| **Pentester Subtitle** | `"Pentester:"` | Section Header Literal | Exists | Wave 1c-i |
| **Lead Pentester Name**| `"[Nama Pentester]"` | `User.full_name` (Lead Tester) | Exists (`context.lead_tester`) | Direct mapping |
| **Completion Date** | `"Pentest Completion Date"` | `Project.updated_at` / `end_date` | Exists (`context.end_date`) | Table 1 Column 2 |
| **Retest Date** | `"Retest Completion Date"` | `ReportGenerateRequest.retest_date` | **Missing** (Hardcoded `"-"` fallback) | Add optional `retest_date` to `ReportGenerateRequest` |
| **App Description** | `<description of apps...>` | `Project.description` | Exists (`context.executive_narrative`) | Renders `"Not provided"` if absent (no tech stack fallback) |
| **App Purpose** | `<explain purpose/feature>` | Report Options / Metadata | Needs Change (No purpose column) | Add `purpose: Optional[str]` to `ReportGenerateRequest`; renders `"Not provided"` if absent (no tech stack fallback) |
| **Scope of Work** | `<url/api/IP>` | `ScopeRule.pattern` list | Exists (`context.target_scope`) | Render list of target URLs & IPs |
| **Summary Table: No** | `1, 2, 3...` | Loop index (`1`-based) | Exists (`enumerate(findings, 1)`) | Table 2 Col 1 |
| **Summary: Temuan** | Vulnerability Title | `Finding.title` | Exists (`finding.title`) | Table 2 Col 2 |
| **Summary: Severity** | High, Medium, Low, Info | `Finding.severity` | Exists (`finding.severity`) | Table 2 Col 3 (with `#FFC000` Amber fill) |
| **Summary: Method** | `"Dynamic/Automated"` | `FindingEvidence.tool` / `source` | Exists (`evidence.tool`) | Maps prober/tool to Method (Dynamic / Automated) |
| **Summary: Status** | `"Confirmed"` | `Finding.status` | Exists (`finding.status`) | Table 2 Col 5 (Confirmed only) |
| **Sign-Off: Roles** | Pentester, Reviewer 1, PIC, Reviewer 2 | Static Structure | Exists | Table 3 Col 1 |
| **Sign-Off: Organization** | Company / Organization Name | `ReportGenerateRequest` / Client | Needs Change | Explicit parameter (never hardcoded Siloam) |
| **Sign-Off: Names** | Reviewer Individual Names | `ReportGenerateRequest` metadata | Needs Change | Explicit report parameters/metadata (NOT `ProjectMember` roles; template pre-filled names NEVER defaults) |
| **Sign-Off: TTD** | Signature Block | Blank line / Digital Hash | Exists | Table 3 Col 4 (blank for signing) |
| **Detail: Title** | `{n}. {Title} ({CVSS}) Description:`| `Finding.title` + CVSS v4.0 | Needs Schema (`DEFECT-FIND-03`) | Implement CVSS v4.0 in Wave 1b |

---

## 1.1 Data Mapping Summary Counts
- **Exists in Current System / As-Is:** **14 elements** (Cover Title, App Name, Pentester Subtitle, Lead Pentester Name, Completion Date, Scope of Work, Summary No, Summary Temuan, Summary Severity, Summary Method, Summary Status, Sign-Off Roles, Sign-Off TTD, Detail Fields [Endpoints, Impact, Mitigation, Reference, POC]).
- **Needs Change (Parameters / Formatting / Logic):** **6 elements** (Corporate Logo path, Retest Date param, App Description `"Not provided"` logic, App Purpose `"Not provided"` logic, Sign-Off Organization param, Sign-Off Names explicit metadata mapping).
- **Needs Schema Migration:** **1 element** (CVSS v4.0 `cvss_score`, `cvss_vector`, `cvss_source` on `findings` table per `DEFECT-FIND-03` / `ADR-009`).
- **Total Mapped Elements:** **21 elements**.
| **Detail: Endpoints** | `"The affected URL endpoints are:"` | `FindingResponse.endpoint` | Exists (`finding.endpoint`) | Direct mapping |
| **Detail: Impact** | `"Impact:"` | `Finding.impact` | Exists (`finding.impact`) | Direct mapping |
| **Detail: Mitigation**| `"Mitigation:"` | `Finding.remediation` | Exists (`finding.remediation`) | Direct mapping |
| **Detail: Reference** | `"Reference:"` | `Finding.references` / WSTG ID | Exists (`finding.references`) | Direct mapping |
| **Detail: POC** | `"POC:"` | `FindingEvidence.reproduction_curl` | Exists (`evidence.reproduction_curl`)| Render formatted code block |

---

## 2. Truthfulness, Integrity & PII Review

### 2.1 Elimination of Hardcoded Person Names and Company Brands
1. **Identified Violations in Template Asset:**
   - Lines 45–48 of `Report Pentest (nama aplikasi).docx` / `.md` hardcode real staff names (`Devin Gunadi Tampuboon`, `Ferdinand Winaya`, `Yuan Yudistira`) and corporate organizational entity (`Siloam International Hospitals`).
   - Line 47 contains a typographical error: `"Siloam Interantional Hospitals"`.
2. **Platform Architectural Requirement:**
   - Zero hardcoded names, emails, or company identifiers are permitted in platform source code, Jinja templates, or ReportLab generators.
   - All personnel fields must dynamically populate from authenticated `User.full_name` and `ProjectMember` records associated with the specific project.
   - If a project lacks designated reviewers, the sign-off table rows must render generic role placeholders (`"Assigned Security Reviewer"`, `"Engineering Project Manager"`) rather than synthetic employee names.
   - The typographical error `"Interantional"` must be permanently corrected to `"International"` in any fallback label.

### 2.2 Preservation of Established Platform Audit Invariants
1. **Neutral Zero-Finding Posture (`DEFECT-REP-01`):**
   - When a project has zero confirmed findings, the template summary and narrative must state:  
     `"No vulnerabilities were confirmed within the tested scope and rules of engagement."`  
   - It must **never** claim `"STRONG SECURITY POSTURE"` or make unsubstantiated assurances of absolute security.
2. **Segregation of Unconfirmed Candidates (`DEFECT-REP-01`):**
   - The primary Findings Summary table (Table 2) must include **confirmed findings only**.
   - If unconfirmed candidate findings exist, they must be rendered on a separate, dedicated `"Candidate Findings for Manual Review"` annex, clearly marked with `Detected: False` / `Status: CANDIDATE`.
3. **Automated CVSS v4.0 Vector Transparency (`DEFECT-FIND-03` / `ADR-009`):**
   - All CVSS v4.0 scores generated autonomously by scan engines must include an explicit `[ESTIMATED]` status qualifier.
   - Scores reviewed and calibrated by a certified human tester transition to `[REVIEWED]`.
4. **Tooling & Capability Grounding (`DEFECT-REP-02`):**
   - In accordance with `commit 44fd758`, all methodology and tool mentions must strictly reflect tools that actually executed in the scan runtime. Hardcoded claims of unexecuted tools (e.g. Katana, Layer-2 Proxy) are forbidden.

### 2.3 Share-Snapshot Sanitization Exclusion
- The raw asset folder `docs/assets/` contains proprietary logos (`Picture1.png`) and staff names.
- In accordance with Part 0d, `docs/assets/` is permanently excluded from the sanitized distribution snapshot generator (`scripts/make_share_snapshot.py`) and share-readiness scanner (`scripts/share_readiness_scan.py`).
