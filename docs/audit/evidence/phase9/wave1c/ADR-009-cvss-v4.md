# ADR-009: CVSS v4.0 Vulnerability Scoring Engine & Vector Architecture

> **Status:** PROPOSED (Specification Phase — Pending User Approval)  
> **Date:** 2026-11-26  
> **Auditors / Authors:** Principal Software Architect, Senior Security QA Engineer  
> **Target Wave:** Phase 9 Wave 1b (`DEFECT-FIND-03`) & Wave 1c  

---

## 1. Context & Problem Statement

Phase 7 security audit registered `DEFECT-FIND-03` (P1): 39 out of 39 (100%) confirmed findings in the production database exhibited `NULL` for `cvss_score` and `cvss_vector`. The original Wave 1b improvement plan scheduled deterministic CVSS calculation.

However, the corporate penetration testing template (`docs/assets/Report Pentest (nama aplikasi).docx` / `.md` / `.pdf`) explicitly standardizes on **FIRST Common Vulnerability Scoring System (CVSS) Version 4.0**:
$$\text{CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N}$$

To ensure compliance with the target enterprise reporting standard, Pentesa must modernize its vulnerability scoring architecture to CVSS v4.0 while maintaining strict determinism, auditability, and role-based access control.

---

## 2. CVSS v4.0 Metrics & Architecture

CVSS v4.0 introduces refined metric dimensions that differentiate between the Vulnerable System and Subsequent Systems:

### 2.1 Base Metric Groups
1. **Exploitability Metrics:**
   - **Attack Vector (AV):** Network (`N`), Adjacent (`A`), Local (`L`), Physical (`P`)
   - **Attack Complexity (AC):** Low (`L`), High (`H`)
   - **Attack Requirements (AT):** None (`N`), Present (`P`) *(New in v4.0)*
   - **Privileges Required (PR):** None (`N`), Low (`L`), High (`H`)
   - **User Interaction (UI):** None (`N`), Passive (`P`), Active (`A`) *(Refined in v4.0)*
2. **Vulnerable System Impact Metrics:**
   - **Vulnerable System Confidentiality (VC):** High (`H`), Low (`L`), None (`N`)
   - **Vulnerable System Integrity (VI):** High (`H`), Low (`L`), None (`N`)
   - **Vulnerable System Availability (VA):** High (`H`), Low (`L`), None (`N`)
3. **Subsequent System Impact Metrics:**
   - **Subsequent System Confidentiality (SC):** High (`H`), Low (`L`), None (`N`)
   - **Subsequent System Integrity (SI):** High (`H`), Low (`L`), None (`N`)
   - **Subsequent System Availability (SA):** High (`H`), Low (`L`), None (`N`)

---

## 3. CWE-to-CVSS v4.0 Baseline Vector Mapping Table

Automated probers and AI validation agents cannot reliably synthesize full multi-dimensional vectors from raw HTTP payloads without hallucination risk. Therefore, Pentesa adopts a deterministic, version-controlled baseline vector lookup table (`packages/common/cvss_vectors.yaml` or versioned JSON):
- CWE / finding type maps to a reviewed base VECTOR string.
- Scores are dynamically computed using a maintained library (`cvss` package) validated against FIRST reference vectors.
- Any finding with an unmapped or unknown type is classified as `"Not rated"` (`cvss_score = None`, `cvss_vector = None`).

### Standard Baseline Vectors & Verified FIRST Reference Scores:
| CWE ID | Vulnerability Classification | Base CVSS v4.0 Vector | Verified Score | Severity |
|---|---|---|:---:|:---:|
| **CWE-89** | SQL Injection | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **9.3** | **Critical** |
| **CWE-78** | OS Command Injection | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` | **10.0** | **Critical** |
| **CWE-22** | Path Traversal / LFI | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | **8.7** | **High** |
| **CWE-918**| Server-Side Request Forgery | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N` | **8.7** | **High** |
| **CWE-639**| Insecure Direct Object Reference (IDOR) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | **7.1** | **High** |
| **CWE-862**| Missing Authorization | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | **7.1** | **High** |
| **CWE-79** | Reflected Cross-Site Scripting | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` | **5.1** | **Medium** |
| **CWE-352**| Cross-Site Request Forgery | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` | **5.1** | **Medium** |
| *(Other)* | Unmapped / Unknown Finding Types | *None* | *None* | **Not rated** |

---

## 4. Vector Source Taxonomy & Quality Governance

To satisfy audit transparency and prevent automated vectors from being mistaken for human adjudications, each finding carries a single unified provenance field (`cvss_source`):

```
[Finding Created] 
       │
       ▼
[Automated CWE Lookup] ──► cvss_score & cvss_vector calculated
                           cvss_source = "ESTIMATED"
                           Rendered in UI & PDF as: "[Score: 9.3 HIGH - ESTIMATED]"
       │
       ▼ (Human Lead Tester Review via API / UI)
[Lead / Admin Calibration] ──► cvss_vector adjusted / confirmed
                              cvss_source = "REVIEWED"
                              reviewed_by = user.id, reviewed_at = timestamp
                              Rendered in UI & PDF as: "[Score: 9.3 HIGH - REVIEWED]"
```

---

## 5. Role-Based Access Control (RBAC) Governance

Calibration and modification of CVSS vectors directly alter client risk posture and executive reports. Access is strictly governed using real system role names (`ADMIN`, `LEAD`, `TESTER`, `VIEWER`):

1. **`VIEWER` & `TESTER` Roles:** Read-only access to CVSS scores and vectors. Any `PATCH /api/v1/findings/{id}` attempting to modify `cvss_score`, `cvss_vector`, or `cvss_source` is rejected with `HTTP 403 Forbidden`.
2. **`LEAD` & `ADMIN` Roles:** Authorized to calibrate CVSS vectors. Upon successful modification:
   - Sets `cvss_source = "REVIEWED"`.
   - Records an immutable audit log entry: `FINDING_CVSS_CALIBRATED` (capturing previous vector, new vector, and auditor user ID).

---

## 6. Implementation & Schema Target

### 6.1 Database Schema (Wave 1b Migration via Alembic ADR-007)
The `findings` table will be extended with:
- `cvss_version: Mapped[str] = mapped_column(String(10), default="4.0", nullable=False)`
- `cvss_vector: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)`
- `cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)`
- `cvss_source: Mapped[str] = mapped_column(String(20), default="ESTIMATED", nullable=False)`
- `cvss_reviewed_by: Mapped[Optional[UUID]] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True)`
- `cvss_reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)`
