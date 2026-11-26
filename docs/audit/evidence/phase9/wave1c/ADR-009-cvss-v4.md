# ADR-009: CVSS v4.0 Vulnerability Scoring Engine & Vector Architecture

> **Status:** PROPOSED (Specification Phase — Pending User Approval)  
> **Date:** 2026-11-26  
> **Auditors / Authors:** Principal Software Architect, Senior Security QA Engineer  
> **Target Wave:** Phase 9 Wave 1b (`DEFECT-FIND-03`) & Wave 1c  

---

## 1. Context & Problem Statement

Phase 7 security audit registered `DEFECT-FIND-03` (P1): 39 out of 39 (100%) confirmed findings in the production database exhibited `NULL` for `cvss_score` and `cvss_vector`. The original Wave 1b improvement plan scheduled deterministic CVSS v3.1 calculation.

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

## 3. CWE-to-CVSS v4.0 Baseline Mapping Matrix

Automated probers and AI validation agents cannot reliably compute full multi-dimensional vectors from raw HTTP payloads without hallucination risk. Therefore, Pentesa adopts a deterministic CWE vector baseline lookup table, ensuring $100\%$ reproducible, zero-drift initial scores:

| CWE ID | Vulnerability Class | CVSS v4.0 Vector String | Base Score | Severity |
|---|---|---|---|---|
| **CWE-89** | SQL Injection | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **9.3** | **Critical** |
| **CWE-78** | OS Command Injection | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` | **10.0** | **Critical** |
| **CWE-22** | Path Traversal / LFI | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | **8.7** | **High** |
| **CWE-918**| Server-Side Request Forgery | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N` | **8.7** | **High** |
| **CWE-862**| Insecure Direct Object Reference | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | **7.1** | **High** |
| **CWE-79** | Stored Cross-Site Scripting | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:N/SC:L/SI:L/SA:N` | **6.8** | **Medium** |
| **CWE-79** | Reflected Cross-Site Scripting | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` | **5.1** | **Medium** |
| **CWE-352**| Cross-Site Request Forgery | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` | **5.1** | **Medium** |
| **CWE-693**| Missing Security Headers | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` | **2.3** | **Low** |
| **CWE-200**| Information Exposure (Banner) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | **5.3** | **Medium** |

---

## 4. Vector State Taxonomy & Quality Governance

To satisfy the transparency requirements of `docs/00-master-prompt.md` and prevent automated scores from being mistaken for human adjudications, each finding carries a CVSS review state:

```
[Finding Created] 
       │
       ▼
[Automated CWE Lookup] ──► cvss_score & cvss_vector populated
                           cvss_status = "ESTIMATED"
                           Rendered in UI & PDF as: "[Score: 9.3 HIGH - ESTIMATED]"
       │
       ▼ (Human Lead Tester Review via API / UI)
[Lead Tester Calibration] ──► cvss_vector adjusted / confirmed
                             cvss_status = "REVIEWED"
                             reviewed_by = user.id, reviewed_at = timestamp
                             Rendered in UI & PDF as: "[Score: 9.3 HIGH - REVIEWED]"
```

---

## 5. Role-Based Access Control (RBAC) Governance

Calibration and modification of CVSS vectors directly alter client risk posture and executive reports. Access is strictly governed:

1. **`Role.VIEWER` & `Role.TESTER`:** Read-only access to CVSS scores and vectors. Any `PATCH /api/v1/findings/{id}` attempting to modify `cvss_score`, `cvss_vector`, or `cvss_status` is rejected with `HTTP 403 Forbidden`.
2. **`Role.LEAD_TESTER` & `Role.ADMIN`:** Authorized to calibrate CVSS vectors. Upon successful modification:
   - Sets `cvss_status = "REVIEWED"`.
   - Records an immutable audit log entry: `FINDING_CVSS_CALIBRATED` (capturing previous vector, new vector, and auditor user ID).

---

## 6. Implementation & Library Selection

### 6.1 Library Choice
The platform will utilize the official `cvss` Python library (maintained by Red Hat and FIRST packaging, with complete CVSS v2, v3.0, v3.1, and v4.0 mathematical scoring implementations) or a zero-dependency deterministic scoring module (`packages/common/cvss.py`).

### 6.2 Database Model Enhancements (Wave 1b Schema Target via Alembic ADR-007)
The `findings` table will be extended with:
- `cvss_version: Mapped[str] = mapped_column(String(10), default="4.0", nullable=False)`
- `cvss_vector: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)`
- `cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)`
- `cvss_status: Mapped[str] = mapped_column(String(20), default="ESTIMATED", nullable=False)`
- `cvss_reviewed_by: Mapped[Optional[UUID]] = mapped_column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)`
- `cvss_reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)`
