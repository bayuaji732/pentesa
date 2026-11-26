# Phase 9 Wave 1c & Wave 1b: Integrated Implementation Roadmap

> **Document Identifier:** `PENTESA-AUDIT-P9-1C-WAVE-PLAN-V1.0`  
> **Evaluation Date:** `2026-11-26`  
> **Status:** Specification Complete — Awaiting Approval  
> **Auditors:** Principal Software Architect, Senior Security QA Engineer  

---

## 1. Wave Architecture & Sequencing

To maintain strict risk management and zero-downtime database evolution, the implementation is partitioned into three decoupled milestones:

```
┌────────────────────────────────────────────────────────┐
│ Wave 1b: Schema & Scoring Foundation (Requires Alembic)│
│  - Alembic Migration Foundation (ADR-007)              │
│  - DEFECT-AUD-02: Fix audit_logs FK ON DELETE RESTRICT │
│  - DEFECT-FIND-03: CVSS v4.0 Engine & Schema Columns   │
│  - Lead Tester+ RBAC for CVSS Vector Calibration       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Wave 1c-i: Template Layout & Visual Styling Adoption   │
│  - ReportLab Platypus Engine refactoring (ADR-008)     │
│  - ISO A4 geometry & 25.4 mm (1.0 in) margin bounds   │
│  - Four-Table Architecture: Tables 1, 2, 3, and 4     │
│  - Shading (#D9D9D9, #FFC000) & sub-mm column widths   │
│  - PII removal & "International" typo correction      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Wave 1c-ii: Dynamic Metadata & Reviewer Sign-Off       │
│  - ReportGenerateRequest options (retest_date, purpose)│
│  - Dynamic ProjectMember role binding to Sign-Off      │
│  - Parity HTML template (corporate_standard.html)      │
│  - Final P7B fidelity verification (score_p7b >= 95%)  │
└────────────────────────────────────────────────────────┘
```

---

## 2. Commit Schedule & Atomic Milestones

1. **Commit 1 (`WAVE-1C-SPEC`):**
   - Specification, measurements, and test harness files only:
     - `docs/audit/evidence/phase9/wave1c/1C-template-analysis.md`
     - `docs/audit/evidence/phase9/wave1c/1C-data-mapping-and-pii-review.md`
     - `docs/audit/evidence/phase9/wave1c/1C-pdf-only-impact-analysis.md`
     - `docs/audit/evidence/phase9/wave1c/ADR-008-report-renderer.md`
     - `docs/audit/evidence/phase9/wave1c/ADR-009-cvss-v4.md`
     - `benchmark/p7b/template_spec.yaml`
     - `benchmark/ground_truth_p7b_template.yaml`
     - `benchmark/p7b/score_p7b_template.py`

2. **Commit 2 (`WAVE-1B-AUD-02`):**
   - Alembic migration altering `audit_logs.user_id` foreign key constraint to `ON DELETE RESTRICT`.
   - Snapshot user email/identity into `details` at log creation time.
   - Unit test: `tests/unit/test_audit_chain_cascade_protection.py`.

3. **Commit 3 (`WAVE-1B-FIND-03`):**
   - Add CVSS v4.0 columns to `findings` table via Alembic migration (`cvss_version`, `cvss_vector`, `cvss_score`, `cvss_status`, `cvss_reviewed_by`, `cvss_reviewed_at`).
   - Implement `packages/common/cvss.py` deterministic CWE baseline calculator.
   - Implement Lead Tester+ calibration RBAC in `apps/api/routers/findings.py`.
   - Unit test: `tests/unit/test_cvss_v4_scoring.py`.

4. **Commit 4 (`WAVE-1C-I-LAYOUT`):**
   - Refactor `services/reporting_engine/renderer.py` ReportLab Platypus canvas to match `template_spec.yaml`.
   - Implement Tables 1, 2, 3, and 4 with `#D9D9D9` and `#FFC000` styling.
   - Enforce neutral zero-finding text and candidate segregation.
   - Verify with `benchmark/p7b/score_p7b_template.py` (Assert 100% pass).

5. **Commit 5 (`WAVE-1C-II-METADATA`):**
   - Extend `ReportGenerateRequest` with `retest_date`, `purpose`, and `template`.
   - Bind `ProjectMember` query to Sign-Off approval table.
   - Implement `templates/corporate_standard.html` for HTML deliverable parity.

---

## 3. Risk Assessment & Rollback Procedures

| Risk Identifier | Likelihood | Impact | Mitigation Strategy | Rollback Procedure |
|---|:---:|:---:|---|---|
| **R-1: Database Migration Lock** | Low | High | Run Alembic migrations during maintenance window with short statement timeouts (`SET statement_timeout = '5s'`). | Run `alembic downgrade -1` to roll back schema mutations cleanly. |
| **R-2: Report Formatting Regression** | Low | Medium | Retain existing `ptes_standard` layout accessible via `template="ptes_standard"`. | Set default template parameter back to `"ptes_standard"`. |
| **R-3: Personnel PII Leakage** | Low | High | Automated CI/CD check enforcing zero hardcoded staff names in templates or code. | Immediate git commit replacing hardcoded string with dynamic `User.full_name`. |

---

## 4. Resource & Authorized Budget Allocation

- **Live LLM Gateway Spend:** **$0.00 / 0 tokens** (All template styling, table geometry, scoring math, and database migrations execute deterministically in Python without upstream AI gateway calls).
- **Authorized Wave 1 Cap Remaining:** **$0.9996 / 29,930 tokens** (Reserved for active testing if required).
