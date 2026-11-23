# Pentesa — Findings, Evidence & Reporting Quality Assessment (Phase 7)

> **Document Identifier:** PENTESA-AUDIT-08-FINDINGS-QUALITY-V1.0  
> **Audit Phase:** Phase 7 — Findings and Evidence Quality (Evaluation Only)  
> **Auditors:** Independent Principal Software Architect, Senior Application Security Engineer, Security QA & AI Evaluation Lead  
> **Date:** November 2026  
> **Target Environment:** `pentesa-prod` (`http://127.0.0.1:8000` / PostgreSQL 16 on `pentesa-internal`, post approved hotfix `hotfix-api-02`)  
> **Frozen Design Tag:** `p7-design-complete` (`782e894`)  
> **Authoritative Scorer Output:** [`docs/audit/evidence/phase7/score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt)  
> **Status:** Completed — 5 Passed (`Verified` / `Partially Verified`), 2 Partially Verified, 5 Failed (Strict Pass Rate: **41.7%**); 0 Canary Hits; Restored to `demo-known-good` (6/6 Cleanup Gates)

---

## 1. Executive Summary & Governance Invariants

This report presents the empirical, deterministic evaluation of **Phase 7: Findings and Evidence Quality** against the Pentesa platform in strict adherence to `docs/audit/00-master-prompt.md` and the frozen Phase 7 specification [`docs/audit/evidence/phase7/7A-spec.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/7A-spec.md):

1. **Evaluation-Only Invariant:** Zero platform production source code was modified during Phase 7. All measurements ran against `pentesa-prod` as-is (incorporating only the previously approved `hotfix-api-02` deviation on `apps/api/dependencies.py`).
2. **Pre-Execution Freeze & Cryptographic Traceability:**
   - **Specification (`7A-spec.md`):** SHA-256 `a98a7ab377c38fd8a204b7d7e0de0b67ef94a57ceb809da4791259e5ca1452ea`
   - **Frozen Ground Truth ([`benchmark/ground_truth_p7.yaml`](file:///c:/Users/User2/Documents/work/pentesa/benchmark/ground_truth_p7.yaml)):** SHA-256 `acd209a69a3b0c8a83d936f498945797e8842fcb815b8295cc31129957c0cac4`
   - **Frozen Scorer ([`benchmark/score_p7.py`](file:///c:/Users/User2/Documents/work/pentesa/benchmark/score_p7.py)):** SHA-256 `2741d23c5df6183517cd25cab0a390fb8318e52d5f58084a0b9963bd5bd66ddd`
   - **Evaluation Runner ([`benchmark/p7/test_runner_p7.py`](file:///c:/Users/User2/Documents/work/pentesa/benchmark/p7/test_runner_p7.py)):** SHA-256 `4736fb5df2517b25dcc383b69754f075d8108dc85c9612348127830b7c60385f`
   - **Machine Results ([`docs/audit/evidence/phase7/p7_test_results.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_test_results.json)):** SHA-256 `f409cadfe3debc5e768e0879f722c44013202cdae24068401001ac79be3019e8`
   - **Scorer Output ([`docs/audit/evidence/phase7/score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt)):** Machine-captured via `Tee-Object`; all numbers in this report come verbatim from `score_p7.py`.
3. **Objective Metrics Only:** All metrics are deterministic and machine-computed. Subjective judgements are excluded from scoring.
4. **Phase 10 Vocabulary Only:** Every requirement and dimension uses strictly `Verified`, `Partially Verified`, `Failed`, `Not Implemented`, or `Not Tested`.
5. **Prior/Failed Runs Disclosure:** Two prior runner invocations failed or hit harness-parsing bugs before the authoritative clean run and are preserved verbatim in [`docs/audit/evidence/phase7/p7_failed_runs_addendum.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_failed_runs_addendum.txt):
   - *Initial Run (Aborted in Phase A):* `yaml.safe_load` failed on unquoted colon in frozen Phase 4 `benchmark/ground_truth_p4.yaml:202` (`HARNESS BUG`; read as text instead without touching frozen GT4).
   - *Superseded Run 1 (Completed):* `HARNESS BUG` in `test_runner_p7.py` checked `is_valid` instead of schema key `verified` on `/api/v1/reports/verify`, omitted `html.unescape()` in `strip_html()`, and lacked `ASCII85Decode` before `FlateDecode` in PDF text extraction. Fixed harness bugs only; frozen `ground_truth_p7.yaml` and `score_p7.py` were NEVER modified.
6. **Live LLM Spend & Budget Cap:** Live gateway (`azure/gpt-5.6-terra-dev-gtw`, health gate `max_completion_tokens=50`) consumed **2,434 tokens / \$0.0144 USD** in the final run (**4,816 tokens / \$0.0283 USD** cumulative across Run 1 + Final Run = **1.41%** of the \$2.00 / 60,000-token cap; tallied in [`docs/audit/evidence/phase7/cost-log.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/cost-log.md)).
7. **Safety & Cleanup Proof:** **0 canary hits** (`bench-canary-sensor:9099`); temporary bench network attach detached and proved; `pentesa-prod` restored cleanly to `demo-known-good` baseline (**6/6 gates passed** in [`docs/audit/evidence/phase7/p7_cleanup_proof.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_cleanup_proof.txt)).

---

## 2. Authoritative Phase 7 Metrics Table (From `score_p7.py`)

| Metric | Authoritative Value (`score_p7.py`) | Evidence Artifact |
|---|---:|---|
| **Total Test Cases Evaluated** | **12** (5 Pass, 2 Partial, 5 Fail, 0 NotImpl, 0 NotTest) | [`score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt) |
| **Strict Benchmark Pass Rate** | **41.7%** (5 / 12) | [`score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt) |
| **Production Findings Evaluated via API** | **39** (all 28 prod projects queried via API) | [`p7_completeness_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_completeness_audit.json) |
| **15-Field Completeness (Strict `score.py` Key View)** | **46.7%** (7/15 fields present) | [`p7_completeness_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_completeness_audit.json) |
| **15-Field Completeness (Joined `FindingResponse` + `/evidence`)** | **60.0%** (9–10/15 fields; `endpoint`/`method`/`target`/`parameter`/`fp_assessment` = 0/39) | [`p7_completeness_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_completeness_audit.json) |
| **Evidence SHA-256 Match Rate (All 39 Prod Rows)** | **100.0%** (39/39 request + 39/39 response) | [`score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt) |
| **Evidence Tamper Detection Rate (In-Memory Copy)** | **100.0%** (78/78 1-byte mutations detected; 0 prod mutations) | [`score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt) |
| **Existing Prod Secret Leaks (Findings + Evidence + Report)** | **0** leaks | [`score_p7.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/score_p7.txt) |
| **Planted Canary Secret Redaction Rate** | **83.33%** (5/6 redacted; custom canary leaked in 3 surfaces) | [`p7_test_results.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_test_results.json) |
| **Reproduction Replay Success Rate (8 Unique Curls × 3)** | **100.0%** (24/24 vuln signature reproduced; 21/24 = 87.5% HTTP status match) | [`p7_reproduction_replays.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_reproduction_replays.json) |
| **Reproduction Scope / Destructive / Canary Violations** | **0 / 0 / 0** (bench attach/detach verified) | [`p7_reproduction_replays.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_reproduction_replays.json) |
| **Accuracy: Adjudicated TP / FP (39 Prod Findings)** | **39 TP / 0 FP** (100.0% adjudicated precision) | [`p7_accuracy_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_accuracy_audit.json) |
| **Accuracy: CVSS v3.1 Band Consistency** | **0.0%** (`cvss_score` is `NULL` on 39/39 prod findings) | [`p7_accuracy_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_accuracy_audit.json) |
| **Accuracy: WSTG ↔ CWE Mapping Validity** | **100.0%** (39/39 valid) | [`p7_accuracy_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_accuracy_audit.json) |
| **Deduplication Cluster Accuracy** | **66.7%** (ingestion auto-dedup=`False`; null-endpoint over-clustered) | [`p7_test_results.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_test_results.json) |
| **Report Export Factual Fidelity (12 Reports: HTML & PDF × 3 × 2)** | **87.5%** (42/48 checks; 24/24 HTML, 18/24 PDF) | [`p7_report_quality_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_report_quality_audit.json) |
| **Report Cross-Run Factual Consistency (3 Generations Each)** | **100.0%** (4/4 format groups identical across 3 runs) | [`p7_report_quality_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_report_quality_audit.json) |
| **Empty Report Claims Target Is Secure** | **True** (FAIL — `"strong security posture"` in HTML) | [`p7_report_quality_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_report_quality_audit.json) |
| **Candidate vs Confirmed Properly Separated in Report** | **False** (FAIL — `Detected` counted in `total_findings`; PDF omits `Status`) | [`p7_report_quality_audit.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_report_quality_audit.json) |
| **LLM Summary Groundedness & Remediation Correctness (3× Live)** | **100.0%** (6/6 statements grounded, 6/6 remediations valid, **0** fabricated CVEs/URLs) | [`p7_llm_report_eval.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_llm_report_eval.json) |
| **Lifecycle Supported Controls Pass Rate** | **100.0%** (5/5 implemented controls pass; assignment & `FLAGGED_FOR_HUMAN_REVIEW` `Not Implemented`) | [`p7_test_results.json`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_test_results.json) |

---

## 3. Tested-and-OK / Tested-and-Failed / Not-Tested & Not-Implemented Split

### 3.1 Tested and OK (`Verified` / `Partially Verified` Passing Controls)

| Case ID | Dimension | Mode | Phase 10 Status | Evidence Summary |
|---|---|:---:|:---:|---|
| **`P7-TC-INT-01`** | (b) Evidence Integrity | `WIRE` | **Verified** | Recomputed SHA-256 matches stored `request_hash_sha256` (39/39) and `response_hash_sha256` (39/39) on all 39 prod evidence rows via API (`100.0%`). |
| **`P7-TC-INT-02`** | (b) Evidence Integrity | `IN-PROCESS` | **Partially Verified** | Single-byte mutations on in-memory copies of all 39 evidence records (78 mutations total) detected 78/78 (`100.0%`); 0 production rows mutated. |
| **`P7-TC-REDACT-01`** | (c) Redaction (Existing Prod) | `WIRE` | **Verified** | Zero unredacted Bearer/Basic tokens, cookies, passwords, or Luhn-valid PANs found across all 39 prod findings, 39 evidence records, reproduction curls, and existing demo report. |
| **`P7-TC-REPRO-01`** | (d) Reproduction Replay | `WIRE` | **Verified** | All 8 unique confirmed reproduction curls replayed 3× (24/24 replays) against freshly reset bench targets: `100.0%` vulnerability signature reproduction (`bench-crapi-web/.env` verified real 201-byte `application/octet-stream` `.env` exposure; `bench-pentesa-app` SQLi/XSS, `bench-juiceshop` SQLi, and missing headers confirmed), 0 scope violations, 0 destructive actions, 0 canary hits, verified bench network detachment. *(Minor P3 note `DEFECT-REPRO-01`: `bench-dvwa` curl omits `-L`, yielding HTTP 302 vs stored HTTP 200 on 3/24 replays = 87.5% status match).* |
| **`P7-TC-REP-03`** | (g) LLM Report Groundedness | `WIRE` | **Verified** | Live Azure GPT-5.6 gateway (`azure/gpt-5.6-terra-dev-gtw`, 3× runs) achieved 6/6 (`100.0%`) grounded statements mapped to DB findings, 6/6 (`100.0%`) WSTG/CWE-correct remediations, 0 fabricated CVEs/URLs, and 100% 3-run count consistency. *(Note: `POST /reports/generate` uses deterministic Jinja2/ReportLab templates; LLM synthesis runs via `ReportingAgent` AGT-15).* |

### 3.2 Tested and Failed / Partially Verified With Defects

| Case ID | Dimension | Mode | Phase 10 Status | Root Finding & Linked Defect |
|---|---|:---:|:---:|---|
| **`P7-TC-COMP-01`** | (a) Field Completeness | `WIRE` | **Failed** | Strict `score.py` API completeness = **46.7%** (7/15); joined `FindingResponse` + `/evidence` = **60.0%** (9–10/15). `endpoint`, `method`, `target`, `parameter` alias, and `false_positive_assessment` are `0/39` on API (`P1-FIND-02`). `affected_parameter` (singular) present on 18/39; `cvss_score` and `cvss_vector` present on **0/39** (`DEFECT-FIND-03`). |
| **`P7-TC-ACC-01`** | (e) Accuracy & CVSS/Mapping | `STATIC` | **Failed** | All 39 prod findings adjudicated **39 TP / 0 FP** (100% WSTG↔CWE validity, 100% severity plausibility), **but failed because `cvss_score` is `NULL` on 39/39 (0.0% CVSS band consistency)** (`DEFECT-FIND-03`). Note also `/ssti/secure` (1 finding) was flagged for Reflected XSS (`CWE-79`) because the bench control disables SSTI evaluation without HTML-escaping `<script>`. |
| **`P7-TC-REDACT-02`** | (c) Planted Canary Redaction | `WIRE` | **Partially Verified** | Standard secrets (Bearer JWT, Cookie session, JSON password, form password, Luhn PAN) achieved **5/5 (100%)** redaction across all 6 surfaces (`raw_request`, `raw_response`, `reproduction_curl`, `description`, HTML, PDF). However, custom planted canary secret (`PENTESA_P7_CANARY_SECRET_9f8e7d6c`) leaked in `raw_response`, `finding_description`, and `html_report` (**5/6 = 83.33%**, `DEFECT-REDACT-01`). |
| **`P7-TC-DEDUP-01`** | (f) Deduplication | `WIRE` | **Partially Verified** | `POST /findings` does **not** deduplicate at ingestion (`6/6` rows persisted). `GET /findings/deduplicate` accurately clusters exact linked-endpoint duplicates (`exact_pair_clustered=True`, `near_dups_kept_separate=True`) but collapses all `endpoint_id=None` findings onto `"global|ANY"`, falsely merging distinct `/.env` and `/debug/vars` findings (**66.7%** accuracy, `DEFECT-DEDUP-01`). |
| **`P7-TC-REP-01`** | (g) Report Factual Fidelity | `WIRE` | **Failed** | All 12 reports (HTML & PDF × 3 × 2) generated cleanly, passed `/api/v1/reports/verify` (`12/12`), matched DB severity counts (`12/12`), and achieved **100.0%** cross-run consistency. HTML passed **24/24 (100%)** checks; PDF text extraction failed `titles_ok`/`cwes_ok` on the 3 findings PDFs (6/48 checks -> **87.5%**) due to ReportLab font/kerning stream encoding vs stdlib regex parsing (reported plainly per frozen scorer output). |
| **`P7-TC-REP-02`** | (g) Report Safety & Labelling | `WIRE` | **Failed** | Three platform defects empirically proven: (1) zero-finding report emits `"STRONG SECURITY POSTURE"` (`context_builder.py:191`, `DEFECT-REP-01`); (2) unconfirmed `Detected` candidates are mixed into `total_findings` (`2` instead of `1` confirmed) and PDF omits the `Status` column (`DEFECT-REP-01`); (3) HTML template hardcodes 4 ungrounded claims (`Layer 2 kernel/proxy`, `Katana`, `Httpx`, `LangGraph`) (`DEFECT-REP-02`). |
| **`P7-TC-LIFE-01`** | (h) Finding Lifecycle | `WIRE` | **Partially Verified** | All 5 implemented API controls passed **100.0%** (valid transitions `Detected -> Triaged -> Validating -> Confirmed -> Accepted Risk -> Confirmed -> Remediated -> Retested`, illegal transition rejected with HTTP 400, false-positive refutation HTTP 201, one-click retest HTTP 200, complete audit logging). Two capabilities are `Not Implemented` (see §3.3). |

### 3.3 Not Implemented / Not Tested Items

| Capability | Phase 10 Status | Basis & Defect Reference |
|---|:---:|---|
| **Finding Assignment (`assigned_to` / `PATCH .../assign`)** | **Not Implemented** | Verified absent from OpenAPI schema, `database/models/finding.py`, `packages/schemas/finding.py`, and `apps/api/routers/findings.py` (`DEFECT-LIFE-01`). |
| **`FLAGGED_FOR_HUMAN_REVIEW` Finding Status** | **Not Implemented** | Live API `PATCH .../status` with `FLAGGED_FOR_HUMAN_REVIEW` returned HTTP 400; known `DEFECT-BUSL-01`. |
| **Headless DOM Screenshot Capture in Evidence (`screenshot_path`)** | **Not Tested** | All 39 prod findings have `screenshot_path=None`; Playwright evidence screenshot capture was not exercised in Phase 7. |
| **WeasyPrint PDF Engine (Specified in PRD/SRS/Spec 15)** | **Not Implemented** | `services/reporting_engine/renderer.py` uses **ReportLab** (`SimpleDocTemplate`), not WeasyPrint, producing a divergent 5-section layout instead of the HTML template's 17-section PTES layout. |

---

## 4. Per-Field API Completeness Breakdown (`P7-TC-COMP-01`, $n = 39$)

| # | Phase 7 Field (`score.py`) | Strict API View (`FindingResponse`) | Joined API View (`FindingResponse` + `/evidence`) | Observation |
|---:|---|---:|---:|---|
| 1 | `id` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | Present as UUID |
| 2 | `target` | 0 / 39 (0.0%) | 0 / 39 (0.0%) | Absent from `FindingResponse` (`P1-FIND-02`) |
| 3 | `endpoint` | 0 / 39 (0.0%) | 0 / 39 (0.0%) | Only `endpoint_id` UUID returned (`P1-FIND-02`) |
| 4 | `method` | 0 / 39 (0.0%) | 0 / 39 (0.0%) | Absent from `FindingResponse` (`P1-FIND-02`) |
| 5 | `parameter` | 0 / 39 (0.0%) | 0 / 39 (0.0%) | Singular `affected_parameter` present on 18/39; `parameter` alias absent (`P1-FIND-02`) |
| 6 | `wstg_id` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | 100% populated & valid |
| 7 | `cwe_id` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | 100% populated & valid |
| 8 | `detection_source` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | `check_runner` (24), `wstg_agent` (15) |
| 9 | `reproduction_procedure` | 0 / 39 (0.0%) | 39 / 39 (100.0%) | Nested under `evidence[0].reproduction_curl` |
| 10 | `actual_evidence` | 0 / 39 (0.0%) | 39 / 39 (100.0%) | Nested under `evidence[0].raw_request`/`raw_response` |
| 11 | `severity_justification` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | Satisfied via `severity` + `description`; `cvss_score`/`cvss_vector` = **0/39** (`DEFECT-FIND-03`) |
| 12 | `confidence` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | 100% populated |
| 13 | `false_positive_assessment` | 0 / 39 (0.0%) | 0 / 39 (0.0%) | Absent from `FindingResponse` |
| 14 | `remediation` | 0 / 39 (0.0%) | 39 / 39 (100.0%) | Exposed as `remediation_guidance` (100% populated) |
| 15 | `validation_status` | 39 / 39 (100.0%) | 39 / 39 (100.0%) | Exposed as `status` (`Confirmed`) |
| — | **Mean Completeness** | **46.7%** | **60.0%** | **Failed (`P1-FIND-02` & `DEFECT-FIND-03`)** |

---

## 5. Defects Registered in Phase 7

All defects below have been added to [`docs/audit/03-defect-register.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/03-defect-register.md) and [`docs/audit/10-improvement-roadmap.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/10-improvement-roadmap.md) with full root cause, evidence, recommended fix, affected components, regression tests, and acceptance criteria:

| Defect ID | Priority | Component | Summary |
|---|:---:|---|---|
| **`P1-FIND-02`** | **P1** (Re-Confirmed) | `packages/schemas/finding.py`, `apps/api/routers/findings.py` | `FindingResponse` omits `endpoint`, `method`, `target`, `parameter` alias, and `false_positive_assessment` (46.7% strict / 60.0% joined API completeness). |
| **`DEFECT-FIND-03`** | **P1** (New) | `services/evidence_engine/finding_service.py`, `services/execution_engine/runners.py`, `agents/` | `cvss_score` and `cvss_vector` are `NULL` on 39/39 (100%) of production confirmed findings (0.0% CVSS band consistency). |
| **`DEFECT-REP-01`** | **P1** (New) | `services/reporting_engine/context_builder.py`, `renderer.py` | Zero-finding reports assert `"STRONG SECURITY POSTURE"` (`context_builder.py:191`); unconfirmed `Detected` candidates are counted alongside `Confirmed` findings, and PDF omits `Status`. |
| **`DEFECT-REP-02`** | **P2** (New) | `services/reporting_engine/templates/ptes_standard.html` | PTES HTML template hardcodes 4 ungrounded claims (`Layer 2 kernel/proxy`, `Katana`, `Httpx`, `LangGraph`) absent from the platform. |
| **`DEFECT-REDACT-01`** | **P2** (New) | `services/evidence_engine/finding_service.py`, `redactor.py` | Custom project secrets (`AuthProfile` / canary tokens) are not passed into `redact_raw_stream()`, and finding text fields (`description`/`title`) are not scrubbed before persistence/export. |
| **`DEFECT-DEDUP-01`** | **P2** (New) | `services/evidence_engine/finding_service.py` | `POST /findings` performs zero ingestion-time deduplication; `GET /deduplicate` collapses all `endpoint_id=None` findings onto `"global|ANY"`, falsely merging distinct vulnerabilities. |
| **`DEFECT-LIFE-01`** | **P3** (New) | `database/models/finding.py`, `apps/api/routers/findings.py` | Finding assignment (`assigned_to` field/route) is `Not Implemented` (alongside known `DEFECT-BUSL-01` `FLAGGED_FOR_HUMAN_REVIEW`). |
| **`DEFECT-REPRO-01`** | **P3** (New) | `services/evidence_engine/curl_generator.py` | Generated `reproduction_curl` omits `-L` when target root issues HTTP 302 redirect (`bench-dvwa`), producing status mismatch (302 replay vs 200 stored). |

---

## 6. Evidence & Restoration Sign-Off

- **Phase 7 Cleanup & Restore Proof:** [`docs/audit/evidence/phase7/p7_cleanup_proof.txt`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/p7_cleanup_proof.txt) — 6/6 gates passed (`users=2, projects=28, findings=39, finding_evidence=39, reports=1, audit_logs=1258`, head `97e166a6108be5ef0e5983ad45e9d7fd2f3c6f7efeafd702939327a08208ade4`, real admin 200, `admin@example.com` 401, `benchmark-admin` inactive, detached from bench/canary).
- **Cryptographic Manifest:** [`docs/audit/evidence/phase7/MANIFEST.sha256`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/evidence/phase7/MANIFEST.sha256) verified with zero mismatches.
- **Phase 8 Readiness:** Phase 7 evaluation is complete. Ready to proceed to **Phase 8 (Documentation Reconciliation)** upon user approval.
