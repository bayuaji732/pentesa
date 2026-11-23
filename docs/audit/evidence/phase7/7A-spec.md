# Phase 7 Specification: Findings & Evidence Quality Evaluation (7A-Spec)

> **Document Identifier:** PENTESA-AUDIT-P7A-SPEC-V1.0  
> **Audit Phase:** Phase 7 — Findings and Evidence Quality (Evaluation Only)  
> **Sources Audited:**
> - `docs/audit/00-master-prompt.md` (§ PHASE 7: Findings and Evidence Quality, lines 216–236)
> - `benchmark/score.py::evaluate_evidence_completeness` (`PHASE_7_REQUIRED_FIELDS`, lines 26–42 & 122–180)
> - `docs/01-prd.md` (§4.7 Vulnerability Validation & Evidence, §4.9 Findings Management, §4.10 PTES Reporting Engine)
> - `docs/02-srs.md` (§4.7 SRS-FR-VV-001..005, §4.9 SRS-FR-FM-001..004, §4.10 SRS-FR-RP-001..004)
> - `docs/14-evidence-and-findings.md` (Evidence Philosophy, Granular Finding Data Model, SHA-256 Hashing, Redaction, Deduplication, Lifecycle)
> - `docs/15-reporting-specification.md` (17-Section PTES Report Structure, Deliverables, Integrity Sealing)
> **Governance Rules:** Evaluation-only (zero platform code modifications). Frozen ground truth (`benchmark/ground_truth_p7.yaml`) and deterministic scorer (`benchmark/score_p7.py`) committed and tagged `p7-design-complete` BEFORE any test execution. Objective deterministic metrics only; subjective judgements are advisory only and never used as metrics. Phase 10 vocabulary only (`Verified`, `Partially Verified`, `Failed`, `Not Implemented`, `Not Tested`).

---

## 1. Requirements Inventory & Mapping to Phase 7 Test Cases

Every requirement being evaluated in Phase 7 is assigned a unique specification ID (`P7-REQ-*`) mapped directly to its authoritative source document, target platform component, and frozen ground-truth test case ID (`P7-TC-*`).

| Spec ID | Dimension | Requirement Description | Source Reference | Platform Component / API Surface | Ground Truth Test ID |
|---|---|---|---|---|---|
| **P7-REQ-A01** | (a) Field Completeness | Every finding exposed via user-facing API (`FindingResponse` + `/evidence`) must populate all 15 mandatory Phase 7 fields: `id`, `target`, `endpoint`, `method`, `parameter`, `wstg_id`, `cwe_id`, `detection_source`, `reproduction_procedure`, `actual_evidence`, `severity_justification`, `confidence`, `false_positive_assessment`, `remediation`, `validation_status`. | Master Prompt Phase 7; `benchmark/score.py:26-42`; SRS-FR-FM-001; Spec 14 §2 | `packages/schemas/finding.py`, `GET /api/v1/projects/{id}/findings`, `GET .../evidence` | `P7-TC-COMP-01` |
| **P7-REQ-A02** | (a) Field Completeness | API `FindingResponse` must expose root `endpoint`, `method`, and standardized `parameter` naming (explicitly measuring known defect `P1-FIND-02`). | `03-defect-register.md` (`P1-FIND-02`); Spec 14 §2 | `packages/schemas/finding.py::FindingResponse` | `P7-TC-COMP-01` |
| **P7-REQ-B01** | (b) Evidence Integrity | Recomputed `SHA-256(raw_request)` and `SHA-256(raw_response)` must match stored `request_hash_sha256` and `response_hash_sha256` across 100% of production `finding_evidence` records. | PRD FR-VV-03; SRS-FR-VV-002; Spec 14 §3.3 | `services/evidence_engine/hasher.py`, `finding_evidence` table via API | `P7-TC-INT-01` |
| **P7-REQ-B02** | (b) Evidence Integrity | Single-byte mutation of `raw_request` or `raw_response` on a non-production copy must be deterministically detected by hash verification without mutating production rows. | Master Prompt Phase 7; PRD FR-VV-03; Spec 14 §3.3 | `services/evidence_engine/hasher.py` (tested on in-memory copy only) | `P7-TC-INT-02` |
| **P7-REQ-C01** | (c) Redaction | Existing production findings, evidence raw HTTP streams, reproduction cURLs, and generated HTML/PDF reports must contain zero unredacted secrets (Bearer/Basic tokens, Cookie/Set-Cookie values, JSON/form passwords, credit card PANs). | PRD FR-VV-04; SRS-FR-VV-003; Spec 14 §3.4 | `services/evidence_engine/redactor.py`, `curl_generator.py`, `reporting_engine/` | `P7-TC-REDACT-01` |
| **P7-REQ-C02** | (c) Redaction | Planted canary secrets (Bearer JWT, Cookie session, JSON password, form password, credit card PAN, custom canary token) ingested via `POST /findings` on a throwaway project must be redacted in stored API evidence, reproduction cURL, and exported HTML/PDF reports. | PRD FR-VV-04; SRS-FR-VV-003; Spec 14 §3.4 | `FindingService.create_finding`, `redact_raw_stream`, `generate_reproduction_curl`, `ReportingService` | `P7-TC-REDACT-02` |
| **P7-REQ-D01** | (d) Reproduction | Each confirmed finding's `reproduction_curl` must execute cleanly against freshly reset authorized bench targets across 3 independent replays, reproducing the HTTP status/vulnerability indicator matching stored evidence. | Master Prompt Phase 7; PRD FR-VV-02/05; Spec 14 §1 & §3.2 | `finding_evidence.reproduction_curl` against `pentesa-bench`, `juiceshop`, `dvwa`, `crapi` | `P7-TC-REPRO-01` |
| **P7-REQ-D02** | (d) Reproduction | Every reproduction command must stay strictly within authorized project scope (0 canary hits, 0 external hosts) and be non-destructive (no destructive verbs/payloads). Temporary bench network attach must be detached and proven. | Master Prompt Rules; PRD §9 Constraints | Scope rules, `bench-canary-sensor:9099`, `docker inspect` | `P7-TC-REPRO-01` |
| **P7-REQ-E01** | (e) Accuracy | Confirmed findings in prod DB (39) and Phase 3/4 evidence JSON must be evaluated against frozen ground truth (`ground_truth.yaml`, `ground_truth_p4.yaml`) and oracle adjudication for TP/FP classification. | Master Prompt Phase 7; Phase 3/4 GT | Production `findings` (39 rows) + `docs/audit/evidence/phase3/`, `phase4/` | `P7-TC-ACC-01` |
| **P7-REQ-E02** | (e) Accuracy | Severity and CVSS v3.1 scores must be internally consistent (score within CVSS band) and plausible against reference severities; WSTG and CWE mappings must match OWASP WSTG v4.2 ↔ CWE standards. | PRD FR-VV-04; SRS-FR-FM-001; Spec 15 §14 | `findings.severity`, `cvss_score`, `cwe_id`, `wstg_id` | `P7-TC-ACC-01` |
| **P7-REQ-F01** | (f) Deduplication | Controlled exact-duplicate and near-duplicate findings submitted via the real API (`POST /findings` + `GET /findings/deduplicate`) on a throwaway project must cluster exact duplicates accurately without over-clustering distinct parameters/endpoints and must document whether ingestion prevents duplicate creation. | PRD FR-FM-02; SRS-FR-FM-002; Spec 14 §5 | `apps/api/routers/findings.py`, `FindingService.deduplicate_findings` | `P7-TC-DEDUP-01` |
| **P7-REQ-G01** | (g) Report Quality | Generate every supported export format (`HTML` and `PDF`) 3 times each for (1) a project with confirmed findings and (2) a project with zero findings; verify every severity count, total, title, CWE, and endpoint against DB truth, and verify cross-generation factual consistency. | PRD FR-RP-01..04; SRS-FR-RP-001..004; Spec 15 | `POST /api/v1/projects/{id}/reports/generate`, `GET /api/v1/reports/{id}/download`, `ReportingService` | `P7-TC-REP-01` |
| **P7-REQ-G02** | (g) Report Quality | Zero-finding reports must NEVER claim the target is secure (no "strong security posture" / "application is secure" claims). Reports must clearly distinguish `Confirmed` vs unconfirmed candidate (`Detected` / `Triaged`) findings, and must not emit ungrounded infrastructure claims (e.g., non-existent Layer-2 proxy / Katana / LangGraph). | Master Prompt Phase 7; PRD FR-RP-02; Spec 15 | `services/reporting_engine/context_builder.py`, `templates/ptes_standard.html`, `renderer.py` | `P7-TC-REP-02` |
| **P7-REQ-G03** | (g) Report Quality | LLM-written executive summaries and remediation guidance (invoked via live Azure GPT-5.6 gateway after health gate `max_completion_tokens>=50`, 3 generations, budget cap \$2 / 60k tokens) must be grounded (every claim mapped to a DB finding or flagged unsupported), technically correct against WSTG/CWE references, free of fabricated CVEs or URLs, and factually consistent across all 3 generations. | Master Prompt Phase 7; SRS-FR-AG-006; Spec 15 §3 & §10 | `agents/reporting/reporting_agent.py` prompt via live LiteLLM gateway (`azure/gpt-5.6-terra-dev-gtw`) | `P7-TC-REP-03` |
| **P7-REQ-H01** | (h) Lifecycle | API must enforce valid finding status transitions (`Detected -> Triaged -> Validating -> Confirmed -> Accepted Risk -> Confirmed -> Remediated -> Retested`), reject illegal transitions (HTTP 400), support false-positive refutation (`POST /false-positive`), support one-click retest (`POST /retest`), and write tamper-evident audit logs for each lifecycle event. | PRD FR-VV-01, FR-FM-03/04; SRS-FR-FM-003/04 | `apps/api/routers/findings.py`, `FindingService`, `audit_logs` | `P7-TC-LIFE-01` |
| **P7-REQ-H02** | (h) Lifecycle | Evaluate finding assignment capability and `FLAGGED_FOR_HUMAN_REVIEW` status via API; explicitly record `Not Implemented` for absent features (`FLAGGED_FOR_HUMAN_REVIEW` is known `DEFECT-BUSL-01`; check whether assignment field/route exists). | PRD FR-AB-05; `03-defect-register.md` (`DEFECT-BUSL-01`) | `apps/api/routers/findings.py`, `packages/schemas/finding.py`, `database/models/finding.py` | `P7-TC-LIFE-01` |

---

## 2. The 15 Mandatory Phase 7 Finding Fields (`benchmark/score.py`)

Verified directly against `benchmark/score.py::PHASE_7_REQUIRED_FIELDS` (lines 26–42) and `evaluate_evidence_completeness()` (lines 122–180):

1. `id` — Unique finding identifier (UUID).
2. `target` — Affected target host/origin (`target`, `target_url`, or `host`).
3. `endpoint` — Affected endpoint path (`endpoint`, `url_path`, or `path`) — **known gap `P1-FIND-02`**.
4. `method` — HTTP method (`method` or `http_method`) — **known gap `P1-FIND-02`**.
5. `parameter` — Affected parameter (`parameter`, `affected_parameters`, or `param`; note `FindingResponse` exposes `affected_parameter` singular — tracked under `P1-FIND-02`).
6. `wstg_id` — OWASP WSTG v4.2 test identifier (`wstg_id` or `wstg_code`).
7. `cwe_id` — CWE identifier (`cwe_id` or `cwe`).
8. `detection_source` — Detection tool or agent identifier (`detection_source`, `source_tool`, or `discovered_by`).
9. `reproduction_procedure` — Reproducible procedure or `curl` command (`reproduction_procedure`, `reproduction_curl`, or `curl_command`, checked at root and nested `evidence[].reproduction_curl`).
10. `actual_evidence` — Captured raw HTTP request/response or evidence digest (`actual_evidence`, `raw_request`, `raw_response`, `evidence_hash`, checked at root and nested `evidence[]`).
11. `severity_justification` — Severity rationale (`severity_justification`, `severity_rationale`, or `severity` + `description`/`cvss_vector`).
12. `confidence` — Confidence level (`Confirmed`, `High`, `Medium`, `Low`).
13. `false_positive_assessment` — Explicit false-positive analysis (`false_positive_assessment`, `fp_analysis`, `is_false_positive`, `fp_risk`).
14. `remediation` — Actionable remediation guidance (`remediation`, `recommendation`, or `remediation_guidance`).
15. `validation_status` — Lifecycle validation status (`validation_status` or `status`).

In `P7-TC-COMP-01`, completeness is computed under **two explicit views** from the API JSON payload only (zero DB queries):
- **Strict `score.py` Key View:** Exact output of `benchmark/score.py::evaluate_evidence_completeness(api_finding_dict)` directly on `GET /api/v1/projects/{id}/findings` (reflecting the exact contract experienced by external consumers and `score.py`).
- **Joined API View (`FindingResponse` + `/evidence` endpoint):** Merging `GET .../findings/{fid}` with `GET .../findings/{fid}/evidence` (mapping `remediation_guidance` -> `remediation`, `evidence[].reproduction_curl` -> `reproduction_procedure`, `evidence[].raw_request/raw_response` -> `actual_evidence`), while strictly flagging fields genuinely absent from the API (`target`, `endpoint`, `method`, `parameter` alias, `false_positive_assessment`).

---

## 3. Execution Environment & Safety Invariants

- **Target Stack:** `pentesa-prod` (`http://127.0.0.1:8000`, `docker-compose.yml` on `pentesa-internal`), post-hotfix `hotfix-api-02`.
- **Execution Order:**
  1. **Read-Only Existing Data Audit First:** All 39 production findings + Phase 3/4 evidence JSON (`P7-TC-COMP-01`, `P7-TC-INT-01`, `P7-TC-INT-02` on copy, `P7-TC-REDACT-01`, `P7-TC-ACC-01`).
  2. **Reproduction Replay (`P7-TC-REPRO-01`):** Temporarily attach `pentesa-bench-net` ONLY for replaying confirmed reproduction curls against freshly reset bench targets (3 replays each), immediately detach and prove detachment via `docker inspect` + 0 canary hits.
  3. **Write Tests on Throwaway `p7test-` Users & Projects (Rules A–H):** `P7-TC-REDACT-02`, `P7-TC-DEDUP-01`, `P7-TC-REP-01`, `P7-TC-REP-02`, `P7-TC-REP-03` (live Azure GPT-5.6 gateway with health gate `max_completion_tokens>=50`, budget cap \$2.00 / 60k tokens, logged in `docs/audit/evidence/phase7/cost-log.md`), `P7-TC-LIFE-01`.
  4. **Mandatory Cleanup & Restore Proof:** Restore `pentesa-prod` cleanly to the exact `demo-known-good` baseline snapshot (`users=2, projects=28, findings=39, finding_evidence=39, reports=1, audit_logs=1258`, head `97e166a6108be5ef0e5983ad45e9d7fd2f3c6f7efeafd702939327a08208ade4`), verifying counts, unbroken audit chain, real admin login 200, `admin@example.com` 401, `benchmark-admin` inactive, and zero bench/canary network attachments.
