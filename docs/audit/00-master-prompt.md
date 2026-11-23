# Mission: Independent Product Verification, Security Validation & Pentest Effectiveness Assessment

## STATUS (read first)
Phases 1, 2, 3, 4, 5, 6, 7, and 8 are complete (Phase 8 reliability, performance, concurrency, and resource limits evaluated; 10 Verified, 1 Partially Verified, 2 Failed, 2 Not Implemented; tag `phase8-complete`; post-step cleanup verified healthy; 0 canary hits; repository hygiene maintained): `docs/audit/00-08b` and `docs/audit/evidence/phase2/` through `phase8/`. Open items to carry: `NI-03` (Layer-2 egress, P0-KNOWN), `DEFECT-REL-01` (P1, worker crash resumption Not Implemented), `P1-FIND-02` (`FindingResponse` omits `endpoint`/`method`/`target`/`parameter` — 46.7% strict / 60.0% joined API completeness), `DEFECT-FIND-03` (P1, `cvss_score`/`cvss_vector` NULL on 39/39 prod findings), `DEFECT-REP-01` (P1, zero-finding report asserts `"STRONG SECURITY POSTURE"` & candidate/confirmed mixed), `DEFECT-AGENT-01` (`P1-AGENT-01`, ValidationAgent blind LLM trust on 404), `DEFECT-AUTH-02` (`P4-AUTH-01`, multi-identity & credential vault disconnection in AGT-07), `SEC-LEAK-02` (P1 while reactivable, `benchmark-admin` credential in commit `55c0a09`, account currently deactivated), `DEFECT-DEP-01` (P1, reachable High/Critical advisories in `next@14.2.18`), `DEFECT-SAFE-01` (P2, circuit breaker Not Implemented & spec conflict 15%/30s vs 20%/60s), `DEFECT-SCAL-01` (P2, cursor pagination Not Implemented for 10k items & findings unpaginated), `DEFECT-RES-01` (P2, `asyncio.CancelledError` unhandled in `BaseToolWrapper` risking orphan subprocesses), `DEFECT-HOST-01` (P2, slow-drip cumulative stream timeout hang), `DEFECT-AUTH-03` (P2, login rate limiting gap), `DEFECT-REP-02` (P2, 4 ungrounded boilerplate claims in PTES HTML template), `DEFECT-REDACT-01` (P2, custom project secrets & finding text fields unscrubbed), `DEFECT-DEDUP-01` (P2, no ingestion dedup & null-endpoint `"global|ANY"` over-clustering), `DEFECT-BUSL-01` (`P4-BUSL-01`, business logic anomaly detection & `FLAGGED_FOR_HUMAN_REVIEW` Not Implemented), `DEFECT-CHAIN-01` (`P4-CHAIN-01`, flat finding architecture), `P2-RECON-01`, `P2-AUTH-01`, `P2-FIND-01`, `P2-REL-01`, `P2-TEST-01`, `DISCO-SPA-01`, `DEFECT-INFRA-01` (P3, unbounded container memory limits on 5 compose services), `DEFECT-DEP-02` (P3), `DEFECT-LIFE-01` (P3, finding assignment Not Implemented), `DEFECT-REPRO-01` (P3, redirect URL in cURL), `P3-TEST-01`, `P3-API-01`, `P3-INFRA-02`, `DEFECT-CFG-01` (P3, SQLite fallback). Work ONE phase per session and stop for approval. Resume at PHASE 9.

## Audit deviations
- **Approved Hotfix (`DEFECT-API-02`, tag `hotfix-api-02`, commit `a6e772b`, branch `hotfix/defect-api-02`):**
  - **What changed:** Applied `DEFECT-API-02` fix to `apps/api/dependencies.py` only (`+4/-1` lines), chaining `.selectinload(ProjectMember.user)` onto `selectinload(Project.members)` inside `verify_project_access()`. Regression test moved to `tests/unit/test_defect_api_02_regression.py`. No other production files were modified.
  - **Why:** Approved targeted deviation from the evaluation-only rule to unblock dashboard project-detail reads and web navigation where `GET /api/v1/projects/{project_id}` previously returned HTTP 500 (`ResponseValidationError: MissingGreenlet`).
  - **Evidence scope:** All Phase 6 and Phase 6b baseline evidence (`demo-smoke.txt`, `p6b_live_output.txt`, `score_p6b.txt`, `p6b_rbac_matrix.json`, `p6b_idor_matrix.json`) refers strictly to the **unpatched** codebase at tag `phase6-final`. Post-hotfix verification runs are stored separately as `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_*.txt/json`.

## Amendments to the Execution Rules (added during the audit)
- Evidence standard: every raw evidence file is machine-captured (script/tee), starts with a header (UTC time, git SHA + dirty flag, exact command, DB version, running stack vs in-process) and is NEVER hand-edited. Corrections go in addenda. Maintain MANIFEST.sha256.
- Lab only: nuclei and ffuf run only against targets defined in the benchmark compose file until a Layer-2 egress proxy exists (NI-03).
- Status words come only from the list in Phase 10. Do not write "certified", "production ready" or similar.
- Report failures and low results plainly. Do not tune the platform, ground truth or scorer to improve results during a measurement phase.

## Role

Act as an independent:
- Principal Software Architect
- Senior Application Security Engineer
- Senior Penetration Tester
- Security QA Engineer
- AI Agent Evaluation Engineer
- DevSecOps Security Engineer

You are auditing an already implemented AI-powered OWASP WSTG penetration testing platform.

The application, backend, frontend, agents, skills, integrations, and database have already been implemented.

Your job is NOT to rebuild the application.

Your job is to determine whether the existing implementation actually works, whether it performs effective penetration testing, and what needs to be improved.

## PHASE 1: Repository and Documentation Audit

Inspect the complete repository.

Review:
- Existing documentation.
- Architecture.
- PRD and SRS.
- Database schema.
- API contracts.
- Agent implementations.
- Skills.
- Tool integrations.
- Frontend.
- Backend.
- Configuration.
- Docker deployment.
- Tests.

Compare documentation against the actual implementation.

Identify:
- Missing functionality.
- Incomplete functionality.
- Dead code.
- Placeholder implementations.
- Mock data presented as real functionality.
- Inconsistent API contracts.
- Duplicate components.
- Missing error handling.
- Outdated documentation.
- Security architecture gaps.

Create a requirement-to-implementation traceability matrix.

Do not mark functionality as verified without execution evidence.

## PHASE 2: Functional and Integration Testing

Test every major module.

Verify:
- Project creation.
- Scope configuration.
- Scope enforcement.
- Authentication.
- Authorization.
- Attack surface discovery.
- Endpoint crawling.
- Parameter extraction.
- WSTG test planning.
- WSTG execution.
- Nuclei integration.
- Fuzzing.
- Vulnerability validation.
- False positive classification.
- Evidence collection.
- Findings management.
- PTES reporting.
- Agent orchestration.
- Skill execution.
- Scan cancellation.
- Error recovery.

Test actual workflows through the UI and backend.

Do not rely exclusively on unit tests.

## PHASE 3: Pentest Effectiveness Benchmark

Create an isolated, authorized vulnerability benchmark environment.

Use OWASP Juice Shop, crAPI, WebGoat, DVWA, and additional controlled test applications where appropriate.

Build a benchmark matrix covering:

- SQL Injection.
- XSS.
- SSRF.
- IDOR / BOLA.
- Broken Access Control.
- Authentication weaknesses.
- JWT weaknesses.
- File upload vulnerabilities.
- Path traversal.
- Command injection.
- SSTI.
- XXE.
- API security weaknesses.
- Race conditions.
- Business logic vulnerabilities.

For each test case define:

1. Known vulnerability condition.
2. Expected secure behavior.
3. Expected discovery result.
4. Expected agent behavior.
5. Expected reproduction evidence.
6. Expected severity.
7. Expected false positive behavior.
8. Pass/fail criteria.

Use non-destructive verification and seeded test data.

The benchmark must include vulnerable and secure cases.

Measure:
- True positive rate.
- False positive rate.
- False negative rate.
- Precision.
- Recall.
- Reproduction success rate.
- Evidence completeness.
- WSTG test coverage.
- Execution reliability.

Do not fabricate benchmark results.

## PHASE 4: Advanced Pentest Validation

Evaluate whether the platform can identify vulnerabilities beyond simple scanner signatures.

Assess:

- Context-aware testing.
- Parameter relationship analysis.
- Authentication-context comparison.
- Cross-user authorization testing.
- API object-level authorization.
- Business logic anomalies.
- Workflow state inconsistencies.
- Multi-step vulnerability validation.
- Chained findings where independently justified.
- Differences between expected and actual behavior.

Identify where deterministic tools are sufficient and where human review is required.

Do not automatically execute destructive exploit chains.

## PHASE 5: AI Agent Evaluation

Evaluate every agent independently.

Check:
- Correct responsibilities.
- Input/output schemas.
- Tool permissions.
- Agent handoffs.
- Context preservation.
- Retry behavior.
- Timeout handling.
- Hallucination resistance.
- Duplicate work prevention.
- Contradictory result handling.
- Prompt injection resistance.

Test adversarial inputs from untrusted target content.

Ensure that agents cannot override scope restrictions or execute arbitrary commands.

## PHASE 6: Security Audit of the Platform

Perform an application security assessment of the platform itself.

Prioritize:
- Scope bypass.
- SSRF.
- Arbitrary command execution.
- Container escape risks.
- Credential leakage.
- Authentication bypass.
- RBAC bypass.
- IDOR.
- Cross-project data access.
- Prompt injection.
- Unsafe tool execution.
- Evidence manipulation.
- Audit log tampering.
- Insecure file handling.
- Dependency vulnerabilities.
- Network egress restrictions.

Use an isolated test environment.

## PHASE 7: Findings and Evidence Quality

Verify that every finding includes:

- Unique finding ID.
- Affected target.
- Endpoint and method.
- Affected parameters.
- WSTG mapping.
- CWE mapping.
- Detection source.
- Reproduction procedure.
- Actual evidence.
- Severity justification.
- Confidence level.
- False positive assessment.
- Remediation.
- Validation status.

Verify evidence integrity and ensure sensitive information is appropriately redacted in exported reports.

## PHASE 8: Documentation Reconciliation

After the audit, update documentation to reflect actual system behavior.

Create:

docs/audit/
  01-repository-audit.md
  02-requirement-traceability.md
  03-functional-test-results.md
  04-integration-test-results.md
  05-pentest-benchmark-results.md
  06-agent-evaluation.md
  07-security-assessment.md
  08-findings-quality-assessment.md
  09-technical-debt.md
  10-improvement-roadmap.md

Update the original architecture, PRD, SRS, API, database, and skill documentation where necessary.

Preserve historical decisions and record architectural changes as ADRs.

## PHASE 9: Improvement Implementation

Do not immediately modify the entire codebase.

Classify discovered issues:

- P0: Critical security or scope enforcement issue.
- P1: Core functionality broken or major vulnerability.
- P2: Important detection or reliability improvement.
- P3: UX, performance, and maintainability improvement.

For each proposed improvement, provide:
- Problem.
- Root cause.
- Evidence.
- Recommended fix.
- Affected components.
- Regression tests.
- Acceptance criteria.

Fix P0 issues before any further active scanning.

Then implement approved improvements incrementally.

Do not rewrite working modules without evidence that a rewrite is necessary.

## PHASE 10: Final Assessment

Produce a final assessment containing:

1. Overall implementation maturity.
2. Functional completeness.
3. Security posture.
4. Pentest effectiveness.
5. Detection accuracy.
6. Reproduction reliability.
7. WSTG coverage.
8. Agent reliability.
9. Evidence quality.
10. Critical security gaps.
11. Technical debt.
12. Prioritized remediation roadmap.

Assign a status to each requirement:

- Verified.
- Partially Verified.
- Failed.
- Not Implemented.
- Not Tested.

Clearly distinguish test results from assumptions.

Do not claim production readiness without supporting evidence.

## Execution Rules

- Work with the existing repository.
- Preserve existing working functionality.
- Do not replace the frontend unnecessarily.
- Do not introduce unnecessary technologies.
- Do not fabricate test results.
- Do not bypass authorization or scope enforcement.
- Use isolated, explicitly authorized benchmark targets.
- Never execute uncontrolled destructive testing.
- Maintain audit logs.
- Keep documentation synchronized with implementation.

Resume per STATUS block above.

Complete the assessment and present the findings before implementing major changes.