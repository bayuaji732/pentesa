# Mission: Independent Product Verification, Security Validation & Pentest Effectiveness Assessment

## STATUS (read first)
Phases 1, 2, 3, and 4 are complete: docs/audit/00-05b and docs/audit/evidence/phase2/, phase3/, phase4/. Open items to carry: P1-FIND-02 (finding response schema omits endpoint/method), P4-AUTH-01 (multi-identity & credential vault disconnection in AGT-07), P4-BUSL-01 (lack of automated business logic anomaly detection & review status), P4-CHAIN-01 (flat finding architecture without vulnerability chaining), P2-RECON-01 (blind crawl 404 dead-end / ffuf fallback), P2-AUTH-01 (session state management), P2-FIND-01 (passive header promotion), P2-COV-01 (specialized probers), P2-REL-01 (gateway resilience / circuit breaking), NI-03 (Layer-2 egress, P0-known), DISCO-SPA-01, no rate limit on /http-test, EVID-01 (earlier hand-edited evidence). Work ONE phase per session and stop for approval. Resume at PHASE 5.

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

Resume with Phase 4 (see STATUS).

Complete the assessment and present the findings before implementing major changes.