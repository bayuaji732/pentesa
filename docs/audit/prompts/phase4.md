PHASE 4: Advanced Pentest Validation (evaluation only. No platform changes, no scorer changes, no building missing features. Work this phase only, then STOP.)

STEP 0 — Close Phase 3 cleanly (15 min)
a) git status must be clean; commit the closeout and tag `phase3-complete`. State whether the repo has any git remote and whether it was ever pushed (relevant to the secrets still in history).
b) For every TP in the score_per_target outputs (pentesa-bench 1, juiceshop 1), list: case id, finding id, matched fields, evidence file. Confirm that --adapt-schema only renames fields (affected_parameter -> parameter) and does not loosen the matching rule (endpoint + method + parameter + CWE/WSTG). If the rule was loosened, say so and recompute strictly.
c) Gateway health gate (1-token call). If it fails, retry 3x with backoff, then STOP.

STEP 1 — Capability inventory BEFORE any scan (code + API evidence, no LLM spend)
For each Phase 4 area, determine by reading code and running ONE minimal non-LLM probe where possible: Implemented / Partial / Not Implemented, with file:line references.
Areas: context-aware testing; parameter relationship analysis; authentication-context comparison (admin vs member vs unauthenticated); cross-user authorization testing; API object-level authorization (BOLA); business-logic anomaly detection; workflow state inconsistency; multi-step validation; chained findings with independent justification; expected vs actual behavior comparison.
Specifically check: can AGT-07 (Authorization Testing Agent) consume AuthProfile entries from the credential vault and send the same request under two identities? Can the platform hold two identities in one workflow? Does anything flag business-logic cases "for human review" as ground truth demands? Write docs/audit/evidence/phase4/4A-capability-inventory.md. Areas that are Not Implemented get NO scan and NO budget; they are recorded as Not Implemented with the code evidence.

STEP 2 — Ground truth for Phase 4 (commit and tag BEFORE any scan)
benchmark/ground_truth_p4.yaml (do not modify the frozen ground_truth.yaml). One entry per testable area/case with the 8 items from the master Phase 3 list plus: identities involved, expected outcome class (CONFIRMED_VULN / SECURE_NO_FINDING / FLAGGED_FOR_HUMAN_REVIEW), and what a deterministic tool would achieve. Use existing targets only: crAPI (vehicle/location and orders BOLA, two registered users), Juice Shop (basket IDOR, two registered users), pentesa-bench (checkout client_price, coupon race, workflow-state flow, vulnerable + secure variants). Include secure controls for every vulnerable case. Two-user setup is done by a seeding script outside the platform; credentials come from untracked env files, never committed or printed. Record the ground_truth_p4.yaml sha256 in every run header. If bench lacks a needed fixture, add it to the bench app only (test fixture), keep reset deterministic, document in b0-compose-changelog.md, and commit before scanning.

STEP 3 — Oracle baseline (deterministic, no LLM)
benchmark/oracle_p4.py, labelled ORACLE/REFERENCE: replays user-A-token against user-B-object and the other P4 cases with plain HTTP, to prove each vulnerable case is really exploitable and each secure case really is not. Machine-captured with header via tee. This is the yardstick for "expected vs actual", not a platform result.

STEP 4 — Platform runs (only for areas marked Implemented/Partial in 4A)
3 runs per configuration, DEEP profile, a named profile in every header, gateway health gate before each run, abort the whole batch on gateway failure and classify as INFRA_FAILURE (never as 0 findings). Cap for this phase: $5 / 150k tokens, tally in evidence/phase4/cost-log.md, stop at 80%. Any request to the canary or an unlisted host = P0, stop immediately. Non-destructive only; race tests on bench only with bounded concurrency; business-logic cases must end as FLAGGED_FOR_HUMAN_REVIEW, not auto-exploited. No chained exploitation: evaluate only whether findings state their dependency and justification.

STEP 5 — Scoring
Write benchmark/score_p4.py (declared before the runs, sha256 in headers) that scores confirmed findings AND candidate findings separately against ground_truth_p4.yaml: TP/FP/FN, precision, recall, FP rate on secure controls, expected-outcome-class match, evidence completeness (Phase 7 field list, including endpoint and method), reproduction success. Numbers only from script output via tee. Never type or edit results. Failed runs are reported, not hidden.

STEP 6 — Report
docs/audit/05b-advanced-pentest-validation.md: per-area table with status from the Phase 10 vocabulary only (Verified / Partially Verified / Failed / Not Implemented / Not Tested); a "deterministic tools sufficient" vs "agent needed" vs "human review required" matrix per area, backed by the oracle and platform results; expected-vs-actual differences; root cause and P0-P3 priority for each gap (new items appended to 03-defect-register.md and 10-improvement-roadmap.md, not implemented). Update 02-requirement-traceability.md and the STATUS block in 00-master-prompt.md (Phase 4 complete, resume at Phase 5). Update MANIFEST.sha256 and prove it with sha256sum -c.

STOP with: capability table, metrics table (platform vs oracle), top gaps with priority, cost spent, readiness verdict for Phase 5, and wait for my approval.