Resume the master audit at PHASE 3 only. Do not start Phase 4. Read phase2-summary.md, 03-defect-register.md and 02-requirement-traceability.md first.

STEP 0: GATE (keep it short; fix the record before benchmarking)
G1 Correct phase2-summary.md:
- Phase 3 is the isolated Pentest Effectiveness Benchmark, NOT "live target penetration testing and exploitation validation". Remove "certified ready".
- Replace the stale pytest figure (208) with the real `pytest --collect-only -q` count (the F-round reported 221). Fix the token total (listed items sum to 15,675, not 15,664). Remove "Swedish" from the gateway description. State the network truthfully (the diagram says internal:false while the text claims zero outbound internet).
- Make MANIFEST.sha256 and the README rule exist and prove `sha256sum -c` passes.
- Add an "Open issues" section listing the carry-over items from STATUS, plus: UI workflow evidence incomplete (screenshots 03 and 09 missing), cancellation during crawl/validation untested, API contract diff lists missing (totals only), DNS rebinding untested for tool subprocesses (Phase 6).
- Restate the traceability totals honestly. NI-05 and NI-09 requirements are Not Implemented, and FR-DS-06 and FR-ST-05 are Partially Verified. "0 Not Implemented / 0 Not Tested" is not credible.
G2 Verify r3_wstg_plan_counts.txt. Its numbers (44 planned, 60 N/A, 2 failed, 58.5%, 4.3% = 2/46) are identical to the values the audit already admitted were artificial (efbcd1b). Show the raw /wstg/coverage JSON and timestamp from that file, and explain how 2 tests "failed" when none were executed. If the raw output differs, log EVID-02 (P1) and regenerate from a fresh stack. Reconcile the wordlist hash: F4 gave upstream SHA-256 47fb86ca..., the summary says 6e8286a...; show `sha256sum` of /opt/wordlists/common.txt in the image and of the raw file at commit 0c618cf.
G3 Restart behaviour (NI-06): start a workflow, restart the API container mid-run, record exactly what happens. Minimal fix required before long benchmark runs: on startup mark workflows left RUNNING (and their agent_executions) as FAILED with reason "interrupted by restart". Add a regression test.
If G2 reveals fabrication, STOP and report before continuing.

BENCHMARK ENVIRONMENT
- Separate benchmark/docker-compose.bench.yml. Targets sit on a network with internal: true. State plainly in the docs that the API/worker also have an internet route (LLM gateway), so the lab-only guard is the only barrier for tool subprocesses (NI-03). Only targets defined in this compose file are ever scanned.
- Targets (pinned image tags or digests): Juice Shop, DVWA, WebGoat, crAPI, plus "pentesa-bench", a small purpose-built app with paired vulnerable and secure endpoints, seeded data and deterministic reset, covering what the others do not cover cleanly: SSTI, XXE, command injection, file upload, path traversal, SSRF to an internal canary, JWT weaknesses, a race condition and a business-logic flow. Secure cases: DVWA at "impossible" and the bench app's patched endpoints.
- Non-destructive only: no DoS, no data-destroying payloads, bounded concurrency (race tests on bench endpoints only), reset state between runs.

GROUND TRUTH (write and commit BEFORE any scan)
benchmark/ground_truth.yaml, one entry per case: id, app, endpoint, method, parameter, category, WSTG id, CWE, vulnerable or secure, and the eight items from the master Phase 3 list (vulnerability condition, expected secure behavior, expected discovery, expected agent behavior, expected reproduction evidence, expected severity, expected false-positive behavior, pass/fail criteria). Cover every category in the master list with vulnerable AND secure cases. For business-logic cases the correct outcome is "flagged for human review", not an automatic exploit. Record the sha256 of the file in every run header.

SCORING
benchmark/score.py: a deterministic scorer that matches findings to ground truth by (endpoint, method, parameter, CWE/WSTG category) and outputs JSON: TP, FP, FN, precision, recall, F1, false-positive rate on secure cases, reproduction success rate, evidence completeness (fields from the master Phase 7 list), WSTG coverage (executed / applicable) and execution reliability (completed runs, timeouts, crashes). Numbers come ONLY from score.py output captured with tee. Never type or edit results.

RUNS
- Use the most thorough non-destructive scan profile (not QUICK) and name it. 3 runs per target; report mean and variance.
- Also run a deterministic baseline (nuclei + ffuf only, same templates and wordlist) to show what the agents add.
- New LLM cap: $10 / 300k tokens (adjust if you want), tallied in cost-log.md; stop at 80%.
- Any request reaching the canary or an unlisted host is a P0: stop immediately.

OUTPUT
benchmark/ (compose, ground truth, bench app, scorer); docs/audit/05-pentest-benchmark-results.md (matrix per case, metrics per target and overall, root-cause analysis of every FN and FP with priority P0-P3); evidence/phase3/ (machine-captured, headers, MANIFEST.sha256); updated 02-requirement-traceability.md. Only P0 safety fixes are allowed in this phase. Detection improvements become P2 items for Phase 9.

STOP at the end with: the metrics table, the top FN/FP causes, cost spent, the new P0-P3 list and the readiness verdict for Phase 4. Wait for my approval.