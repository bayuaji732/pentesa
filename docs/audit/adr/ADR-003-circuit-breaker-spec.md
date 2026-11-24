# ADR-003: Circuit-Breaker Error Rate Specification Standard

> **Document Identifier:** `ADR-003-CIRCUIT-BREAKER-SPEC`  
> **Status:** ACCEPTED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** Principal Security Architect & QA Team  
> **Reference Baseline:** `docs/audit/evidence/phase8/p8_test_results.json` (`P8-TC-SAFE-01`)

---

## 1. Context & Problem Statement

Phase 8 testing (`P8-TC-SAFE-01` / `NFR-SAFE-01`) revealed that zero circuit-breaker or 5xx error backoff logic currently exists in the platform (`DEFECT-SAFE-01`).
Furthermore, a direct contradiction exists between core documentation artifacts:
- **`docs/01-prd.md:115`:** Specifies that scanning must throttle/pause when target error rate exceeds **15% over a 30-second sliding window**.
- **`docs/03-system-architecture.md:400`:** Specifies that scanning must throttle/pause when target error rate exceeds **20% over a 60-second sliding window**.

A single authoritative standard must be chosen and reconciled across all platform documentation before implementation in Wave 2.

---

## 2. Decision

We adopt the **PRD specification: 15% 5xx error rate over a 30-second sliding window** as the authoritative platform standard.

---

## 3. Rationale & Security Justification

1. **Target Safety & Availability Invariant:** Penetration testing tools (especially fuzzers and vulnerability scanners) can generate 20–50 requests per second. Under a 60-second sliding window, a target experiencing cascading database failure could absorb 1,200 to 3,000 hostile requests before the breaker trips. A 30-second window cuts reaction time in half.
2. **Defensive Sensitivity:** A 15% error threshold detects unstable backends earlier than 20%, preventing denial-of-service (DoS) conditions against sensitive microservices.
3. **Sliding Window Implementation:** Redis sorted sets (`ZSET`) keyed by `pentesa:circuit:{project_id}` allow $O(\log N)$ sliding window counts of 5xx timestamps without memory growth.

---

## 4. Documentation Synchronization Actions

1. Update `docs/03-system-architecture.md` §6 to cite `15% over 30s`.
2. Update `docs/02-srs.md` and `docs/07-wstg-test-catalog.md` to reference the 15%/30s standard.
3. Implement `CircuitBreakerService` in `services/execution_engine/circuit_breaker.py` during Wave 2.
