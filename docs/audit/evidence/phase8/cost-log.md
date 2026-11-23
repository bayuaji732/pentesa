# Phase 8 Cost and LLM Token Usage Log

**Audit Phase:** Phase 8 Reliability, Performance, Concurrency, and Resource Limits  
**Date:** 2026-11-23  
**Budget Cap:** $1.00 USD / 30,000 tokens  
**LLM Mode:** Mock LLM (`PENTESA_LLM_PROVIDER=mock`) for plumbing, concurrency, and resilience benchmarking.

---

## 1. Gateway Health Gate Pre-Check
- **Model:** Mock Provider (`mock`)
- **Status:** PASS (Local deterministic response generation, 0 external egress)

---

## 2. Token and Cost Accounting Table

| Test Sub-Area | Test ID | Description | LLM Provider | Prompt Tokens | Completion Tokens | Total Tokens | Estimated Cost (USD) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **a_startup** | `P8-TC-DEP-01` | Compose startup timing | None (Infra) | 0 | 0 | 0 | $0.0000 |
| **b_api_performance** | `P8-TC-PERF-01` | API latency under 5k scale | None (API) | 0 | 0 | 0 | $0.0000 |
| **b_api_performance** | `P8-TC-PERF-02` | API latency under 10k scale | None (API) | 0 | 0 | 0 | $0.0000 |
| **b_api_performance** | `P8-TC-SCAL-01` | Cursor pagination inspection | None (API) | 0 | 0 | 0 | $0.0000 |
| **c_rate_control** | `P8-TC-RATE-01` | Outbound scan rate control (5 & 20 RPS) | None (Network) | 0 | 0 | 0 | $0.0000 |
| **d_circuit_breaker** | `P8-TC-SAFE-01` | 5xx error backoff circuit breaker | None (Network) | 0 | 0 | 0 | $0.0000 |
| **e_resilience** | `P8-TC-REL-01` | Worker kill mid-workflow | Mock LLM | 0 | 0 | 0 | $0.0000 |
| **e_resilience** | `P8-TC-REL-02` | Tool failure fault isolation | Mock LLM | 0 | 0 | 0 | $0.0000 |
| **e_resilience** | `P8-TC-REL-03` | Infrastructure restart recovery | None (Infra) | 0 | 0 | 0 | $0.0000 |
| **f_concurrency** | `P8-TC-CONC-01` | 1, 3, 5 parallel workflows | Mock LLM | 0 | 0 | 0 | $0.0000 |
| **g_integrity** | `P8-TC-AUD-01` | Concurrent audit calls & hash chain | None (API) | 0 | 0 | 0 | $0.0000 |
| **g_integrity** | `P8-TC-AUD-02` | Concurrent finding ingestion race | None (API) | 0 | 0 | 0 | $0.0000 |
| **h_cancellation** | `P8-TC-RES-01` | Subprocess cancellation & cleanup | None (Process) | 0 | 0 | 0 | $0.0000 |
| **i_hostile_responses**| `P8-TC-HOST-01` | Pathological HTTP response resilience | None (HTTP) | 0 | 0 | 0 | $0.0000 |
| **j_resource_limits** | `P8-TC-LIM-01` | Container limits & log rotation review | None (Docker) | 0 | 0 | 0 | $0.0000 |

---

## 3. Cumulative Tally
- **Total Prompt Tokens:** 0
- **Total Completion Tokens:** 0
- **Total Tokens Consumed:** 0
- **Total Incurred Cost:** **$0.0000 USD** (Budget remaining: $1.00 USD / 100%)
