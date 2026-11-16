# Phase 2 — Real LLM Token and Cost Telemetry Log

> **Phase 2 Hard Cost Cap:** $5.00 USD (or 100,000 total tokens)  
> **LLM Provider:** LiteLLM Enterprise Gateway (`https://uat-ai-gateway.siloamhospitals.com/v1/`)  
> **Configured Model:** `azure/gpt-5.6-terra-dev-gtw`  
> **Scope:** All Phase 2 Runs (Run 1 and Run 2)

---

## 1. Cost Summary

| Metric | Budget / Cap | Cumulative Used | Remaining |
|---|---|---|---|
| **Total Prompt Tokens** | - | 8 | - |
| **Total Completion Tokens** | - | 4 | - |
| **Total Tokens** | 100,000 | 12 | 99,988 |
| **Total Cost (USD)** | **$5.00** | **$0.0001** | **$4.9999** |

---

## 2. Invocation Log

| Timestamp (UTC) | Agent | Run # | Prompt Tokens | Completion Tokens | Total Tokens | Estimated Cost (USD) | Cumulative Cost | Gateway Status |
|---|---|---|---|---|---|---|---|---|
| *Baseline Initialized* | - | - | 0 | 0 | 0 | $0.0000 | $0.0000 | Initialized |
| 2026-11-13T22:48:47Z | AGT-01 (Planning) | Run 1 | 0 | 0 | 0 | $0.0000 | $0.0000 | Gateway Origin Unreachable (CloudFront 403) |
| 2026-11-13T22:48:48Z | AGT-01 (Planning) | Run 2 | 0 | 0 | 0 | $0.0000 | $0.0000 | Gateway Origin Unreachable (CloudFront 403) |
| 2026-11-13T22:48:49Z | AGT-01 (Planning) | Run 3 | 0 | 0 | 0 | $0.0000 | $0.0000 | Gateway Origin Unreachable (CloudFront 403) |
| 2026-11-16T03:34:34Z | S1 Gateway Check | Probe | 8 | 4 | 12 | $0.0001 | $0.0001 | Online (HTTP 200 OK) |

---

## 3. Telemetry Notes & Observations

1. **LiteLLM Gateway Status:**  
   During initial Part 2A verification, the gateway returned HTTP 403 via CloudFront. In Run 2 (Part 2B), probe at `2026-11-16T03:34:34Z` succeeded with HTTP 200 OK, returning model `azure/gpt-5.6-terra-dev-gtw` via `istio-envoy` upstream (`x-litellm-call-id: 87471726-e14e-49a5-991e-7cd8042925e9`). LLM-dependent tests (L1-L4) unblocked.
2. **Deterministic Agent Handoffs:**  
   The workflow supervisor handles live provider calls with token/latency instrumentation.
3. **Budget Status:**  
   12 total tokens consumed ($0.0001 USD); budget remains at $4.9999 / 99,988 tokens under the $5.00 hard cap.
