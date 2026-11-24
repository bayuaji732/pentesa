# Master Benchmark LLM Token & Cost Telemetry Ledger

> **Scope:** Comprehensive audit accounting across all benchmark phases (Phase 2, Phase 3, Phase 3B, Phase 4, Phase 4 Rerun, Phase 5, Phase 6, Phase 6B, Phase 7, and Phase 8).  
> **LLM Gateway Provider:** LiteLLM Enterprise Gateway (`https://uat-ai-gateway.siloamhospitals.com/v1/`)  
> **Production Model:** `azure/gpt-5.6-terra-dev-gtw` (Mock mode used during Phase 8 plumbing/concurrency).  
> **Pricing Formula:** $2.50 / 1M prompt tokens, $10.00 / 1M completion tokens (effective average ~$6.00-$8.00 / 1M tokens depending on completion ratio).

---

## 1. Consolidated Ledger by Phase

| Phase | Evaluation Scope | Primary LLM Mode | Authorized Budget Cap | Tokens Consumed | Incurred Cost (USD) | Budget Share Used | Status |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Phase 2** | Architecture & Agent Handoffs | Live Gateway | $5.00 / 100,000 | 15,664 | $0.1221 | 2.44% | COMPLETED |
| **Phase 3 & 3B** | Efficacy Baseline & Ground Truth | Live Gateway | $10.00 / 300,000 | 160,842 | $1.2741 | 12.74% | COMPLETED |
| **Phase 4 & Rerun** | Security Target Scans & Reruns | Live Gateway | $5.00 / 150,000 | 71,081 | $0.5459 | 10.92% | COMPLETED |
| **Phase 5** | Vulnerability Ingestion & Pipeline | Live Gateway | $4.00 / 120,000 | 4,836 | $0.0459 | 1.15% | COMPLETED |
| **Phase 6 & 6B** | Adversarial & Defense In-Depth | Live Gateway | $2.00 / 60,000 | 10,754 | $0.0658 | 3.29% | COMPLETED |
| **Phase 7** | Quality, False Positives & PDF | Live Gateway | $2.00 / 60,000 | 4,816 | $0.0283 | 1.41% | COMPLETED |
| **Phase 8** | Concurrency, Limits & Reliability | Mock LLM | $1.00 / 30,000 | 0 | $0.0000 | 0.00% | COMPLETED |
| **TOTAL** | **Entire Benchmark Campaign** | **Mixed** | **$29.00 / 820,000** | **267,993** | **$2.0821** | **7.18%** | **WITHIN CAP** |

---

## 2. Granular Phase Details & Raw Log Traceability

### Phase 2: Multi-Agent Handoffs (`docs/audit/evidence/phase2/cost-log.md`)
- **Gateway Health Probe:** 12 tokens ($0.0001 USD)
- **Multi-Agent Workflow Runs (Runs 1–3):**
  - Run 1: 5,296 tokens ($0.0414)
  - Run 2: 4,907 tokens ($0.0376)
  - Run 3: 5,460 tokens ($0.0430)
- **Phase 2 Subtotal:** **15,664 tokens / $0.1221 USD** (Remaining: $4.8779)

### Phase 3 & 3B: Efficacy Baseline (`docs/audit/evidence/phase3/cost-log.md`)
- **Initial Dry-Runs & Fails:** 18,766 tokens ($0.1649 USD)
- **Bench Runs (JuiceShop, DVWA, cRAPI, WebGoat):** Completed 3 passes each.
- **Final Row Accumulation:** `RUN-WEBGOAT-DEEP-03`
- **Phase 3 Subtotal:** **160,842 tokens / $1.2741 USD** (Remaining: $8.7259)

### Phase 4 & 4 Rerun: Target Scans (`docs/audit/evidence/phase4/cost-log.md`)
- **Initial P4 Runs:** 27,249 tokens ($0.2118 USD)
- **Rerun Series (JuiceShop Reruns 1–3, cRAPI Reruns 1–3):** 43,832 tokens ($0.3341 USD)
- **Final Row Accumulation:** `P4-CRAPI-RERUN3`
- **Phase 4 Subtotal:** **71,081 tokens / $0.5459 USD** (Remaining: $4.4541)

### Phase 5: Pipeline & Ingestion (`docs/audit/evidence/phase5/cost-log.md`)
- **Live Pipeline Generation:** `P5-LIVE-RUNS` consumed 330 prompt tokens, 4,506 completion tokens.
- **Phase 5 Subtotal:** **4,836 tokens / $0.0459 USD** (Remaining: $3.9541)

### Phase 6 & 6B: Adversarial In-Depth (`docs/audit/evidence/phase6/cost-log.md`)
- **P6-TC-INJECT-01 Baseline:** 168 tokens ($0.0011 USD)
- **P6B-TC-INJECT-01 Iterations (7 passes x 10 vectors):**
  - Pass 1: 1,519 tokens ($0.0093)
  - Pass 2: 1,528 tokens ($0.0094)
  - Pass 3: 1,535 tokens ($0.0095)
  - Pass 4: 1,519 tokens ($0.0093)
  - Pass 5: 1,488 tokens ($0.0090)
  - Pass 6: 1,526 tokens ($0.0094)
  - Pass 7: 1,471 tokens ($0.0088)
- **Phase 6 & 6B Subtotal:** **10,754 tokens / $0.0658 USD** (Remaining: $1.9342)

### Phase 7: Quality & Report Generation (`docs/audit/evidence/phase7/cost-log.md`)
- **Run 1 (Superseded):** 2,382 tokens ($0.0139 USD)
- **Run 2 (Final Gate Verification):** 2,434 tokens ($0.0144 USD)
- **Phase 7 Cumulative (All Runs):** **4,816 tokens / $0.0283 USD** (Remaining: $1.9717)

### Phase 8: Concurrency & Reliability (`docs/audit/evidence/phase8/cost-log.md`)
- **Plumbing & Stress Benchmark:** Conducted entirely under Mock LLM provider (`PENTESA_LLM_PROVIDER=mock`) to stress async queues and process tables without external API egress.
- **Phase 8 Subtotal:** **0 tokens / $0.0000 USD** (Remaining: $1.0000)

---

## 3. Discrepancy Reconciliation

> [!IMPORTANT]
> The initial Phase 8 report (`docs/audit/08b-reliability-performance.md` Section 6) erroneously cited cumulative project spend as `$0.0283 / 4,816 tokens`.
> That figure represented exclusively the **Phase 7 standalone expenditure**.
> The true cumulative expenditure across all phases (Phase 2 through Phase 8) is **267,993 tokens / $2.0821 USD**, representing **7.18%** of the cumulative authorized cap of **$29.00 USD / 820,000 tokens**.
