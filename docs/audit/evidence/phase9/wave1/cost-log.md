# Phase 9 Wave 1a — Cost & Token Accumulation Log

- **Authorized Phase Budget Cap:** $1.00 USD / 30,000 tokens
- **Pricing Formula:** $2.50 / 1M prompt tokens, $10.00 / 1M completion tokens
- **Target Gateway:** `https://uat-ai-gateway.siloamhospitals.com/v1/` (`azure/gpt-5.6-terra-dev-gtw`)

| Run ID | Operation | Prompt Tokens | Completion Tokens | Total Tokens | Cost (USD) | Cumulative Tokens | Cumulative Cost | Budget % | Status |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `P9-GATEWAY-HEALTH-01` | Pre-flight Gateway Health Gate | 8 | 4 | 12 | $0.0001 | 12 | $0.0001 | 0.01% | PASS |
| `P9-WAVE1A-HEALTH-02` | Live Acceptance Health Gate | 43 | 15 | 58 | $0.0003 | 70 | $0.0004 | 0.04% | PASS |
| `P9-WAVE1A-SEEDED-01` | Seeded Acceptance Run (Preliminary) | 0 | 0 | 0 | $0.0000 | 70 | $0.0004 | 0.04% | SUPERSEDED |
| `P9-WAVE1A-SEEDED-02` | Live Seeded Acceptance Run (Real Gateway) | 4,777 | 409 | 5,186 | $0.0160 | 5,256 | $0.0164 | 1.64% | PASS |

**Total Live Tokens Consumed:** 5,256 tokens  
**Total Cumulative Cost:** $0.0164 USD (1.64% of authorized $1.00 cap)
