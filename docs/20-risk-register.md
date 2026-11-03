# Pentesa — Platform Risk Register & Mitigation Strategy

> **Document Identifier:** PENTESA-RISK-REG-V1.0  
> **Status:** Approved for Implementation  
> **Risk Framework:** ISO 31000 / NIST SP 800-30  
> **Review Cadence:** Bi-weekly during development, Monthly post-GA  
> **Target Release:** v1.0  

---

## Table of Contents

1. [Risk Management Framework & Scoring Methodology](#1-risk-management-framework--scoring-methodology)
2. [5x5 Risk Matrix & Heatmap](#2-5x5-risk-matrix--heatmap)
3. [Exhaustive Risk Register (15 Critical Risks)](#3-exhaustive-risk-register-15-critical-risks)
4. [Deep-Dive Mitigation Specifications](#4-deep-dive-mitigation-specifications)
   - [4.1 Mitigation for RSK-01: Scope Breach / Out-of-Scope Probing](#41-mitigation-for-rsk-01-scope-breach--out-of-scope-probing)
   - [4.2 Mitigation for RSK-02: Target Application Denial of Service (DoS)](#42-mitigation-for-rsk-02-target-application-denial-of-service-dos)
   - [4.3 Mitigation for RSK-03: AI Hallucination of Security Flaws](#43-mitigation-for-rsk-03-ai-hallucination-of-security-flaws)
   - [4.4 Mitigation for RSK-04: Destructive State Modification in Business Logic](#44-mitigation-for-rsk-04-destructive-state-modification-in-business-logic)
   - [4.5 Mitigation for RSK-05: Local LLM VRAM / System Memory Exhaustion](#45-mitigation-for-rsk-05-local-llm-vram--system-memory-exhaustion)
5. [Risk Governance & Continuous Monitoring Cadence](#5-risk-governance--continuous-monitoring-cadence)

---

## 1. Risk Management Framework & Scoring Methodology

Operating an autonomous security testing system introduces legal, operational, and technical risks. The Pentesa Risk Register evaluates each threat scenario using standard NIST qualitative scoring:

$$\text{Risk Score} = \text{Likelihood (1--5)} \times \text{Impact (1--5)}$$

- **Likelihood Scale:** 1 (Rare), 2 (Unlikely), 3 (Possible), 4 (Likely), 5 (Almost Certain).
- **Impact Scale:** 1 (Negligible), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Catastrophic).
- **Severity Bands:**
  - **Critical (Score 20–25):** Red. Immediate executive escalation; blocks release.
  - **High (Score 12–19):** Orange. Must have automated architectural mitigations.
  - **Medium (Score 6–11):** Yellow. Managed via standard operational procedures.
  - **Low (Score 1–5):** Green. Acceptable operational risk.

---

## 2. 5x5 Risk Matrix & Heatmap

```
IMPACT --->
L  5 | [RSK-08]     [RSK-07]     [RSK-06]     [RSK-02]     [RSK-01]
I  4 |              [RSK-09]     [RSK-04]     [RSK-03]     
K  3 |                           [RSK-10]     [RSK-05]     
E  2 |                                        [RSK-12]     [RSK-11]
L  1 |                                        [RSK-14]     [RSK-13]
   +-------------------------------------------------------------
       1 (Negl)     2 (Minor)    3 (Mod)      4 (Major)    5 (Catastrophic)
```

---

## 3. Exhaustive Risk Register (15 Critical Risks)

| Risk ID | Category | Risk Description | Pre L | Pre I | Pre Score | Post L | Post I | Post Score | Owner |
|---|---|---|---|---|---|---|---|---|---|
| **RSK-01** | Legal / Ops | **Scope Breach:** Automated tool probes unauthorized third-party infrastructure. | 3 | 5 | **15 (High)** | 1 | 5 | **5 (Low)** | AppSec Lead |
| **RSK-02** | Operational| **Target DoS:** Aggressive fuzzing or crawling crashes client production/staging app. | 4 | 4 | **16 (High)** | 2 | 3 | **6 (Med)** | DevSecOps |
| **RSK-03** | AI / Quality| **AI Hallucination:** Agent fabricates non-existent vulnerability in report. | 4 | 4 | **16 (High)** | 1 | 3 | **3 (Low)** | AI Lead |
| **RSK-04** | Operational| **Destructive Mutation:** Business logic agent triggers real financial charges or drops data. | 3 | 4 | **12 (High)** | 1 | 4 | **4 (Low)** | QA Lead |
| **RSK-05** | Technical  | **Hardware OOM:** Local Ollama model exhausts workstation RAM/VRAM during scan. | 4 | 3 | **12 (High)** | 2 | 2 | **4 (Low)** | DevOps |
| **RSK-06** | Security   | **Target Counter-Exploit:** Malicious web app exploits scanner worker via response payload. | 2 | 5 | **10 (Med)** | 1 | 4 | **4 (Low)** | Sec Arch |
| **RSK-07** | Security   | **Client Data Breach:** Compromise of Pentesa database leaks client zero-days. | 2 | 5 | **10 (Med)** | 1 | 4 | **4 (Low)** | Sec Arch |
| **RSK-08** | Operational| **Human Approval Fatigue:** Operator blindly clicks "Approve" on dangerous actions. | 4 | 3 | **12 (High)** | 2 | 3 | **6 (Med)** | Product Mgr |
| **RSK-09** | Quality    | **High False Negatives:** Platform misses critical business logic flaws. | 3 | 4 | **12 (High)** | 2 | 3 | **6 (Med)** | Pentest Lead|
| **RSK-10** | Performance| **Egress Proxy Bottleneck:** Dual-layer proxy creates latency in high-speed scans. | 3 | 3 | **9 (Med)** | 1 | 2 | **2 (Low)** | Backend Lead|
| **RSK-11** | Compliance | **RoE Expiration Bypass:** Scan continues after authorization window closes. | 2 | 5 | **10 (Med)** | 1 | 5 | **5 (Low)** | Backend Lead|
| **RSK-12** | AI / Security| **Indirect Prompt Injection:** Target website overrides agent instructions via HTML comments. | 3 | 4 | **12 (High)** | 1 | 3 | **3 (Low)** | AI Lead |
| **RSK-13** | Legal      | **Cloud Provider ToS Breach:** Scanning AWS/GCP targets without proper authorization flags. | 2 | 5 | **10 (Med)** | 1 | 4 | **4 (Low)** | Compliance |
| **RSK-14** | Technical  | **Tool Binary Drift:** Upstream Nuclei/Katana update breaks CLI argument syntax. | 3 | 3 | **9 (Med)** | 1 | 2 | **2 (Low)** | DevSecOps |
| **RSK-15** | Usability  | **Report Rejection:** Client engineering rejects findings due to unclear reproduction steps. | 3 | 4 | **12 (High)** | 1 | 2 | **2 (Low)** | Product Mgr |

---

## 4. Deep-Dive Mitigation Specifications

---

### 4.1 Mitigation for RSK-01: Scope Breach / Out-of-Scope Probing
- **Mitigation Strategy (Dual-Layer Hardening):**
  1. *Layer 1:* Application-level pre-routing assertion on all URLs prior to queuing.
  2. *Layer 2:* Forward egress proxy enforces DNS pinning; resolves domain and asserts destination IP against authorized CIDRs before TCP socket establishment.
  3. Automatic redirect following is disabled by default across all tools; redirects to external domains are terminated.
- **Contingency Plan:** Instant emergency kill switch (`SIGKILL` to all tool workers) triggered automatically upon any egress proxy denial alert.

---

### 4.2 Mitigation for RSK-02: Target Application Denial of Service (DoS)
- **Mitigation Strategy:**
  1. Global Redis token-bucket rate limiter enforces maximum RPS per target hostname (default: 20 RPS).
  2. Circuit breaker monitoring: If target returns $\ge 15\%$ HTTP 500/502/503 errors over a 30-second window, scans pause automatically for 120 seconds.
  3. Heavy DoS templates are stripped from Nuclei test suites.
- **Contingency Plan:** Operator alerted immediately via WebSocket; option to resume with 50% reduced concurrency.

---

### 4.3 Mitigation for RSK-03: AI Hallucination of Security Flaws
- **Mitigation Strategy:**
  1. **Deterministic Burden of Proof:** An agent cannot declare a vulnerability confirmed based on reasoning alone.
  2. The Vulnerability Validation Agent (AGT-11) must execute a minimal reproduction probe and confirm the expected response signature.
  3. Confirmed findings require raw HTTP request/response evidence, a working `curl` command, and a SHA-256 cryptographic hash.
- **Contingency Plan:** Unverified anomalies are routed to `Needs Manual Review` or classified as False Positives.

---

### 4.4 Mitigation for RSK-04: Destructive State Modification in Business Logic
- **Mitigation Strategy:**
  1. Crawler skips forms with submit buttons containing keywords: `delete`, `purge`, `cancel`, `terminate`, `pay`, `charge`.
  2. State-modifying operations (POST/PUT/DELETE) on production profiles require explicit operator sign-off via Human-in-the-Loop approval dialog.
  3. Mandatory exclusion of payment and billing routes.
- **Contingency Plan:** Immediate audit logging of all requests sent during business logic testing for rapid rollback if needed.

---

### 4.5 Mitigation for RSK-05: Local LLM VRAM / System Memory Exhaustion
- **Mitigation Strategy:**
  1. Default to quantized models (Q8_0 or Q4_K_M) requiring $< 8\text{ GB}$ VRAM.
  2. Context window pruning: HTTP response bodies are truncated to 4KB before passing to LLM context.
  3. Fallback configuration allowing instant switch to external OpenAI-compatible API endpoint if local resources are saturated.
- **Contingency Plan:** Celery worker health check restarts Ollama container if memory exceeds 90% threshold.

---

## 5. Risk Governance & Continuous Monitoring Cadence

- **Bi-Weekly Risk Reviews:** Product Manager and AppSec Lead review the Risk Register during sprint retrospectives.
- **Pre-Engagement Checklist:** Prior to launching any scan, the system enforces a checklist: valid RoE dates verified, scope approved, emergency contact on file.
- **Post-Assessment Review:** Any false positive reported by a client is analyzed to update heuristic suppression rules.
