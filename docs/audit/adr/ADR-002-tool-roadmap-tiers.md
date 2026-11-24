# ADR-002: Offensive Security Tooling Phased Roadmap & Tiers

> **Document Identifier:** `ADR-002-TOOL-ROADMAP-TIERS`  
> **Status:** ACCEPTED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** Independent AppSec & Tool Integration Team  
> **Reference Baseline:** `docs/audit/evidence/phase9/9A-tool-inventory.md`

---

## 1. Context & Problem Statement

The platform documentation claims integration with 18+ offensive security tools (`docs/09-tool-integrations.md`).
The empirical tool audit in `9A-tool-inventory.md` revealed that only 5 tools are actually functional (`Nuclei`, `ffuf`, `Python Check Engine`, `SSL/TLS Analyzer`, `Header Analyzer`), while 12 are completely absent and `httpx` CLI is broken due to missing packaging.

Uncontrolled addition of external binaries without sandboxing creates severe risks:
- Out-of-scope network egress (`NI-03`)
- Unbounded memory/PID consumption (`DEFECT-INFRA-01`)
- Orphan process leakage on task cancellation (`DEFECT-RES-01`)

---

## 2. Decision: Phased Four-Tier Roadmap

We establish four strict evolutionary tiers for security tool integration:

### Tier 1: Immediate Hardening (Now / Waves 1–2)
- **Scope:** Harden the 5 currently functional tools and repair broken entrypoints.
- **Actions:**
  1. Fix `httpx` packaging by adding `httpx[cli]` to `requirements.txt` or Dockerfiles.
  2. Implement `except asyncio.CancelledError:` and `finally:` subprocess kill handlers in `BaseToolWrapper.execute()` (`DEFECT-RES-01`).
  3. Enforce cumulative `asyncio.timeout()` in `safe_request()` to prevent slow-drip hangs (`DEFECT-HOST-01`).
  4. Enforce strict `deploy.resources.limits` in `docker-compose.yml` (`DEFECT-INFRA-01`).

### Tier 2: Network-Active Tools (Gated on NI-03 Layer-2 Egress Proxy)
- **Scope:** Active reconnaissance and crawling tools emitting outbound network traffic.
- **Tools:** `Subfinder` (passive subdomain discovery), `Katana` (headless web spidering), and `Naabu` (port scanner).
- **Gate Invariant:** Strictly blocked from installation or execution until the dedicated Layer-2 egress proxy with iptables enforcement (`NI-03`) is deployed and verified with 0 canary hits.

### Tier 3: Authenticated Context Tools (Gated on Multi-Tenant Auth Profiles)
- **Scope:** Complex single-page application (SPA) testing and credentialed testing.
- **Tools:** `Playwright` (authenticated headless browser automation, token-bound session storage).
- **Gate Invariant:** Requires completion of `DEFECT-AUTH-02` (credential vault binding in `AuthzAgent`).

### Tier 4: Retired from Scope / Not Planned
- **OWASP ZAP:** Retired. Heavy Java runtime, slow execution, redundant with Nuclei + ffuf.
- **Amass:** Retired. Resource-intensive graph database, redundant with Subfinder + DNS resolver.
- **sqlmap:** Retired. Automated active database takeover is out-of-scope for safe web application penetration testing.
- **Schemathesis:** Retired. Redundant with raw HTTP prober and custom OpenAPI validation engine.
- **External Interactsh:** Retired per `ADR-007`. Replaced by local callback sink (`pentesa-callback-sink`).
