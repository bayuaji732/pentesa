# ADR-008: Final Architectural Determinations for v1.0 Implementation

## Status
Accepted

## Context
Following the independent architecture review of Pentesa v1.0, several critical implementation decisions were evaluated for operational effectiveness, security posture, and alignment with the platform's core principles.

The architectural leadership has formally determined the resolution of these decisions prior to development.

## Decisions

### 1. Subprocess Environment Isolation Policy
- **Decision:** Mandate strict allowlist-only environment variable construction for all child tool processes (`nuclei`, `katana`, `ffuf`, `subfinder`, `httpx`).
- **Specification:** Child processes inherit strictly: `PATH`, `HOME`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and `TMPDIR`. Platform master encryption keys (`PENTESA_MASTER_KEY`), database passwords (`POSTGRES_PASSWORD`), and JWT secrets (`JWT_SECRET_KEY`) are completely excluded from the child process memory space.

### 2. Local Containerized OAST Callback Sink
- **Decision:** Provision `pentesa-callback-sink` as a native, lightweight service within the Docker Compose topology.
- **Specification:** Replaces reliance on public cloud interaction servers (`interact.sh`). Captures out-of-band DNS and HTTP callbacks locally on the internal `worker_net` network, correlating unique tokens for blind SSRF and blind injection testing without data leakage.

### 3. Composite Uniqueness for Endpoint Inventory
- **Decision:** Define the unique constraint on the `endpoints` table as `UNIQUE (project_id, fqdn, url_path, http_method)`.
- **Specification:** Ensures that multi-domain projects (e.g. `app.example.com` and `admin.example.com`) can catalog identically-named paths (e.g. `/api/v1/profile`) without relational collisions.

### 4. Local-First Default with Configurable Endpoint Abstraction
- **Decision:** Default out-of-the-box operation uses local Ollama (`Llama 3.1 8B` / `Qwen 2.5 14B`), while providing an abstracted OpenAI-compatible client interface.
- **Specification:** Enables organizations with enterprise on-premises vLLM gateways, LiteLLM routers, or private VPC LLMs to route reasoning tasks securely without code changes.

### 5. Dual-Profile Crawling Strategy
- **Decision:** Implement toggleable discovery profiles:
  - *Profile A (Fast Crawler):* High-speed CLI crawling via `katana` (minimal memory footprint).
  - *Profile B (Deep SPA Crawler):* Headless Chromium via Playwright for client-side JavaScript DOM rendering.

### 6. Human-in-the-Loop Approval Thresholds
- **Decision:** Formalize mandatory operator sign-off triggers:
  - Fuzzing volume $> 5,000$ requests.
  - Authentication attempts $> 15$ per target account.
  - State-modifying requests (`POST`, `PUT`, `DELETE`) on production target profiles.
  - Out-of-band SSRF listener probes targeting non-local CIDRs.

## Consequences
- The architectural blueprint is 100% frozen, unambiguous, and hardened against security bypasses.
- No further architectural design is required. The system is fully specified and awaiting authorization for Phase 8 implementation.
