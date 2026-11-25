# Phase 9: Comprehensive Security Tooling Matrix & Inventory

> **Document Identifier:** `9A-TOOL-INVENTORY-V1.0`  
> **Evaluation Date:** `2026-11-24`  
> **Target Environment:** `pentesa-prod` (`pentesa-api`, `pentesa-worker`, Docker engine)  
> **Baseline Source:** `docs/09-tool-integrations.md`, `agents/`, `integrations/`, `infrastructure/docker/`, `benchmark/`  
> **Audit Status:** Complete & Empirically Verified

---

## 1. Executive Summary & Tooling Landscape

The Pentesa documentation across `docs/00` through `docs/09` describes an extensive multi-tool offensive security platform integrating 18+ tools covering reconnaissance, active port scanning, headless crawling, directory fuzzing, CVE scanning, and API schema testing.

Empirical container and codebase auditing reveals that:
- **Only 5 tool capabilities are fully Implemented-and-Used:** `Nuclei` (CLI), `ffuf` (CLI), `Python Check Engine` (native), `SSL/TLS Analyzer` (Python `ssl`), and `Header Analyzer` (Python `SecurityHeadersRunner`).
- **1 tool has a severe packaging defect (`httpx`):** The Python `httpx` library is heavily used, but `/usr/local/bin/httpx` CLI is a broken stub because `pip install 'httpx[cli]'` was omitted from Dockerfiles; the ProjectDiscovery Go binary is absent.
- **1 tool is Allowlisted-only (`Subfinder`):** Documented in `docs/09` §5.3 and named in `ReconAgent.allowed_tools`, but has zero wrapper code and no binary in containers.
- **12 tools are Documented-only or Absent:** Nmap, Amass, Naabu, Katana, Playwright, Feroxbuster, Arjun, OWASP ZAP, sqlmap, Schemathesis, and Interactsh (OAST).

---

## 2. Comprehensive 18-Tool Audit Matrix

| # | Tool Name | Documented in `docs/09` | Wrapper File : Line | Agent Allowlist Name | Binary in `api` / `worker` Image | Pinned in Dockerfile | Used in Evidence Run | Status Classification |
|:---|:---|:---:|:---|:---:|:---:|:---:|:---|:---:|
| **1** | **Nuclei** | §5.1 | `integrations/nuclei/runner.py:19`<br>(`NucleiRunner`) | `VulnAgent`<br>(`nuclei_runner`) | `/usr/local/bin/nuclei`<br>(v3.3.7) | `v3.3.7`<br>(SHA-256 pinned)<br>Templates: `v10.5.2` | Phase 3, 4, 5, 7, 8 (`score_p7.txt`, `score_p8.txt`) | **Implemented-and-Used** |
| **2** | **ffuf** | §5.5 | `integrations/ffuf/runner.py:42`<br>(`FfufRunner`) | `VulnAgent`<br>(`ffuf_runner`) | `/usr/local/bin/ffuf`<br>(v2.1.0) | `v2.1.0`<br>(SHA-256 pinned)<br>SecLists: `0c618cf` | Phase 3 (`3A-checkpoint.md`), Phase 8 (`P8-TC-RATE-01`) | **Implemented-and-Used** |
| **3** | **Python Check Engine** | §5.6 | `services/execution_engine/`<br>`runners.py:164`<br>(`BaseTestRunner`) | `VulnAgent` (`check_runner`),<br>`WstgAgent` (`wstg_runner`) | Native Python 3.12 runtime | `python:3.12-slim-bookworm` | Phase 3, 4, 5, 6, 7 (WSTG-CONF-01–07 checks) | **Implemented-and-Used** |
| **4** | **SSL/TLS Analyzer** | §5.7 | `services/execution_engine/`<br>`runners.py:381`<br>(`GenericProbeRunner`) | `ReconAgent`<br>(`tls_inspector`) | Native Python runtime | Built into Python 3.12 | Phase 3 baseline (`RUN-PENTESA-BENCH-DEEP-01`) | **Implemented-and-Used** |
| **5** | **Header Analyzer** | §5.8 | `services/execution_engine/`<br>`runners.py:175` | `WstgAgent`<br>(`headers_analyzer`) | `SecurityHeadersRunner` | Platform code | Phase 3, 7 (39 findings derived from header inspection) | **Implemented-and-Used** |
| **6** | **httpx (Python Library)** | §5.4 | `services/execution_engine/`<br>`tools/http_client.py:19` | `WstgAgent` (`http_prober`),<br>`AuthzAgent` (`http_prober`) | Python `httpx==0.27.2`<br>(`import httpx`) | `pyproject.toml`<br>(`httpx>=0.27.0`) | Phase 2, 3, 4, 5, 6, 7, 8 (all HTTP requests) | **Implemented-and-Used** |
| **7** | **httpx (ProjectDiscovery Go CLI)** | §5.4 | Absent (Zero CLI wrapper) | None | Absent<br>(`/usr/local/bin/httpx` is broken Python console script) | Absent from Dockerfile<br>(Go binary never built/copied) | Never used | **Absent**<br>(ProjectDiscovery CLI Absent;<br>Python entrypoint broken) |
| **8** | **Subfinder** | §5.3 | Absent (Zero wrapper) | `ReconAgent`<br>(`subfinder`) | Absent in both images (`which subfinder` empty) | No | Never used | **Allowlisted-only**<br>(Action: remove from allowlist<br>or implement per ADR-002) |
| **9** | **Katana** | §5.2 | Absent (`services/crawler/`<br>uses custom BeautifulSoup) | None (`ReconAgent` allowlists `web_crawler`) | Absent in both images (`which katana` empty) | No | Never used (in-house Python crawler used instead) | **Documented-only** |
| **10** | **Playwright** | PRD §4.2 | Absent | None | Absent in both images | No | Never used (Phase 6b confirmed SPA unparsed) | **Documented-only** |
| **11** | **Nmap** | PRD §4.2 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **12** | **Naabu** | Evaluation §4 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **13** | **Amass** | Roadmap §3 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **14** | **Feroxbuster** | Evaluation §4 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **15** | **Arjun** | Evaluation §4 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **16** | **OWASP ZAP** | Vision §2 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **17** | **sqlmap** | Vision §2 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **18** | **Schemathesis** | Evaluation §4 | Absent | None | Absent in both images | No | Never used | **Documented-only** |
| **19** | **Interactsh (OAST)** | §3.6 | Absent (Spec mandates local `pentesa-callback-sink`) | None | Absent in both images (`nuclei` runs with `-no-interactsh`) | No | Never used | **Documented-only** |

---

## 3. Baseline Adapter Audit & Execution Topology

- **Adapter Script:** `benchmark/baseline_adapter.py`
- **Purpose:** Standardizes raw scanner JSON/JSONL outputs from independent baseline tools into the Phase 7/8 quality finding schema required by `benchmark/score.py`.
- **Supported Baseline Tools:**
  1. **Nuclei:** Tag-based vulnerability findings transformed via `adapt_nuclei_findings()`. Normalizes `matched_at`, raw request/response, CWE, and generates `reproduction_curl`.
  2. **ffuf:** Fuzzing discovery outputs transformed via `adapt_ffuf_findings()`. Extracts discovered paths, status codes, and wordlist parameters.
- **Execution Container Topology:**
  - In baseline benchmarks, tools executed directly inside `pentesa-worker` (and temporarily `pentesa-api` during P8 rate testing).
  - Both containers run Debian Bookworm with pinned binary installations of `nuclei` (3.3.7) and `ffuf` (2.1.0) under `/usr/local/bin/`.
  - Tools are executed with sandboxed env (`build_sanitized_env()`) stripped of database credentials, but currently lack `asyncio.CancelledError` trapping (`DEFECT-RES-01`).

---

## 4. Key Gaps & Strategic Recommendations

1. **`httpx` CLI Packaging Discrepancy:**
   - Either add `httpx[cli]` to `requirements.txt` or download ProjectDiscovery's standalone Go `httpx` binary if active probing features (e.g. tech detection, title extraction, status probe) are required by the pipeline.
2. **Reconnaissance Tooling Disconnection (Subfinder):**
   - `ReconAgent` allowlists `subfinder`, yet `subfinder` is absent from images with zero wrapper code. The agent currently fails or simulates. Action: remove from allowlist or implement (ADR-002) once external egress controls (`NI-03`) are in place.
3. **Crawl Depth Deficit (`Katana` vs In-House Crawler):**
   - The in-house crawler (`services/crawler/crawler.py`) is a basic static HTML parser that cannot execute JavaScript or handle SPAs. Katana or Playwright is urgently needed to resolve `DISCO-SPA-01` and `RECON-01`.
