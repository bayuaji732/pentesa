# 5A — Comprehensive AI Agent, Skill & Tool Inventory

> **Document Identifier:** PENTESA-AUDIT-5A-AGENT-INVENTORY-V1.0  
> **Audit Phase:** Phase 5 — AI Agent Evaluation (Step 1 Static Architecture & Code Audit)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, AI Systems Safety Auditor  
> **Date:** November 19, 2026  
> **Methodology:** Static AST Inspection, Code Reading, Schema Analysis & Execution Flow Tracing (Zero LLM Spend)  
> **Vocabulary Governance:** Strictly uses Phase 10 status vocabulary: `Verified`, `Partially Verified`, `Failed`, `Not Implemented`, `Not Tested`.

---

## 1. Executive Summary & Architectural Overview

The Pentesa platform specification documents a 15-agent autonomous penetration testing architecture (`AGT-01` through `AGT-15`) coordinated via a stateful DAG workflow (`docs/05-agent-specifications.md`). 

Inspection of the actual Python codebase reveals an **architectural consolidation** (cataloged under divergence `NI-02`):
- **7 Concrete Agent Classes** exist in `agents/`, subclassing `BaseAgent` (`agents/base.py:27`).
- **8 Agent Responsibilities** from the PRD are merged into the 7 concrete classes or handled directly by core Python engine services (`services/scope_engine/`, `services/discovery_engine/`, `services/evidence_engine/`).
- **18 Skills** (`skills/*/SKILL.md`) exist as static prompt/markdown documentation files, but the dynamic runtime engine to load or execute them is **Not Implemented** (`NI-05`).
- **Worker Process** (`services/execution_engine/worker.py:28`) is an idle polling loop stub (`asyncio.sleep(2)`) (`NI-06`).
- **Execution Engine:** The API server executes workflows in-process via `asyncio.create_task` within `WorkflowSupervisor` (`services/orchestrator/supervisor.py:58`).

In accordance with Phase 5 Step 1 rules, **zero agents are marked "Verified" from code reading alone**. All implemented agents are cataloged as **Not Tested** pending empirical benchmark execution in Steps 2–3.

---

## 2. Agent Inventory Matrix (AGT-01 through AGT-15)

| Agent ID | Declared Agent Name | Implementation File & Line | Structural Status | Evaluation Status | Tools Allowed | Handoff Input (From) | Handoff Output (To) |
|---|---|---|---|---|---|---|---|
| **AGT-01** | Project Planning Agent | `agents/planner/planner_agent.py:16` | Concrete Class | **Not Tested** | `db_query`, `policy_evaluator`, `wstg_planner` | Supervisor (Initial) | AGT-03 (Recon) |
| **AGT-02** | Scope Validation Agent | `services/scope_engine/service.py:15`<br>`services/scope_engine/validator.py:18` | Consolidated Service | **Not Tested** | `dns_resolver`, `cidr_matcher` | Supervisor / AGT-01 | Probers / Tools |
| **AGT-03** | Reconnaissance Agent | `agents/recon/recon_agent.py:27` | Concrete Class (Merged AGT-03/04) | **Not Tested** | `subfinder`, `tls_inspector`, `web_crawler`, `parameter_extractor` | AGT-01 (Planner) | AGT-05 (WSTG) |
| **AGT-04** | Attack Surface Mapping Agent | `agents/recon/recon_agent.py:27`<br>`services/discovery_engine/crawler.py:25` | Consolidated into AGT-03 | **Not Tested** | `web_crawler`, `parameter_extractor` | AGT-01 (Planner) | AGT-05 (WSTG) |
| **AGT-05** | WSTG Assessment Agent | `agents/wstg/wstg_agent.py:25` | Concrete Class | **Not Tested** | `wstg_runner`, `http_prober`, `headers_analyzer`, `metafiles_checker` | AGT-03 (Recon) | AGT-09 (Vuln) |
| **AGT-06** | Authentication Testing Agent | `agents/authorization/authz_agent.py:20`<br>`services/execution_engine/runners.py:180` | Consolidated into AGT-07 | **Not Tested** | `http_prober`, `token_analyzer` | AGT-05 (WSTG) | AGT-07 (Authz) |
| **AGT-07** | Authorization Testing Agent | `agents/authorization/authz_agent.py:20` | Concrete Class (Merged AGT-06/07/14) | **Not Tested** | `multi_identity_prober`, `http_prober`, `token_analyzer` | AGT-09 (Vuln) | AGT-11 (Validation) |
| **AGT-08** | Input Validation Agent | `agents/vulnerability/vuln_agent.py:28`<br>`services/execution_engine/runners.py:240` | Consolidated into AGT-09 | **Not Tested** | `check_runner`, `nuclei_runner` | AGT-05 (WSTG) | AGT-09 (Vuln) |
| **AGT-09** | Vulnerability Detection Agent | `agents/vulnerability/vuln_agent.py:28` | Concrete Class (Merged AGT-08/09/10) | **Not Tested** | `nuclei_runner`, `ffuf_runner`, `check_runner` | AGT-05 (WSTG) | AGT-07 (Authz) |
| **AGT-10** | Controlled Fuzzing Agent | `agents/vulnerability/vuln_agent.py:233`<br>`integrations/ffuf/runner.py:42` | Consolidated into AGT-09 | **Not Tested** | `ffuf_runner` | AGT-09 (Vuln) | AGT-07 (Authz) |
| **AGT-11** | Vulnerability Validation Agent | `agents/validation/validation_agent.py:23` | Concrete Class (Merged AGT-11/12/13) | **Not Tested** | `repro_harness`, `curl_builder`, `response_differ`, `fp_heuristic`, `dedup_engine` | AGT-07 (Authz) | AGT-15 (Reporting) |
| **AGT-12** | False Positive Analysis Agent | `agents/validation/validation_agent.py:151` | Consolidated into AGT-11 | **Not Tested** | `fp_heuristic`, `response_differ` | AGT-11 (Validation) | AGT-15 (Reporting) |
| **AGT-13** | Evidence Collection Agent | `agents/validation/validation_agent.py:102`<br>`services/evidence_engine/collector.py:18` | Consolidated into AGT-11 & Services | **Not Tested** | `curl_builder`, `repro_harness` | AGT-11 (Validation) | AGT-15 (Reporting) |
| **AGT-14** | Business Logic Analysis Agent | `agents/authorization/authz_agent.py:72` | Consolidated Stub in AGT-07 | **Not Tested** | `multi_identity_prober` | AGT-09 (Vuln) | AGT-11 (Validation) |
| **AGT-15** | PTES Reporting Agent | `agents/reporting/reporting_agent.py:15` | Concrete Class | **Not Tested** | `report_compiler`, `cvss_calculator`, `markdown_generator` | AGT-11 (Validation) | Workflow Completion |

---

## 3. Forensic Agent Specifications (The 7 Active Agent Classes)

### 3.1 AGT-01: Project Planning Agent (`ProjectPlanningAgent`)
- **Source Location:** [`agents/planner/planner_agent.py:16-66`](file:///c:/Users/User2/Documents/work/pentesa/agents/planner/planner_agent.py#L16-L66)
- **Declared Responsibility:** Scopes engagement Rules of Engagement (RoE), formulates scanning strategy and rate limits based on `scan_profile` (`QUICK`, `FULL`, `DEEP`), and initializes the project WSTG test instance catalog.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.approved_scope`.
  - *Writes / Mutates:* `state.wstg_matrix_state` (maps `inst.wstg_id` $\to$ status), appends execution log, transitions phase to `RECON`.
- **Handoff Topology:**
  - *Receives From:* `WorkflowSupervisor.execute_workflow` (pipeline entry point).
  - *Hands Off To:* `AGT-03` (`ReconnaissanceAgent`).
- **Tool Allowlist:**
  - `["db_query", "policy_evaluator", "wstg_planner"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()` verifies `tool_name in self.allowed_tools`. Unauthorized tool names trigger `PermissionError` and write `AGENT_TOOL_CALL_BLOCKED` to the cryptographic audit log.
- **LLM Input & Output Validation:**
  - *Prompt Construction:* Formats scope JSON and scan profile into raw prompt string.
  - *LLM Call:* `self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)`.
  - *Parsing & Schema:* LLM text output is **not** validated against a Pydantic schema; it is stored raw as the `AgentDecision.thought_trace`. Test instance initialization occurs deterministically via `WSTGPlannerService(self.session).initialize_project_instances()`.
- **Timeout & Retry Config:** LLM provider default (120.0s timeout). Zero supervisor-level retry.

---

### 3.2 AGT-03 / AGT-04: Reconnaissance & Surface Mapping Agent (`ReconnaissanceAgent`)
- **Source Location:** [`agents/recon/recon_agent.py:27-219`](file:///c:/Users/User2/Documents/work/pentesa/agents/recon/recon_agent.py#L27-L219)
- **Declared Responsibility:** Merges AGT-03 (Passive Subdomain Discovery) and AGT-04 (Attack Surface Mapping). Resolves seed hostnames, performs scoped HTTP crawling, extracts endpoint paths, query parameters, and builds endpoint inventory.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.approved_scope`, `state.target_base_url`.
  - *Writes / Mutates:* `state.discovered_subdomains`, `state.target_base_url`, `state.endpoints_inventory` (list of endpoint dicts with path, method, schema, auth requirement), transitions phase to `WSTG_PLANNING`.
- **Handoff Topology:**
  - *Receives From:* `AGT-01` (`ProjectPlanningAgent`).
  - *Hands Off To:* `AGT-05` (`WSTGAssessmentAgent`).
- **Tool Allowlist:**
  - `["subfinder", "tls_inspector", "web_crawler", "parameter_extractor"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **LLM Input & Output Validation:**
  - *LLM Call:* Calls LLM in `json_mode=True` to log a thought trace on crawl strategy.
  - *Parsing & Schema:* LLM output is not used to populate seeds; seeds are extracted strictly from database `DiscoveredDomain`, `approved_scope.target_domains`, or `ScopeRule` patterns. Crawl execution is driven by `discovery_service.execute_crawl(CrawlRequest(...))`.
- **Timeout & Retry Config:** Crawl HTTP client has 4.0s timeout (1.5s connect); automatic HTTP fallback for public HTTP-only targets if default HTTPS yields 0 endpoints.

---

### 3.3 AGT-05: OWASP WSTG Assessment Agent (`WSTGAssessmentAgent`)
- **Source Location:** [`agents/wstg/wstg_agent.py:25-268`](file:///c:/Users/User2/Documents/work/pentesa/agents/wstg/wstg_agent.py#L25-L268)
- **Declared Responsibility:** Maps discovered attack surface against the 12 OWASP WSTG v4.2 categories. Dispatches category-specific runners (`TestExecutionCreate`), updates test instance statuses, executes live security-header evaluations, and generates candidate findings.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.endpoints_inventory`, `state.discovered_subdomains`, `state.target_base_url`.
  - *Writes / Mutates:* `state.wstg_matrix_state`, `state.candidate_findings` (appends missing header candidates), transitions phase to `ACTIVE_ASSESSMENT`.
- **Handoff Topology:**
  - *Receives From:* `AGT-03` (`ReconnaissanceAgent`).
  - *Hands Off To:* `AGT-09` (`VulnerabilityAgent`).
- **Tool Allowlist:**
  - `["wstg_runner", "http_prober", "headers_analyzer", "metafiles_checker"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **LLM Input & Output Validation:**
  - *LLM Call:* `json_mode=True` to log WSTG testing plan reasoning.
  - *Parsing & Schema:* Dispatches execution via `WSTGExecutionService.dispatch_execution(TestExecutionCreate(...))`. Candidate findings for missing defensive headers (CSP, HSTS, XFO, XCTO) are deterministically compiled from `safe_request()` wire observations without relying on LLM parsing.
- **Timeout & Retry Config:** Header probe client timeout: 5.0s (3.0s connect). WSTG test dispatch batch limits: 5 (QUICK), 15 (FULL), 30 (DEEP).

---

### 3.4 AGT-09 / AGT-08 / AGT-10: Vulnerability Detection Agent (`VulnerabilityAgent`)
- **Source Location:** [`agents/vulnerability/vuln_agent.py:28-501`](file:///c:/Users/User2/Documents/work/pentesa/agents/vulnerability/vuln_agent.py#L28-L501)
- **Declared Responsibility:** Consolidates AGT-08 (Input Validation), AGT-09 (Vulnerability Detection), and AGT-10 (Controlled Fuzzing). Executes sandboxed Nuclei scanner templates, controlled `ffuf` directory fuzzing, and direct diagnostic exposure probes. Enforces Human-in-the-Loop (HITL) approval gates when `auto_approve_medium=False`.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.target_base_url`, `state.discovered_subdomains`, `state.endpoints_inventory`, `state.auto_approve_medium`, `state.workflow_id`.
  - *Writes / Mutates:* `state.candidate_findings` (ingests findings from Nuclei, ffuf, and direct HTTP probers), `state.status` (`WAITING_APPROVAL` if HITL gate triggers), transitions phase to `VALIDATION` (or `ACTIVE_ASSESSMENT`).
- **Handoff Topology:**
  - *Receives From:* `AGT-05` (`WSTGAssessmentAgent`).
  - *Hands Off To:* `AGT-07` (`AuthorizationAgent`).
- **Tool Allowlist:**
  - `["nuclei_runner", "ffuf_runner", "check_runner"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **Subcommand & Execution Boundaries:**
  - Subprocess execution strictly via `asyncio.create_subprocess_exec` (`services/execution_engine/tools/base.py:108-142`).
  - Shell execution (`shell=True`) strictly prohibited.
  - `NucleiRunner`: options schema restricts template base path to `/opt/nuclei-templates` (`build_argv` in `integrations/nuclei/runner.py:25-80`); redirect flags (`-follow-redirects`, `-fr`, `-r`) are stripped.
  - `FfufRunner`: wordlist restricted to `/opt/wordlists/`; rate limit clamped to $\le 50$ rps; redirect flags (`-r`, `-recursion`) stripped (`integrations/ffuf/runner.py:48-78`).
- **LLM Input & Output Validation:**
  - *LLM Call:* `json_mode=True` to reason about template tags.
  - *Parsing & Schema:* Zero synthetic findings from LLM. Findings populated strictly from database `Finding` records created by `ToolService` execution or direct wire HTTP status/body matching.
- **Timeout & Retry Config:** Nuclei subprocess timeout: 30s; per-probe HTTP timeout: 5s. Ffuf timeout: 20s. Direct prober timeout: 8.0s (3.5s connect).

---

### 3.5 AGT-07 / AGT-06 / AGT-14: Authorization Testing Agent (`AuthorizationAgent`)
- **Source Location:** [`agents/authorization/authz_agent.py:20-244`](file:///c:/Users/User2/Documents/work/pentesa/agents/authorization/authz_agent.py#L20-L244)
- **Declared Responsibility:** Assesses object-level authorization (IDOR/BOLA), authentication context, and business logic endpoints using live HTTP differential probing.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.endpoints_inventory`, `state.target_base_url`, `state.discovered_subdomains`.
  - *Writes / Mutates:* `state.candidate_findings` (appends BOLA candidate if data leakage detected), execution logs.
- **Handoff Topology:**
  - *Receives From:* `AGT-09` (`VulnerabilityAgent`).
  - *Hands Off To:* `AGT-11` (`ValidationAgent`).
- **Tool Allowlist:**
  - `["multi_identity_prober", "http_prober", "token_analyzer"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **LLM Input & Output Validation:**
  - *LLM Call:* Generates reasoning prompt regarding access control boundaries.
  - *Defect Note (`DEFECT-AUTH-02`):* Probing logic substitutes path integer `/1` with `/2`, but issues unauthenticated requests (`headers=None`). Does not query `AuthProfile` credentials or mint dual-user tokens.
- **Timeout & Retry Config:** HTTP client probe timeout: 5.0s (3.0s connect).

---

### 3.6 AGT-11 / AGT-12 / AGT-13: Vulnerability Validation Agent (`ValidationAgent`)
- **Source Location:** [`agents/validation/validation_agent.py:23-271`](file:///c:/Users/User2/Documents/work/pentesa/agents/validation/validation_agent.py#L23-L271)
- **Declared Responsibility:** Consolidates AGT-11 (Vulnerability Validation), AGT-12 (False Positive Analysis), and AGT-13 (Evidence Collection). Enforces the Evidence Triad: executes deterministic reproduction probes, captures raw HTTP request/response wire pairs, computes SHA-256 hashes, refutes false positives (WAF block pages, 404s), and promotes confirmed findings via `FindingService`.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.candidate_findings`.
  - *Writes / Mutates:* `state.confirmed_findings`, `state.false_positives`, transitions phase to `REPORTING`.
- **Handoff Topology:**
  - *Receives From:* `AGT-07` (`AuthorizationAgent`).
  - *Hands Off To:* `AGT-15` (`ReportingAgent`).
- **Tool Allowlist:**
  - `["repro_harness", "curl_builder", "response_differ", "fp_heuristic", "dedup_engine"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **LLM Input & Output Validation:**
  - *Prompt:* Supplies candidate title, target URL, and raw request/response wire excerpts.
  - *Parsing Mechanism:* Strips Markdown code blocks (````json ... ````), performs `json.loads()`, and evaluates boolean keys:
    ```python
    if parsed.get("is_valid") is False or parsed.get("is_false_positive") is True:
        is_false_positive = True
    ```
  - *Fallback Parser:* If JSON parsing fails, performs substring heuristic matching (`"waf_block_page" in low or ...`).
  - *Finding Promotion:* Confirmed findings are validated against `FindingCreate` schema and saved to PostgreSQL via `FindingService.create_finding()`.
- **Timeout & Retry Config:** Live reproduction probe timeout: 3.0s (1.5s connect). LLM timeout: 120s.

---

### 3.7 AGT-15: PTES Reporting Agent (`ReportingAgent`)
- **Source Location:** [`agents/reporting/reporting_agent.py:15-74`](file:///c:/Users/User2/Documents/work/pentesa/agents/reporting/reporting_agent.py#L15-L74)
- **Declared Responsibility:** Synthesizes confirmed findings, evidence artifacts, and WSTG coverage metrics into a PTES-compliant deliverable, generating executive summaries and prioritized remediation roadmaps.
- **Workflow State Interactions:**
  - *Reads:* `state.project_id`, `state.scan_profile`, `state.confirmed_findings`, `state.false_positives`, `state.endpoints_inventory`.
  - *Writes / Mutates:* Sets `state.status = "COMPLETED"`, transitions phase to `COMPLETED`.
- **Handoff Topology:**
  - *Receives From:* `AGT-11` (`ValidationAgent`).
  - *Hands Off To:* Workflow completion / termination.
- **Tool Allowlist:**
  - `["report_compiler", "cvss_calculator", "markdown_generator"]`
  - *Enforcement Mechanism:* `BaseAgent.log_tool_call()`.
- **LLM Input & Output Validation:**
  - *Prompt:* Formats confirmed findings JSON and endpoints inventory.
  - *Output Handling:* Directly takes `llm_res.content` as the executive summary text. Emits report structure via `log_tool_call(tool_name="report_compiler", output_result=report_data)`.
- **Timeout & Retry Config:** LLM provider default (120s).

---

## 4. Skills Inventory (18 Markdown Specifications)

All 18 skills are located in `skills/`. Inspection confirms that **zero Python modules load, parse, or execute these files** (`NI-05`). They function as prompt specifications / documentation templates:

| Skill Directory | Skill File | Responsibility / Domain | Code References | Runtime Execution Status |
|---|---|---|---|---|
| `controlled-fuzzing` | `skills/controlled-fuzzing/SKILL.md` | Rate-limited directory fuzzing with SecLists | None | **Not Implemented** (`NI-05`) |
| `endpoint-extraction` | `skills/endpoint-extraction/SKILL.md` | SPA & JavaScript endpoint extraction | None | **Not Implemented** (`NI-05`) |
| `evidence-collection` | `skills/evidence-collection/SKILL.md` | Raw wire capture & SHA-256 evidence hashing | None | **Not Implemented** (`NI-05`) |
| `false-positive-analysis` | `skills/false-positive-analysis/SKILL.md` | WAF error refutation & heuristic analysis | None | **Not Implemented** (`NI-05`) |
| `hidden-path-discovery` | `skills/hidden-path-discovery/SKILL.md` | Wordlist-based hidden route discovery | None | **Not Implemented** (`NI-05`) |
| `nuclei-scanning` | `skills/nuclei-scanning/SKILL.md` | Pinned template CVE & misconfig prober | None | **Not Implemented** (`NI-05`) |
| `parameter-discovery` | `skills/parameter-discovery/SKILL.md` | Query, JSON, and form parameter parsing | None | **Not Implemented** (`NI-05`) |
| `ptes-reporting` | `skills/ptes-reporting/SKILL.md` | PTES structure & CVSS v3.1 scoring | None | **Not Implemented** (`NI-05`) |
| `scope-validation` | `skills/scope-validation/SKILL.md` | CIDR, domain, and redirect validation | None | **Not Implemented** (`NI-05`) |
| `subdomain-discovery` | `skills/subdomain-discovery/SKILL.md` | Passive DNS & certificate transparency | None | **Not Implemented** (`NI-05`) |
| `technology-fingerprinting` | `skills/technology-fingerprinting/SKILL.md` | Server headers & Wappalyzer signatures | None | **Not Implemented** (`NI-05`) |
| `vulnerability-validation` | `skills/vulnerability-validation/SKILL.md` | Evidence Triad reproduction harness | None | **Not Implemented** (`NI-05`) |
| `web-crawling` | `skills/web-crawling/SKILL.md` | Scope-aware HTML crawler configuration | None | **Not Implemented** (`NI-05`) |
| `wstg-auth-testing` | `skills/wstg-auth-testing/SKILL.md` | WSTG-ATHN authentication test rules | None | **Not Implemented** (`NI-05`) |
| `wstg-authz-testing` | `skills/wstg-authz-testing/SKILL.md` | WSTG-ATHZ IDOR and privilege rules | None | **Not Implemented** (`NI-05`) |
| `wstg-info-gathering` | `skills/wstg-info-gathering/SKILL.md` | WSTG-INFO reconnaissance checklist | None | **Not Implemented** (`NI-05`) |
| `wstg-input-validation` | `skills/wstg-input-validation/SKILL.md` | WSTG-INPV SQLi, XSS, and command injection | None | **Not Implemented** (`NI-05`) |
| `wstg-session-testing` | `skills/wstg-session-testing/SKILL.md` | WSTG-SESS cookie & session token analysis | None | **Not Implemented** (`NI-05`) |

---

## 5. Tool Wrapper & Integration Inventory

| Tool / Wrapper Name | Source Location | Invoked Binary / Library | Subprocess Execution Model | Security & Scope Controls |
|---|---|---|---|---|
| **`NucleiRunner`** | [`integrations/nuclei/runner.py:19`](file:///c:/Users/User2/Documents/work/pentesa/integrations/nuclei/runner.py#L19) | `/usr/local/bin/nuclei` | `asyncio.create_subprocess_exec` (safe `argv: List[str]`, no shell) | Template path strictly locked to `/opt/nuclei-templates`; redirect flags (`-fr`, `-r`, `-follow-redirects`) stripped; per-probe timeout clamped to $\le 30$s. Soft-404 baseline filtering. |
| **`FfufRunner`** | [`integrations/ffuf/runner.py:42`](file:///c:/Users/User2/Documents/work/pentesa/integrations/ffuf/runner.py#L42) | `/usr/local/bin/ffuf` | `asyncio.create_subprocess_exec` (safe `argv: List[str]`, no shell) | Wordlist locked to `/opt/wordlists/`; rate limit clamped to $\le 50$ rps; redirect and recursion flags (`-r`, `-recursion`) stripped. |
| **`RawHttpClient`** | [`services/execution_engine/tools/http_client.py:19`](file:///c:/Users/User2/Documents/work/pentesa/services/execution_engine/tools/http_client.py#L19) | `httpx.AsyncClient` | Native async Python | Bounded redirect loop (max 5 hops) with DNS re-pinning and cross-origin credential stripping (`safe_request`). |
| **`ToolService`** | [`services/execution_engine/tools/service.py:26`](file:///c:/Users/User2/Documents/work/pentesa/services/execution_engine/tools/service.py#L26) | Dispatcher for Nuclei & Ffuf | In-process Python dispatcher | Validates tool against registered runners; logs `ToolExecution` record in PostgreSQL. |
| **`Soft404Baseline`** | [`services/execution_engine/tools/soft_404.py:12`](file:///c:/Users/User2/Documents/work/pentesa/services/execution_engine/tools/soft_404.py#L12) | Native Python heuristic | In-process pattern & similarity diff | Computes random-path baseline to filter SPA catch-all false positives (`TOOL-FP-01`). |

---

## 6. Worker Stubs & Dead Code

- **Worker Module:** [`services/execution_engine/worker.py:28-60`](file:///c:/Users/User2/Documents/work/pentesa/services/execution_engine/worker.py#L28-L60)
  - *Declared Capability:* Autonomous asynchronous execution worker consuming Redis queues.
  - *Actual Implementation State:* **Idle Stub (`NI-06`).** The loop executes `while not SHUTDOWN_EVENT.is_set(): await asyncio.sleep(2)`. No Celery or Redis queue consumers are wired. All workflow executions occur in-process in the API server container.
- **Mock Multi-Identity Prober:** [`agents/authorization/authz_agent.py:148-168`](file:///c:/Users/User2/Documents/work/pentesa/agents/authorization/authz_agent.py#L148-L168)
  - *Actual Implementation State:* Unauthenticated scalar integer prober (`safe_request(..., headers=None)`). Lacks session management or token switching (`DEFECT-AUTH-02`).

---

## 7. Status Summary for Phase 5 Step 1

| Component Category | Total Count | Active / Concrete | Consolidated / Service | Stub / Dead Code | Not Tested |
|---|:---:|:---:|:---:|:---:|:---:|
| **Documented Agents (AGT-01..15)** | 15 | 7 | 7 | 1 (Authz Multi-ID prober stub) | 15 |
| **Skills (SKILL.md)** | 18 | 0 | 0 | 18 (Prompt docs, no runtime) | 18 |
| **Tool Wrappers & Services** | 5 | 5 | 0 | 0 | 5 |
| **Async Execution Worker** | 1 | 0 | 0 | 1 (Idle polling stub NI-06) | 1 |

---

## 8. Addendum: LLM Influence Map & Tool Wrapper Gap Analysis

### 8.1 LLM Influence Map (Decision Authority: LLM vs Deterministic Code)

To establish rigorous provenance over agent behavior, each agent class was inspected to determine whether operational decisions (tool dispatches, scan paths, vulnerability validations, state mutations) are driven by the Large Language Model or by deterministic Python code.

| Agent ID & Class | Decision / Operation | Decision Authority | Description & Implementation Reality |
|---|---|:---:|---|
| **AGT-01** (`ProjectPlanningAgent`) | Scan Strategy & Rate Limits | **Deterministic Code** | LLM generates a freeform thought trace; test instance initialization is executed deterministically by `WSTGPlannerService.initialize_project_instances()` based on the static `scan_profile` parameter. |
| **AGT-03 / AGT-04** (`ReconnaissanceAgent`) | Crawl Depth & Target Traversal | **Deterministic Code** | LLM generates a thought trace; crawling is executed by `AsyncWebCrawler` using standard HTML/JS regex parsing. Scope checks are enforced deterministically by `ScopeService.check_target()`. |
| **AGT-05** (`WSTGAssessmentAgent`) | Test Case Execution Plan | **Deterministic Code** | LLM provides a thought trace; WSTG test probes are dispatched deterministically by `WSTGRunner` and `check_headers` iterating over the project's seeded WSTG catalog. |
| **AGT-07** (`AuthorizationAgent`) | BOLA / IDOR Probing | **Deterministic Code** | LLM generates an anomaly hypothesis; the prober deterministically substitutes static integer IDs (`1` and `2`) in URL path templates. |
| **AGT-09 / AGT-10** (`VulnerabilityAgent`) | Tool Invocations (Nuclei / Ffuf) | **Deterministic Code** | LLM generates an analysis summary; scanner subprocess execution arguments, wordlists, and templates are compiled deterministically by `NucleiRunner` and `FfufRunner`. |
| **AGT-11 / AGT-12** (`ValidationAgent`) | Finding Validation & Promotion | **LLM Semantic Output** *(Vulnerable)* | **Critical Architectural Finding:** This is the ONLY agent where LLM output directly drives a state mutation. The agent inspects `parsed.get("is_valid")` from the LLM. If `is_valid: true`, the candidate is promoted to `confirmed_findings` without validating that the empirical reproduction probe succeeded (`DEFECT-AGENT-01`). |
| **AGT-15** (`ReportingAgent`) | Executive Summary & Deliverables | **LLM Text Generation** | LLM writes the narrative executive summary string; finding tables, severity matrices, and CVSS scores are compiled deterministically from PostgreSQL records. |

> **Key Architectural Finding:**  
> In 5 of the 7 active agents (AGT-01, AGT-03, AGT-05, AGT-07, AGT-09), the LLM functions purely as an explanatory co-pilot generating textual thought traces and rationales. All routing, scanning, and tool dispatching are 100% deterministic code. In AGT-15, the LLM provides content synthesis. Only in **AGT-11 (`ValidationAgent`)** does LLM generation possess operational decision authority over finding promotion—which directly introduced `DEFECT-AGENT-01`.

---

### 8.2 Tool Wrapper Inventory Gaps (Specification vs Codebase)

A comparison between the integration specifications in `docs/09-tool-integrations.md`, agent tool allowlists, and the actual files in `integrations/` and `services/execution_engine/tools/` reveals that several specified tools lack executable wrappers:

| Tool Identifier | Spec Reference | Agent Allowlist Reference | Actual Implementation State | Gap Classification |
|---|---|---|---|---|
| **`subfinder`** | `docs/09-tool-integrations.md` §5.3 | `AGT-03` (`ReconnaissanceAgent`) | **Missing in Code.** No subprocess runner or CLI wrapper exists in `integrations/`. Subdomain resolution relies on Python socket lookups. | Tooling Gap (`NI-04`) |
| **`tls_inspector`** | `docs/09-tool-integrations.md` §5.7 | `AGT-03` (`ReconnaissanceAgent`) | **Missing in Code.** No dedicated SSL/TLS cipher inspection wrapper exists. Basic TLS certificate expiry is checked via standard Python `ssl` library. | Tooling Gap |
| **`web_crawler`** (`katana`) | `docs/09-tool-integrations.md` §5.2 | `AGT-03`, `AGT-04` | **Replaced by Native Python.** No Katana binary runner exists; crawling is performed in-process via `httpx` + `BeautifulSoup4` (`services/discovery_engine/crawler.py`). | Architectural Replacement |
| **`token_analyzer`** | `docs/05-agent-specifications.md` §4.6 | `AGT-06`, `AGT-07` | **Missing in Code.** No Shannon entropy calculation or session token predictability wrapper exists. | Feature Gap |
| **`multi_identity_prober`**| `docs/05-agent-specifications.md` §4.7 | `AGT-07` (`AuthorizationAgent`) | **Unauthenticated Stub.** Implemented as unauthenticated `safe_request(headers=None)` in `agents/authorization/authz_agent.py:148-168`; lacks multi-tenant session context (`DEFECT-AUTH-02`). | Functional Defect |

