# ADR-009: Transition to Enterprise Light Theme, Progressive Lifecycle Navigation, and Streaming Agent Terminal

## Status
Accepted

## Context
Following real-world operational evaluation of the Pentesa SOC Console, four critical UI/UX improvements were established to elevate the platform from a prototype dark-mode dashboard to an enterprise-grade penetration testing platform:

1. **Enterprise Light Theme & Aesthetic Alignment:**  
   The previous v2.0 UI specification enforced a pure dark cyberpunk aesthetic (`#030712` canvas, neon accents). Security engineering directors, compliance auditors, and enterprise penetration testers require an authoritative, high-clarity light theme. The visual system must align with the verified `codemax-ai-FE-BE-Core` design tokens (modern OKLCH color space, Sapphire Blue primary `#1e3a8a`, crisp 1px neutral slate borders `#e2e8f0`, and pure white paper surfaces).

2. **Sequential Pentest Methodology vs. Flat Navigation:**  
   Offensive security follows the standardized **PTES (Penetration Testing Execution Standard)** lifecycle. Presenting an unorganized, flat menu of 12 disconnected items created cognitive overload and allowed operators to inadvertently bypass prerequisite phases (such as Rules of Engagement and Scope definition). The platform requires a structured, progressive stepper.

3. **Project Context Isolation & Safety:**  
   In offensive security tooling, a quick-switch dropdown in the top bar is an active operational risk. Accidental switching of projects mid-engagement can lead to payloads being executed against incorrect target environments (e.g., executing staging exploit payloads against production). Context switching must be deliberate and safely contained.

4. **Forensic Visibility into Autonomous Agents:**  
   Static card views and raw JSON accordion inspects fail to provide real-time assurance of agent actions. Operators require a live, streaming terminal experience (modeled after Claude Code and modern CLI terminals like Warp) that renders agent chain-of-thought reasoning, tool execution commands (`curl`, `nuclei`, `katana`), raw response snippets, and inline Human-in-the-Loop (HITL) approval gates.

---

## Decisions

### 1. Enterprise Light Theme Palette (OKLCH Tokens)
- **Decision:** Shift default theme to an Enterprise Light Theme grounded in the `codemax-ai` design specification.
- **Tokens:**
  - **Canvas Background:** Pure White `#ffffff` / Slate-50 `#f8fafc` (`oklch(1 0 0)` / `oklch(0.985 0 0)`).
  - **Surfaces & Cards:** `#ffffff` with 1px solid slate border `#e2e8f0` (`oklch(0.922 0 0)`).
  - **Brand Primary:** Enterprise Deep Sapphire Blue `#1e3a8a` / `#2563eb` (`oklch(0.3791 0.1378 265.52)`).
  - **Accent / In-Progress:** Amber-Orange `#ea580c` / `#d97706` (`oklch(0.7049 0.1867 47.6)`).
  - **Severity Badges:** High-contrast light pastel pills with dark semantic foregrounds (Critical: `#ffe4e6` / `#9f1239`; High: `#ffedd5` / `#9a3412`; Medium: `#fef3c7` / `#92400e`; Low: `#dbeafe` / `#1e40af`; Info: `#f1f5f9` / `#334155`).

### 2. Progressive 6-Phase Engagement Stepper
- **Decision:** Implement a horizontal progressive stepper pinned at the top of the workspace for all active engagements.
- **Workflow Order:**
  1. `Scope & RoE` (`/scope`) — Target boundaries, out-of-scope paths, legal sign-off.
  2. `Attack Surface` (`/discovery`) — FQDNs, open ports, endpoints, and technology stack.
  3. `OWASP WSTG Plan` (`/wstg`) — Standardized test matrix and testing catalog.
  4. `Multi-Agent DAG` (`/agents`) — Autonomous LangGraph orchestration and live streaming execution.
  5. `Findings & Retest` (`/findings`) — Vulnerability confirmation, CVSS 3.1 scoring, and cryptographic re-verification.
  6. `PTES Report` (`/reports`) — Formal executive and technical PDF deliverables.
- **State Semantics:** Steps display clear visual states: `Completed` (Green check), `Active` (Blue/Amber pulse), `Pending/Locked` (Muted gray). Operators can freely jump back to review completed steps without losing work.

### 3. Safe Project Isolation & Hierarchical Top Navigation
- **Decision:** Remove the top navigation quick-switch project dropdown and replace it with a hierarchical breadcrumb: `Projects / [Project Name]`.
- **Specification:**
  - `Projects` links directly to the `/projects` directory table.
  - To switch engagements, the operator must deliberately navigate to the Projects directory and select "Open Engagement".
  - The top bar displays read-only contextual security badges: `[ RoE: Strict Sandbox | In-Scope: 3 ]`, global agent activity status (`[ ⚡ Active: 1 ]`), and authenticated user details.

### 4. Dual-Aesthetic Streaming Agent Terminal (Claude Code Style)
- **Decision:** Implement an inset, high-contrast dark terminal viewport (`#0b0f19`) inside the clean light-mode `/agents` view.
- **Specification:**
  - Monospace font (`JetBrains Mono` / `Geist Mono`) with syntax-highlighted streaming output.
  - Distinct message types: `THOUGHT` (Reasoning bubble), `TOOL` (Executed CLI command + truncated output), `EVIDENCE` (Confirmed vulnerability signature), and `HITL` (Interactive approval prompt).
  - Inline Human-in-the-Loop decision gate: Renders `[ Approve ]`, `[ Skip ]`, and `[ Modify Payload ]` buttons directly in the log flow without modal popups.
  - Terminal toolbar: Auto-scroll toggle, search/filter (Thoughts/Tools/Errors), and one-click log export.

### 5. Collapsible Sidebar Rail
- **Decision:** Provide a one-click sidebar collapse mechanism (`[ ◀ ]`) to allow full-width expansion of the live streaming terminal and DAG graph during active penetration testing runs.

---

## Consequences
- **Positive:**
  - Modern, credible enterprise appearance meeting CISO, compliance auditor, and corporate client expectations.
  - Eliminates dangerous cross-project execution errors during live active testing.
  - Streamlines operator workflow by enforcing PTES methodology without locking users out of completed phases.
  - Vastly improves transparency and trust in AI agent operations through real-time streaming traces.
- **Negative / Trade-offs:**
  - Existing dark-mode Tailwind utility classes across all web components must be refactored to support the light design tokens.
  - The DAG execution view requires real-time streaming hooks (SSE/WebSocket) to drive the live terminal interface.

