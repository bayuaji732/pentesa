# Pentesa — Enterprise UI/UX Redesign & Progressive Lifecycle Specification (v3.0)

> **Document Identifier:** PENTESA-UIUX-SPEC-V3.0  
> **Status:** Approved for Implementation (Supersedes v2.0 Dark-Mode Spec)  
> **Design Foundation:** Enterprise Light Theme (OKLCH Tokens from `codemax-ai-FE-BE-Core`), Progressive PTES Stepper, Inset Dark Live Terminal  
> **Frontend Stack:** Next.js 14 App Router + React 18 + Tailwind CSS + Lucide Icons  
> **Related Decisions:** [ADR-009: Transition to Enterprise Light Theme, Progressive Lifecycle Navigation, and Streaming Agent Terminal](decisions/ADR-009-enterprise-light-theme-and-lifecycle-navigation.md)

---

## Table of Contents
1. [Executive Summary & Core Principles](#1-executive-summary--core-principles)
2. [Design Tokens & Color Architecture](#2-design-tokens--color-architecture)
3. [Global Top Navigation & Project Isolation](#3-global-top-navigation--project-isolation)
4. [The 6-Phase Progressive Engagement Stepper](#4-the-6-phase-progressive-engagement-stepper)
5. [Real-Time Streaming Agent Terminal (Claude Code Model)](#5-real-time-streaming-agent-terminal-claude-code-model)
6. [Component Specifications & Severity Matrix](#6-component-specifications--severity-matrix)
7. [Screen Wireframes & Layout Blueprints](#7-screen-wireframes--layout-blueprints)
8. [Phased Implementation Roadmap](#8-phased-implementation-roadmap)

---

## 1. Executive Summary & Core Principles

Pentesa is an enterprise-grade autonomous penetration testing platform for security engineers, AppSec architects, and compliance auditors. The previous v2.0 interface utilized an ultra-dark cyberpunk aesthetic (`#030712`) that felt like an arcade hacking tool. 

The v3.0 redesign transforms Pentesa into a **credible, forensic-grade enterprise suite**:

1. **Enterprise Clarity First:** High-readability light canvas (`#ffffff` / `#f8fafc`) with authoritative Sapphire Blue (`#1e3a8a`) brand accents and crisp 1px neutral slate borders (`#e2e8f0`).
2. **Methodology-Driven Navigation:** Unifies fragmented menus into a sequential 6-phase **PTES (Penetration Testing Execution Standard)** lifecycle stepper.
3. **Strict Project Isolation:** Eliminates hazardous quick-switch dropdowns in favor of deliberate breadcrumb navigation (`Projects / [Project Name]`) to prevent accidental testing against incorrect scopes.
4. **Transparent Autonomous Agents:** Replaces static tables and JSON dumps with an interactive, streaming terminal (modeled after Claude Code and modern CLI terminals) with inline Human-in-the-Loop (HITL) approval gates.

---

## 2. Design Tokens & Color Architecture

Grounded directly in the modern OKLCH color space extracted from the reference repository (`C:\Users\User2\Documents\work\dev\codemax-ai-FE-BE-Core\bth-casemix-fe`):

### 2.1 CSS Variable Tokens (`apps/web/src/app/globals.css`)

```css
:root {
  /* Canvas & Base Layers */
  --background: oklch(1 0 0);               /* Pure White #ffffff */
  --foreground: oklch(0.145 0 0);           /* Slate-900 #0f172a */
  --muted-background: oklch(0.985 0 0);     /* Slate-50 #f8fafc */

  /* Card Surfaces & Elevation */
  --card: oklch(1 0 0);                     /* #ffffff */
  --card-foreground: oklch(0.145 0 0);      /* #0f172a */
  --popover: oklch(1 0 0);                  /* #ffffff */
  --popover-foreground: oklch(0.145 0 0);   /* #0f172a */

  /* Brand Primary: Enterprise Sapphire Blue */
  --primary: oklch(0.3791 0.1378 265.52);   /* Deep Royal Sapphire #1e3a8a */
  --primary-foreground: oklch(0.985 0 0);  /* Clean White #ffffff */

  /* Brand Accent: In-Progress & Active Stepper */
  --accent: oklch(0.7049 0.1867 47.6);      /* Warm Amber/Orange #ea580c */
  --accent-foreground: oklch(0.985 0 0);   /* Clean White */

  /* Neutral Borders & Dividers */
  --border: oklch(0.922 0 0);               /* Slate-200 #e2e8f0 */
  --input: oklch(0.922 0 0);                /* Slate-200 #e2e8f0 */
  --ring: oklch(0.3791 0.1378 265.52);      /* Focus Ring matching Primary */

  /* Dark Terminal Inset (High-Contrast Cockpit inside Light Shell) */
  --terminal-bg: #0b0f19;                   /* Deep Void Slate */
  --terminal-fg: #f8fafc;                   /* Monospace White */
  --terminal-border: #1e293b;               /* Slate-800 */
  --terminal-prompt: #38bdf8;               /* Sky Blue 400 */
  --terminal-thought: #93c5fd;              /* Indigo 300 */
  --terminal-evidence: #4ade80;             /* Emerald 400 */
}
```

### 2.2 Severity Matrix Tokens (Light Mode Contrast)

| Severity | Badge Background | Badge Text | Border | Indicator Dot |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | `#FFE4E6` (`rose-100`) | `#9F1239` (`rose-800`) | `#FECDD3` (`rose-200`) | `#E11D48` (`rose-600`) |
| **HIGH** | `#FFEDD5` (`orange-100`) | `#9A3412` (`orange-800`) | `#FED7AA` (`orange-200`) | `#EA580C` (`orange-600`) |
| **MEDIUM** | `#FEF3C7` (`amber-100`) | `#92400E` (`amber-800`) | `#FDE68A` (`amber-200`) | `#D97706` (`amber-600`) |
| **LOW** | `#DBEAFE` (`blue-100`) | `#1E40AF` (`blue-800`) | `#BFDBFE` (`blue-200`) | `#2563EB` (`blue-600`) |
| **INFO** | `#F1F5F9` (`slate-100`) | `#334155` (`slate-700`) | `#E2E8F0` (`slate-200`) | `#64748B` (`slate-500`) |

---

## 3. Global Top Navigation & Project Isolation

### 3.1 Architectural Layout

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [🛡️ PENTESA]  /  Projects  /  DVWA Assessment   [ 🛡️ RoE Active: In-Scope ]     [⚡ Agents: Idle]  [👤 Operator]│
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Elements & Behaviors
1. **Brand Anchor:** `PENTESA` logo with a subtle primary sapphire badge. Clicking redirects to the default Project Directory (`/projects`).
2. **Hierarchical Breadcrumbs:**
   - `Projects`: Clickable link navigating back to `/projects`.
   - `/`: Neutral divider glyph (`slate-300`).
   - `[Active Project Name]` (e.g. `DVWA Assessment`): Static bold text representing the current security boundary.
3. **No Quick-Switch Dropdown:** Context-switching from the top bar is explicitly prohibited. The operator must navigate to `/projects` and select an engagement. This eliminates inadvertent target switching during active exploit retests.
4. **RoE Context Badge:**
   - Pill: `[ 🛡️ RoE: Active | In-Scope: 3 Targets ]`.
   - Tooltip: Displays authorization window, target CIDRs, rate limit rules (e.g., `50 req/sec`), and test window expiry.
5. **Global System Pulse:**
   - `[ ⚡ Agents: Idle ]` or `[ ⚡ 2 Agents Active (42 req/s) ]` with an animated pulse indicator.
6. **User Identity:**
   - Displays real authenticated operator details with role tag (`Security Engineer`), settings shortcut, and `Sign Out`.

---

## 4. The 6-Phase Progressive Engagement Stepper

### 4.1 Stepper Architecture

Pinned directly beneath the project title on all engagement pages:

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  ( 1. Scope & RoE ) ──> ( 2. Surface ) ──> ( 3. WSTG Plan ) ──> [ 4. Agent DAG ] ──> ( 5. Findings ) ──> ( 6. PTES Report )
│        ✓ DONE                 ✓ DONE             ✓ READY            ● RUNNING             4 Detected           Draft        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Phase Lifecycle & Path Mapping

| Phase | Route | Name | Purpose | Unlocking Prerequisite |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `/scope` | **Scope & RoE** | Seed URLs, CIDR bounds, out-of-scope paths, legal sign-off. | Always available upon project creation. |
| **2** | `/discovery` | **Attack Surface** | Subdomains, ports, technology fingerprinting, crawled endpoints. | Target seeds configured in Phase 1. |
| **3** | `/wstg` | **OWASP WSTG Plan** | Test matrix generation, test case selection, tool mapping. | At least 1 in-scope endpoint cataloged. |
| **4** | `/agents` | **Multi-Agent DAG** | Autonomous LangGraph execution, live streaming terminal, HITL gates. | WSTG plan validated and RoE signed off. |
| **5** | `/findings` | **Findings & Retest** | Confirmed vulnerabilities, CVSS 3.1 scoring, cryptographic chain re-verify. | At least 1 scan execution completed. |
| **6** | `/reports` | **PTES Report** | Executive summary, technical disclosures, PDF export. | Completed assessment review. |

### 4.3 Phase State Machine
- **`COMPLETED` (`✓ Green`):** Phase is done. Clicking jumps to inspect the phase.
- **`ACTIVE` (`● Sapphire / Amber`):** Current working phase with the primary call to action (e.g., `Launch DAG →`).
- **`PENDING / LOCKED` (`○ Muted Gray`):** Cannot execute until upstream prerequisites are satisfied. Hovering displays the missing prerequisite (e.g., *"Requires Scope approval before launching agents"*).

---

## 5. Real-Time Streaming Agent Terminal (Claude Code Model)

### 5.1 Terminal Design Concept
In offensive security, agents cannot be black boxes. The live terminal displays real-time agent chain-of-thought, commands executed, tool outputs, and interactive approval gates.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  LIVE EXECUTION STREAM  ·  [AGT-02] Input Validation Specialist                                         │
│  Target: http://localhost:8080/vulnerabilities/fi/?page=  |  Model: gemini-2.5-pro  |  Status: RUNNING  │
│  [ Filter: All ▾ ]  [ Auto-Scroll: ON ]  [ 📋 Copy Session Logs ]  [ 🛑 Kill Agent ]                   │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                         │
│  11:45:02.110  THOUGHT  Agent received target task: WSTG-INJV-04 (Path Traversal Testing)              │
│                         Analyzing HTTP GET parameters from Recon phase...                               │
│                         Identified sensitive parameter: 'page' on /vulnerabilities/fi/                  │
│                                                                                                         │
│  11:45:02.450  TOOL     curl_http_probe                                                                 │
│                         ┌─────────────────────────────────────────────────────────────────────────────┐ │
│                         │ $ curl -s -X GET "http://target:8080/vulnerabilities/fi/?page=../../passwd" │ │
│                         │ > HTTP/1.1 200 OK (842 bytes, 18ms)                                         │ │
│                         │ > Response Body: root:x:0:0:root:/root:/bin/bash                            │ │
│                         └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                                         │
│  11:45:02.820  EVIDENCE Validated arbitrary file disclosure against /etc/passwd.                        │
│                         Pattern match: Unix passwd entry signature verified.                            │
│                         Confidence: 98% (Confirmed Vulnerable)                                          │
│                                                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 🛡️ HUMAN-IN-THE-LOOP (HITL) APPROVAL REQUIRED                                                     │  │
│  │ Rule: WSTG-INJV-04 recommends verifying directory traversal with null-byte injection.             │  │
│  │ Target: http://localhost:8080/vulnerabilities/fi/?page=../../../../etc/shadow%00                  │  │
│  │                                                                                                   │  │
│  │ [ ✓ Approve Probe ]          [ ✕ Skip This Vector ]          [ ⚙️ Edit Custom Payload ]            │  │
│  └───────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                         │
│  11:45:03.010  STREAM   ▋ Waiting for operator input or autonomous continuation...                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Structured Message Types
1. **`THOUGHT` (Color: `#93c5fd` Slate/Blue):** Agent internal reasoning and hypothesis formulation.
2. **`TOOL_CALL` (Color: `#38bdf8` Sky Blue with monospace border):** Exact CLI command line or HTTP request dispatched to the sandbox runner.
3. **`TOOL_OUTPUT` (Color: `#94a3b8` Muted Slate):** Structured response snippet, status code, headers, and body snippet.
4. **`EVIDENCE` (Color: `#4ade80` Emerald):** Confirmed vulnerability pattern match and confidence calculation.
5. **`HITL_GATE` (Color: `#ea580c` Amber Callout Box):** Mandatory operator decision gate with inline `[ Approve ]`, `[ Skip ]`, and `[ Edit Payload ]` buttons.

---

## 6. Component Specifications & Severity Matrix

### 6.1 Buttons & Interactive Controls
- **Primary Action:** Deep Sapphire background (`#1e3a8a`), white text, 6px rounded corners (`rounded-md`), subtle shadow (`shadow-xs`), hover: `#1d4ed8`.
- **Secondary Action:** Pure white background, 1px slate border (`#e2e8f0`), slate-800 text, hover: `#f8fafc`.
- **Destructive / Abort:** Rose background (`#e11d48`), white text, hover: `#be123c`.

### 6.2 Data Tables & Finding Grids
- **Header:** Slate-50 background (`#f8fafc`), 1px bottom border (`#e2e8f0`), uppercase 11px font (`font-semibold text-slate-500`).
- **Rows:** White background, 1px bottom border, hover: `#f1f5f9` with subtle transition.
- **Monospace Cells:** Target URLs, CVSS vector strings, hashes, and tool names rendered in `font-mono text-xs text-slate-700`.

---

## 7. Screen Wireframes & Layout Blueprints

### 7.1 Workspace Layout with Collapsed/Expanded Sidebar

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [🛡️ PENTESA]  /  Projects  /  DVWA Assessment   [ 🛡️ RoE: Active ]                [⚡ Active: 1]  [👤 Operator] │
├──────────────┬─────────────────────────────────────────────────────────────────────────────────────────┤
│ LIFECYCLE    │  DVWA Assessment · Web Application Penetration Test                                     │
│              │                                                                                         │
│ [✓] 1. Scope │  ( 1. Scope ) ──> ( 2. Surface ) ──> ( 3. WSTG ) ──> [ 4. AGENTS ] ──> ( 5. Findings )  │
│ [✓] 2. Recon │                                                                                         │
│ [✓] 3. WSTG  ├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [●] 4. Agents│                                                                                         │
│ [ ] 5. Issues│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│ [ ] 6. Report│  │                                                                                   │  │
│              │  │                       LIVE AGENT STREAM TERMINAL                                  │  │
│ GOVERNANCE   │  │                       (Dark high-contrast viewport)                               │  │
│              │  │                                                                                   │  │
│ Dashboard    │  │                                                                                   │  │
│ Audit Logs   │  └───────────────────────────────────────────────────────────────────────────────────┘  │
│ [◀ Collapse] │                                                                                         │
└──────────────┴─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Phased Implementation Roadmap

To maintain operational integrity and avoid regressions:

### Phase 8.1: Design System Foundations & Global Navigation
- Update `apps/web/src/app/globals.css` with the OKLCH enterprise light tokens.
- Refactor `TopNav.tsx` to adopt the hierarchical breadcrumb (`Projects / [Name]`), remove the raw target link, and add RoE status pills.
- Refactor `Sidebar.tsx` into the 3-tier structure (Lifecycle, Governance, System) with one-click rail collapse.

### Phase 8.2: Engagement Stepper Component
- Build reusable `EngagementStepper.tsx` component mounted at the top of all project views.
- Integrate active state detection based on current pathname and project completion flags.

### Phase 8.3: Live Agent Streaming Terminal
- Build `AgentTerminal.tsx` with monospace streaming window, auto-scroll, log filter chips, and inline HITL gate actions.
- Connect to existing `/api/agents` and SSE task feeds.

### Phase 8.4: Page-by-Page Light Theme Polish
- Apply light tokens and high-contrast severity pills across:
  - `/projects` (Project directory table)
  - `/scope` (Scope boundary editor)
  - `/discovery` (Attack surface grid)
  - `/wstg` (OWASP test matrix)
  - `/findings` (Vulnerability detail and cryptographic chain retest view)
  - `/reports` (PTES report preview and download)

