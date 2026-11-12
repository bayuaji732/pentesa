# ADR-010: Guided Lifecycle Gating, Zero-Sidebar Layout, Dual SOC Clock, and Engagement Architecture

- **Status:** Approved
- **Date:** 2026-11-12
- **Context:** Pentesa Enterprise Autonomous Penetration Testing Platform (UI/UX Evolution)
- **Supersedes/Extends:** [ADR-009: Transition to Enterprise Light Theme, Progressive Lifecycle Navigation, and Streaming Agent Terminal](ADR-009-enterprise-light-theme-and-lifecycle-navigation.md)
- **Document Identifier:** PENTESA-ADR-010

---

## 1. Context and Problem Statement

Following the completion of Phases 1–4 of the Enterprise UI/UX Redesign, several structural and workflow discrepancies were identified:

1. **Navigation Duplication & Screen Real Estate:** A persistent left sidebar duplicated the 6-step lifecycle stepper (`EngagementStepper`), occupying 256px of horizontal space on dense data pages (Live Terminal, WSTG Matrix, Evidence Drawer) and permitting out-of-order phase skipping.
2. **Dashboard Disconnection & Unrestricted Launch:** The root `/` dashboard contained a "Launch Multi-Agent Assessment" button, allowing operators to trigger autonomous AI agent swarms before defining in-scope seeds, enumerating attack surfaces, or approving WSTG test plans.
3. **Out-of-Order Lifecycle Navigation:** Users could arbitrarily jump from Step 1 to Step 5 or 6 without fulfilling upstream prerequisites (e.g., viewing reports before running scans).
4. **Implementation Jargon in Top Navigation:** The top navbar prominently featured `"LAYER 1 & 2 SCOPE GUARD ENFORCED"`, which leaks internal architecture naming and provides zero operational utility.
5. **Amateur Browser Notification Popups:** Native blocking browser dialogs (`window.alert()` and `window.confirm()`) were utilized for engagement creation, deletions, and clipboard feedback.
6. **Redundant "Switch to Project" Action:** The project directory required a distinct "Switch to Project" button that left the user stranded on the directory rather than opening the engagement.
7. **Inconsistent Terminology:** Mixing "Project", "Engagement", "Assessment", and "Target" degraded platform credibility.

---

## 2. Decision Drivers

- **PTES (Penetration Testing Execution Standard) & CREST Compliance:** Penetration testing is an inherently linear, legally governed lifecycle. Execution must strictly depend on verified Rules of Engagement (RoE) and defined scope boundaries.
- **SOC Operator Ergonomics:** Maximizing horizontal canvas space for high-density terminal feeds, 106-test matrices, and side-by-side evidence inspection.
- **Forensic Time Synchronization:** Correlating UTC timestamps from server logs and Merkle audit chains against local operator time (e.g. WIB / UTC+7).
- **Enterprise Grade UX:** Zero native browser dialogs, frictionless single-click navigation, and consistent cybersecurity industry terminology.

---

## 3. Decisions & Architectural Specifications

### 3.1 Decision 1: Header-Driven Workspace Layout (Retire Redundant Left Sidebar)
- **Decision:** Eliminate the persistent left navigation sidebar for all project/engagement screens.
- **Rationale:** The horizontal 6-phase `EngagementStepper` is the authoritative navigation mechanism for engagements. Removing the sidebar recovers 256px of width, giving the Terminal, WSTG table, and Evidence drawer maximum horizontal canvas.
- **Workspace Navigation:** Top-level global navigation (Engagements Directory, Audit Logs, Settings) is managed directly via the TopNav breadcrumb and global header shortcuts.

### 3.2 Decision 2: Strict Prerequisite Lifecycle Gating & Linear "Continue" Action Bars
- **Decision:** Enforce hard linear gating across all 6 phases. Users cannot skip ahead to locked phases.
- **Prerequisite Rules:**
  - **Phase 1 (Scope & RoE):** Unlocked upon engagement creation. Prerequisite to advance: at least 1 in-scope target rule defined.
  - **Phase 2 (Attack Surface):** Locked until Phase 1 valid. Prerequisite to advance: at least 1 endpoint enumerated or seed confirmed.
  - **Phase 3 (OWASP WSTG Plan):** Locked until Phase 2 valid. Prerequisite to advance: Operator reviews and approves matrix applicability.
  - **Phase 4 (Multi-Agent DAG):** Locked until Phase 3 approved. **This is the ONLY location where autonomous scans can be launched.**
  - **Phase 5 (Findings & Retest):** Locked until Phase 4 execution completes at least 1 pass.
  - **Phase 6 (PTES Report):** Locked until Phase 5 triage review completed.
- **Footer Action Bars:** Every step page includes a persistent, standardized bottom navigation dock:
  - Left: `[ ← Back to Step X ]`
  - Right: `[ Save & Continue to Step Y → ]` or `[ Proceed to Step Y → ]` (when optional).

### 3.3 Decision 3: Engagement Directory as Root (`/`) or Primary Workspace
- **Decision:** Re-architect `/` so that the primary operational dashboard is the **Engagements Directory** (or an executive portfolio summary with direct engagement cards).
- **Behavior:** Clicking an engagement immediately opens its active workspace at its current unlocked step.
- **Elimination of Direct Launch:** The standalone `/` dashboard no longer contains a direct "Launch Assessment" button.

### 3.4 Decision 4: TopNav Dual Real-Time Clock (UTC & Local Time / WIB)
- **Decision:** Replace the static `"LAYER 1 & 2 SCOPE GUARD ENFORCED"` badge with a synchronized dual-time SOC clock:
  - Form: `[ 🕒 09:30:15 UTC  ·  16:30:15 WIB ]`
  - Automatically detects the user's local timezone (via browser `Intl.DateTimeFormat`) while preserving the authoritative UTC reference.
  - Retains subtle RoE validity status indicator on the active project breadcrumb.

### 3.5 Decision 5: Brand Identity Click Navigation
- **Decision:** Clicking the top-left `PENTESA` logo/shield redirects directly to the **Engagements Directory** (`/projects`), establishing the directory as the foundational workspace anchor.

### 3.6 Decision 6: In-App Toast & Modal System (Zero Browser Alerts)
- **Decision:** Completely eliminate all native `alert()` and `confirm()` invocations.
- **Replacement:**
  - **Toast Notifications:** Lightweight, animated in-app toast stack in the upper-right corner for success, error, and clipboard notifications.
  - **Confirmation Dialogs:** Accessible, stylized modal overlays for high-impact actions (e.g., deleting an engagement, aborting an active scan).

### 3.7 Decision 7: Elimination of "Switch to Project"
- **Decision:** Remove the redundant "Switch to Project" button. The entire engagement card/row in the directory is clickable and immediately opens the engagement's active lifecycle step.

### 3.8 Decision 8: Unified Terminology Standard — "Engagement"
- **Decision:** Standardize all user-facing terminology on **"Engagement"** (plural: **"Engagements"**), aligning with PTES, CREST, and enterprise pentest platforms.
- **Standard Hierarchy:**
  - **Engagement:** Time-bounded, legally authorized penetration testing contract (e.g. *Q4 DVWA Security Assessment*).
  - **Scope & Targets:** Authorized target perimeter (domains, CIDRs, API endpoints).
  - **Assessment:** Technical testing activity (OWASP WSTG matrix & Multi-Agent DAG execution).
  - **Deliverable:** Cryptographically sealed PTES Report artifact.

---

## 4. Consequences & Impact

### Positive:
- **Maximum Screen Real Estate:** 100% full-width viewports for complex security tools.
- **Bulletproof Operational Integrity:** Prevents reckless out-of-order scanning without verified scope and approved WSTG test plans.
- **Enterprise Credibility:** Clean SOC dual-time clock, polished in-app toasts, and authoritative PTES engagement terminology.

### Negative / Mitigations:
- **Navigation Adaptation:** Users accustomed to clicking the left sidebar will now use the top stepper. *Mitigation:* The 6-step stepper is prominently pinned at the top of all engagement views.

