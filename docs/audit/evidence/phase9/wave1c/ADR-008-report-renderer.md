# ADR-008: Automated Pentest Report PDF Rendering Engine Selection

> **Status:** PROPOSED (Specification Phase — Pending User Approval)  
> **Date:** 2026-11-26  
> **Auditors / Authors:** Principal Software Architect, Senior Security QA Engineer  
> **Target Wave:** Phase 9 Wave 1c  

---

## 1. Context & Problem Statement

Pentesa requires an automated, deterministic reporting engine capable of compiling scan results, WSTG evaluations, and executive sign-offs into signed, high-fidelity PDF deliverables that strictly match the corporate report template specification (`docs/assets/Report Pentest (nama aplikasi).docx` / `.pdf`).

The engine must satisfy rigorous non-functional requirements:
1. **Container Isolation & Portability:** Must execute reliably across developer workstations (Windows/macOS) and production Linux Docker containers without complex OS-level desktop runtime dependencies.
2. **Resource Constraints:** Must comply with `DEFECT-INFRA-01` memory bounds (1024 MB container limit for `pentesa-api`).
3. **Subprocess & Concurrency Safety:** Zero risk of hanging headless daemons, orphan zombie processes (`DEFECT-RES-01`), or unhandled exceptions under concurrent generation (`PERF-02`).
4. **Visual & Geometric Fidelity:** Exact A4 page geometry ($210 \times 297\text{ mm}$), 25.4 mm (1.0 inch) margins, precise table column widths, and cell background shading (`#D9D9D9`, `#FFC000`).

---

## 2. Architecture Options Evaluation

| Evaluation Criteria | Option A: Native ReportLab Platypus (Current Engine) | Option B: HTML/CSS via WeasyPrint | Option C: python-docx + Headless LibreOffice Subprocess |
|---|---|---|---|
| **Underlying Technology** | Pure Python programmatic flowable document builder | HTML5 + CSS Paged Media converted via Cairo/Pango | OpenXML docx builder + `soffice --headless` conversion |
| **Container Footprint** | **Zero additional bloat** (`reportlab 5.1.1` already installed in production image) | **Heavy** (requires `libcairo2`, `libpango-1.0-0`, `libgdk-pixbuf2.0-0`, `shared-mime-info`) | **Severe** (>500 MB container bloat for LibreOffice suite and Java/X11 deps) |
| **OS Portability** | **100% portable** across Windows host, macOS, and Linux Docker | **Poor on Windows**; requires external GTK+3 runtime and DLL path configuration | **Complex**; requires platform-specific `soffice` binary paths and font caches |
| **Execution Speed** | **Fast** (<0.5 seconds for 10-page report) | **Moderate** (~2.0–4.0 seconds for CSS reflow) | **Slow** (4.0–8.0 seconds due to LibreOffice JVM/IPC startup overhead) |
| **Peak RAM Consumption** | **Minimal** (<40 MB peak memory during build) | **High** (120–250 MB for DOM tree layout) | **Very High** (350–700 MB per conversion process; risks container OOM) |
| **Process Lifecycle Safety** | **In-Process Python execution**; zero subprocesses or zombie risks | **In-Process Python execution**; no subprocesses | **High Risk**; spawns background LibreOffice subprocess; prone to hangs on slow IO |
| **Layout & Color Fidelity** | **100% conformant** with `template_spec.yaml` (proven via prototype) | Good, but complex CSS paged media margin box quirks | 100% native DOCX; PDF export identical to Word |

---

## 3. Empirical Prototype Demonstration

A throwaway prototype was implemented in `.scratch/prototype_template.py` and executed against the target template metrics:
- **Output Artifact:** `.scratch/prototype_template_reportlab.pdf` (178,039 bytes)
- **Execution Time:** 0.38 seconds
- **MediaBox Coordinates:** `[0, 0, 595.28, 841.89]` (exact standard ISO A4)
- **Margin Enforcement:** Exactly 25.40 mm (72.0 pt) on Top, Bottom, Left, and Right
- **Table Structures:**
  - Table 1 (Dates): 2 rows, 2 cols, 0.5 pt solid borders.
  - Table 2 (Findings Summary): 5 cols, `#D9D9D9` header shading, `#FFC000` amber severity fill.
  - Table 3 (Sign-Off Approval): 4 cols, dynamic personnel mapping, signature lines.
  - Table 4 (Detail Vulnerability): `#D9D9D9` centered banner + CVSS v4.0 vector strings.

---

## 4. Architectural Decision

**Decision:** **Adopt Option A (Native ReportLab Platypus Engine)**.

### Rationale:
1. `reportlab 5.1.1` is already vetted, hardened, and deployed inside `pentesa-api` and `pentesa-worker`.
2. ReportLab eliminates all external C-runtime and headless office daemon dependencies, guaranteeing zero platform drift between Windows development workstations and production Linux containers.
3. Memory and CPU consumption are bounded well within the 1024 MB container limits established in `DEFECT-INFRA-01`.
4. Visual fidelity, table widths, background colors, and typography match the reference DOCX/PDF template with sub-millimeter precision.

---

## 5. Consequences

### Positive:
- Zero container image rebuilding or Dockerfile modification required for new system dependencies.
- Sub-second report compilation speed under concurrent load.
- Deterministic, tamper-evident SHA-256 hash generation for generated deliverables.

### Negative / Trade-offs:
- Document layouts are defined programmatically via Python Platypus flowables (`Table`, `ParagraphStyle`, `SimpleDocTemplate`) rather than HTML/CSS markup.
- Adding new visual components requires updating ReportLab flowable helper classes rather than editing HTML templates.
