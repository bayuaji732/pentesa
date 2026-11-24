# ADR-005: Next.js Frontend Security & Upgrade Path

> **Document Identifier:** `ADR-005-NEXTJS-UPGRADE-PATH`  
> **Status:** ACCEPTED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** Frontend & Security Engineering Team  
> **Reference Baseline:** `docs/audit/evidence/phase8/nextjs_advisories.md`, `DEFECT-DEP-01`

---

## 1. Context & Problem Statement

`apps/web/package.json` specifies `next: "14.2.18"`.
An empirical `npm audit --json` scan identified **35 security advisories** affecting `next@14.2.18` in the npm registry, including:
- High Severity Denial of Service in Server Actions (`GHSA-7m27-7ghc-44w9`, `GHSA-p3m5-59mp-jv5r`)
- Server Components DoS (`GHSA-mwv6-3258-q52c`, `GHSA-5j59-xgg2-r9c4`)
- Image Optimizer SVG Remote Code Execution (`GHSA-2464-fhr4-w9xw`)
- Cross-client response injection in self-hosted deployments (`GHSA-pc58-hwjq-p385`)

Empirical registry analysis indicates that Next.js 14.x ceased receiving security backports after `14.2.35` (published 2025-12-11), leaving three late-2026 advisories without 14.x patches. A disciplined upgrade strategy is required to eliminate vulnerabilities while preserving React 18 stability and preventing frontend UI breakage.

---

## 2. Evaluation of Upgrade Paths

| Strategy | Target Version | Breaking Change Risk | React Compatibility | Advisory Coverage | Recommendation |
|---|---|:---:|:---:|---|:---:|
| **Option A (Smallest-Jump)** | `next@14.2.35` | **LOWEST** | Native React 18 (`^18.3.1`) | Resolves all 32 upstream 14.x advisories; SVG RCE mitigated via `dangerouslyAllowSVG: false`; Server Actions unused | **ACCEPTED for Wave 0/1** |
| **Option B (Minor Bump)** | `next@15.2.x` | **MODERATE** | Requires React 19 or compat flag | Requires async `cookies()`/`headers()` migration; fetch cache breaking changes; still lacks SVG RCE fix | Rejected |
| **Option C (Minimum Major for 100% Fixes)** | `next@16.4.6` | **HIGH** | React 19 mandatory | Upstream-closes 100% (35/35) of advisories without relying on config mitigations | **ACCEPTED for Post-Audit Roadmap** |

---

## 3. Decision

1. **Immediate Maintenance Path (Wave 0/1):**
   - Adopt **Option A (Smallest-Jump)**: bump `next` from `14.2.18` to **`14.2.35`** in `apps/web/package.json`.
   - Explicitly harden `apps/web/next.config.js`:
     ```javascript
     images: {
       dangerouslyAllowSVG: false, // Mitigates GHSA-2464-fhr4-w9xw
     }
     ```
   - Retain React 18 (`react@^18.3.1`, `react-dom@^18.3.1`).
   - Execute full UI regression battery across `/dashboard`, `/projects`, `/scans`, `/findings`, and `/audit-logs`.

2. **Long-Term Full Upstream Resolution (Post-Audit Roadmap):**
   - Note that because 14.x has received no patches since December 2025, 14.x cannot officially close all 35 CVEs on its own.
   - The minimum major version required to achieve 100% upstream code fixes across all 35 advisories is **`next@16.4.6`** (alongside React 19). This major migration is scheduled as post-audit engineering work under Wave 3/4.
