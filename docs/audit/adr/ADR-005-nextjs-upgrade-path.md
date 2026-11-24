# ADR-005: Next.js Frontend Security & Upgrade Path

> **Document Identifier:** `ADR-005-NEXTJS-UPGRADE-PATH`  
> **Status:** PROPOSED  
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

A disciplined upgrade strategy is required to eliminate vulnerabilities while preserving React 18 stability and preventing frontend UI breakage.

---

## 2. Evaluation of Upgrade Paths

| Strategy | Target Version | Breaking Change Risk | React Compatibility | Advisory Coverage | Recommendation |
|---|---|:---:|:---:|---|:---:|
| **Option A (Smallest-Jump)** | `next@14.2.35` | **LOWEST** | Native React 18 (`^18.3.1`) | Resolves all immediate Server Action & App Router DoS/SSRF advisories; SVG RCE mitigated via config | **ACCEPTED** |
| **Option B (Minor Bump)** | `next@15.2.x` | **MODERATE** | Requires React 19 or compat flag | Requires async `cookies()`/`headers()` migration; fetch cache breaking changes | Deferred |
| **Option C (Major Bump)** | `next@16.4.6` | **HIGH** | React 19 mandatory | Complete frontend rewrite of custom middleware and route handlers | Deferred |

---

## 3. Decision

We adopt **Option A (Smallest-Jump)**:
1. Upgrade `next` from `14.2.18` to **`14.2.35`** in `apps/web/package.json`.
2. Harden `apps/web/next.config.js` with:
   ```javascript
   images: {
     dangerouslyAllowSVG: false, // Mitigates GHSA-2464-fhr4-w9xw
   }
   ```
3. Retain React 18 (`react@^18.3.1`, `react-dom@^18.3.1`).
4. Execute full UI regression battery across `/dashboard`, `/projects`, `/scans`, `/findings`, and `/audit-logs`.
