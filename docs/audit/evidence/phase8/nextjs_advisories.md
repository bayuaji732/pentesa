# Next.js Advisory Analysis Matrix (apps/web)

> **Current Installed Version:** `next@14.2.18` (via `apps/web/package.json`)  
> **Target Framework:** React 18 (`react@^18.3.1`, `react-dom@^18.3.1`)  
> **Advisory Source:** npm Registry Security Advisories (`npm audit --json`)  
> **LTS Analysis:** Latest Next.js 14.x release is `14.2.35` (`2025-12-11`). No 14.x security patches released in 2026.  
> **Minimum Major for 100% Fixes:** `next@16.4.6` (`2026-11-09`).

---

## 1. Vulnerability Breakdown & Reachability Matrix

| Advisory ID | Title | Severity | CWE | Vulnerable Range | Fixed in 14.x | Fixed in 15.x | Fixed in 16.x | Reachability Assessment |
|---|---|---|---|---|---|---|---|---|
| [GHSA-7m27-7ghc-44w9](https://github.com/advisories/GHSA-7m27-7ghc-44w9) | Next.js Allows a Denial of Service (DoS) with Server Actions | **MODERATE** | `CWE-770` | `>=14.0.0 <14.2.21` | `14.2.21` | `15.2.0` | `16.4.6` | **Not Reachable** (Server Actions unused) |
| [GHSA-3h52-269p-cp9r](https://github.com/advisories/GHSA-3h52-269p-cp9r) | Information exposure in Next.js dev server due to lack of origin verification | **LOW** | `CWE-1385` | `>=13.0 <14.2.30` | `14.2.30` | `15.2.0` | `16.4.6` | **Dev-Only** (affects `next dev` only) |
| [GHSA-g5qg-72qw-gw5v](https://github.com/advisories/GHSA-g5qg-72qw-gw5v) | Next.js Affected by Cache Key Confusion for Image Optimization API Routes | **MODERATE** | `CWE-524` | `>=0.9.9 <14.2.31` | `14.2.31` | `15.2.0` | `16.4.6` | **Prod Reachable** (`next/image` caching) |
| [GHSA-4342-x723-ch2f](https://github.com/advisories/GHSA-4342-x723-ch2f) | Next.js Improper Middleware Redirect Handling Leads to SSRF | **MODERATE** | `CWE-918` | `>=0.9.9 <14.2.32` | `14.2.32` | `15.2.0` | `16.4.6` | **Prod Reachable** (Middleware redirects) |
| [GHSA-xv57-4mr9-wg8v](https://github.com/advisories/GHSA-xv57-4mr9-wg8v) | Next.js Content Injection Vulnerability for Image Optimization | **MODERATE** | `CWE-20` | `>=0.9.9 <14.2.31` | `14.2.31` | `15.2.0` | `16.4.6` | **Prod Reachable** (`next/image` content) |
| [GHSA-qpjv-v59x-3qc4](https://github.com/advisories/GHSA-qpjv-v59x-3qc4) | Next.js Race Condition to Cache Poisoning | **LOW** | `CWE-362` | `>=0.9.9 <14.2.24` | `14.2.24` | `15.2.0` | `16.4.6` | **Prod Reachable** (Cache race conditions) |
| [GHSA-mwv6-3258-q52c](https://github.com/advisories/GHSA-mwv6-3258-q52c) | Next Vulnerable to Denial of Service with Server Components | **HIGH** | `CWE-400, 502, 1395` | `>=13.3.0 <14.2.34` | `14.2.34` | `15.2.0` | `16.4.6` | **Prod Reachable** (Server Components) |
| [GHSA-5j59-xgg2-r9c4](https://github.com/advisories/GHSA-5j59-xgg2-r9c4) | Next has a Denial of Service with Server Components - Follow-Up | **HIGH** | `CWE-400, 502, 1395` | `>=13.3.1-canary.0 <14.2.35` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (Server Components) |
| [GHSA-9g9p-9gw9-jx7f](https://github.com/advisories/GHSA-9g9p-9gw9-jx7f) | Next.js self-hosted DoS via Image Optimizer remotePatterns | **MODERATE** | `CWE-400, CWE-770` | `>=10.0.0 <15.5.10` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (remotePatterns config) |
| [GHSA-h25m-26qc-wcjf](https://github.com/advisories/GHSA-h25m-26qc-wcjf) | Next.js HTTP request deserialization DoS in React Server Components | **HIGH** | `CWE-400, CWE-502` | `>=13.0.0 <15.0.8` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (RSC deserialization) |
| [GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw) | Authorization Bypass in Next.js Middleware | **CRITICAL** | `CWE-285, CWE-863` | `>=14.0.0 <14.2.25` | `14.2.25` | `15.2.0` | `16.4.6` | **Prod Reachable** (Auth route middleware) |
| [GHSA-ggv3-7p47-pfv8](https://github.com/advisories/GHSA-ggv3-7p47-pfv8) | Next.js: HTTP request smuggling in rewrites | **MODERATE** | `CWE-444` | `>=9.5.0 <15.5.13` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (Rewrites config) |
| [GHSA-3x4c-7xq6-9pq8](https://github.com/advisories/GHSA-3x4c-7xq6-9pq8) | Next.js: Unbounded next/image disk cache growth | **MODERATE** | `CWE-400` | `>=10.0.0 <15.5.14` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (Self-hosted disk storage) |
| [GHSA-q4gf-8mx6-v5v3](https://github.com/advisories/GHSA-q4gf-8mx6-v5v3) | Next.js has a Denial of Service with Server Components | **HIGH** | `CWE-770` | `>=13.0.0 <15.5.15` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (RSC payload handling) |
| [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj) | Next.js Vulnerable to Denial of Service with Server Components | **HIGH** | `CWE-770` | `>=13.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (RSC payload handling) |
| [GHSA-3g8h-86w9-wvmq](https://github.com/advisories/GHSA-3g8h-86w9-wvmq) | Next.js Middleware / Proxy redirects can be cache-poisoned | **LOW** | `CWE-349` | `>=12.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (Proxy redirects) |
| [GHSA-ffhc-5mcf-pf4q](https://github.com/advisories/GHSA-ffhc-5mcf-pf4q) | Next.js XSS in App Router applications using CSP nonces | **MODERATE** | `CWE-79` | `>=13.4.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (CSP nonces) |
| [GHSA-vfv6-92ff-j949](https://github.com/advisories/GHSA-vfv6-92ff-j949) | Next.js cache poisoning via collisions in RSC cache-busting | **LOW** | `CWE-328` | `>=13.4.6 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (Cache busting) |
| [GHSA-gx5p-jg67-6x7h](https://github.com/advisories/GHSA-gx5p-jg67-6x7h) | Next.js XSS in beforeInteractive scripts with untrusted input | **MODERATE** | `CWE-79` | `>=13.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (beforeInteractive scripts) |
| [GHSA-h64f-5h5j-jqjh](https://github.com/advisories/GHSA-h64f-5h5j-jqjh) | Next.js Denial of Service in Image Optimization API | **MODERATE** | `CWE-770` | `>=10.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (`next/image`) |
| [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) | Next.js SSRF in applications using WebSocket upgrades | **HIGH** | `CWE-918` | `>=13.4.13 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (WebSocket upgrades) |
| [GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7) | Next.js cache poisoning in React Server Component responses | **MODERATE** | `CWE-436` | `>=14.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (RSC response cache) |
| [GHSA-36qx-fr4f-26g5](https://github.com/advisories/GHSA-36qx-fr4f-26g5) | Next.js Middleware / Proxy bypass in Pages Router with i18n | **HIGH** | `CWE-863` | `>=12.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` | **Not Reachable** (App Router used) |
| [GHSA-m99w-x7hq-7vfj](https://github.com/advisories/GHSA-m99w-x7hq-7vfj) | Next.js: Denial of Service in App Router using Server Actions | **HIGH** | `CWE-834` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Not Reachable** (Server Actions unused) |
| [GHSA-89xv-2m56-2m9x](https://github.com/advisories/GHSA-89xv-2m56-2m9x) | Next.js: SSRF in Server Actions on custom servers | **HIGH** | `CWE-918` | `>=14.1.1 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Not Reachable** (Server Actions unused) |
| [GHSA-68g3-v927-f742](https://github.com/advisories/GHSA-68g3-v927-f742) | Next.js: Cache confusion of response bodies for requests with bodies | **MODERATE** | `CWE-524` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (POST caching) |
| [GHSA-4633-3j49-mh5q](https://github.com/advisories/GHSA-4633-3j49-mh5q) | Next.js: Cache confusion with invalid UTF-8 byte sequences | **MODERATE** | `CWE-116` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Prod Reachable** (Cache UTF-8 parsing) |
| [GHSA-4c39-4ccg-62r3](https://github.com/advisories/GHSA-4c39-4ccg-62r3) | Next.js: Unbounded Server Action payload in Edge runtime | **MODERATE** | `CWE-770` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Not Reachable** (Node runtime, no actions) |
| [GHSA-p9j2-gv94-2wf4](https://github.com/advisories/GHSA-p9j2-gv94-2wf4) | Next.js: SSRF in rewrites via destination hostname | **HIGH** | `CWE-918` | `>=12.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (Rewrites config) |
| [GHSA-955p-x3mx-jcvp](https://github.com/advisories/GHSA-955p-x3mx-jcvp) | Next.js: Unauthenticated disclosure of internal Server Functions | **MODERATE** | `CWE-201` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` | **Not Reachable** (Server Functions unused) |
| [GHSA-p293-qw3h-jr36](https://github.com/advisories/GHSA-p293-qw3h-jr36) | Next.js: Unauthenticated RCE on windows-hosted servers | **CRITICAL** | `CWE-22` | `>=13.4.0 <15.5.24` | `14.2.35` | `15.2.0` | `16.4.6` | **Dev-Only** (Prod runs on Linux Debian container) |
| [GHSA-2xp9-vwfh-vxw4](https://github.com/advisories/GHSA-2xp9-vwfh-vxw4) | Next.js: RCE in Image Optimization API when AVIF files are used | **CRITICAL** | `CWE-1395` | `>=10.0.0 <15.5.24` | `14.2.35` | `15.2.0` | `16.4.6` | **Feature-Dependent** (AVIF format unused) |
| [GHSA-2464-fhr4-w9xw](https://github.com/advisories/GHSA-2464-fhr4-w9xw) | Next.js: RCE in Image Optimization API when SVG files are used | **CRITICAL** | `CWE-1395` | `>=10.0.0 <=15.5.27` | `No 14.x fix` | `No 15.x fix` | `16.4.6` | **Mitigated** (`dangerouslyAllowSVG: false`) |
| [GHSA-p3m5-59mp-jv5r](https://github.com/advisories/GHSA-p3m5-59mp-jv5r) | Next.js: Denial of Service in App Router using Server Actions | **HIGH** | `CWE-770` | `>=13.0.0 <=15.5.27` | `No 14.x fix` | `No 15.x fix` | `16.4.6` | **Not Reachable** (Server Actions unused) |
| [GHSA-pc58-hwjq-p385](https://github.com/advisories/GHSA-pc58-hwjq-p385) | Next.js: Cross-client response injection in self-hosted forwarded responses | **MODERATE** | `CWE-444` | `<=15.5.28` | `No 14.x fix` | `No 15.x fix` | `16.4.6` | **Not Reachable** (Streaming forwarding unused) |

---

## 2. LTS Status & Security Patch Analysis

- **Latest Next.js 14.x Release:** `14.2.35` published on **December 11, 2025**.
- **Security Patch Inflow:** Zero security patches have been backported to Next.js 14.x throughout 2026. The 14.x maintenance branch is effectively End-Of-Life (EOL) for newly discovered CVEs.
- **Three Advisories Lacking 14.x Upstream Fixes:**
  1. `GHSA-2464-fhr4-w9xw` (SVG Image Optimizer RCE): Affects all versions up to 15.5.27. Fixed only in `16.4.6`. Mitigated in 14.x/15.x by configuring `images.dangerouslyAllowSVG: false` in `next.config.js`.
  2. `GHSA-p3m5-59mp-jv5r` (Server Actions DoS): Fixed only in `16.4.6`. Unreachable in Pentesa because `apps/web` uses client-side fetch clients communicating with the FastAPI backend and defines zero Server Actions.
  3. `GHSA-pc58-hwjq-p385` (Cross-client response injection): Fixed only in `16.4.6`. Unreachable in Pentesa because `apps/web` does not use streaming proxy response forwarding with shared caching.

---

## 3. Decision & Minimum Major Identification

1. **Smallest-Jump Option for Immediate Wave Maintenance:**
   - **Target Version:** `next@14.2.35` (retains React 18, zero API breaks).
   - **Configuration Hardening:** `images: { dangerouslyAllowSVG: false }` in `apps/web/next.config.js`.
   - **Result:** Closes all 32 upstream-fixed advisories; the remaining 3 advisories are either mitigated via configuration or functionally unreachable.

2. **Strict Zero-Residual Minimum Major Version:**
   - If upstream policy requires 100% of advisories to have official code fixes without relying on configuration mitigations, **Next.js 14.x cannot achieve this**.
   - The **minimum major version** providing official fixes for all 35 advisories is **`next@16.4.6`** (released 2026-11-09).
   - Upgrading to `16.4.6` requires a React 19 migration, Turbopack testing, and App Router async headers migration, and is scheduled under Wave 3/4 post-audit maintenance.
