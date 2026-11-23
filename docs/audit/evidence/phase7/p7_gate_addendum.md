# Phase 7 Gate Reconciliation Addendum (Part 0)

- **Timestamp (UTC):** `2026-11-23T07:11:56.076337+00:00`
- **Git Commit:** `efb1c383ddf5a38e7e69507233e998f1f26d6510`
- **Exact Command:** `git diff p7-design-complete..HEAD` + `p0c_pdf_recheck.py`
- **Runner P7 SHA-256:** `4736fb5df2517b25dcc383b69754f075d8108dc85c9612348127830b7c60385f`
- **Cleanup P7 SHA-256:** `512f27306d1f4f7ab4adbd852e9395dc214656952f6598a2ef4518b0739f8ea1`
- **Ground Truth P7 SHA-256:** `acd209a69a3b0c8a83d936f498945797e8842fcb815b8295cc31129957c0cac4` (unchanged since `p7-design-complete`)
- **Scorer P7 SHA-256:** `2741d23c5df6183517cd25cab0a390fb8318e52d5f58084a0b9963bd5bd66ddd` (unchanged since `p7-design-complete`)
- **Target Stack / DB:** `pentesa-prod` (`http://127.0.0.1:8000`, running stack) / PostgreSQL 16 Alpine (`pentesa-db`)

---

## Part 0(a) — Audit Trail (`git diff p7-design-complete..HEAD`)

| File | Diff Since `p7-design-complete` (`782e894`) | Classification | Weakened Any Check? | Action |
|---|---|---|---|---|
| `benchmark/ground_truth_p7.yaml` | **0 lines changed** (SHA-256 `acd209a69...`) | Frozen / Unmodified | No | None required |
| `benchmark/score_p7.py` | **0 lines changed** (SHA-256 `2741d23c5...`) | Frozen / Unmodified | No | None required |
| `benchmark/p7/cleanup_p7.py` | Added post-freeze (+167 lines, committed in `efb1c38`) | Cleanup harness | No | Keep as Phase 7 record |
| `benchmark/p7/test_runner_p7.py` | Added post-freeze (+1,805 lines, committed in `efb1c38`); 4 pre-commit fixes between Run 0/Run 1 and Final Run (detailed below) | `HARNESS BUG` (all 4) | **No** (0 `CRITERIA CHANGE`) | No revert required; Run 0 & Run 1 preserved verbatim in `p7_failed_runs_addendum.txt` |

### Why Run 0 & Run 1 Were Superseded (Preserved Verbatim in `p7_failed_runs_addendum.txt`)
1. **Run 0 -> Run 1 (`HARNESS BUG`):** `yaml.safe_load()` aborted on an unquoted colon in frozen Phase 4 `benchmark/ground_truth_p4.yaml:202`. Changed runner to read GT4 case IDs via regex without modifying frozen `ground_truth_p4.yaml`.
2. **Run 1 -> Final Run (`HARNESS BUG` #1):** Runner checked `rv.json().get("is_valid")` instead of the actual API response field `verified` on `POST /api/v1/reports/verify`, falsely failing all 12/12 report cryptographic verification checks (causing Run 1 fidelity to read 56.25% = 27/48).
3. **Run 1 -> Final Run (`HARNESS BUG` #2):** `strip_html()` omitted `html.unescape()`, causing HTML entities (`&#39;`) in finding titles (`'q'`, `'name'`) to fail literal substring matching on HTML reports.
4. **Run 1 -> Final Run (`HARNESS BUG` #3):** `extract_pdf_text()` attempted raw `zlib.decompress()` without `ASCII85Decode` (ReportLab's filter chain). *Note:* As proven in Part 0(c) below, `extract_pdf_text()` still contained a residual `HARNESS BUG` (`base64.a85decode(..., adobe=True)` + `\r?\nendstream`), which returned `0` characters on every ReportLab PDF.

All Phase 7 evidence files (`p7_accuracy_audit.json`, `p7_completeness_audit.json`, `p7_llm_report_eval.json`, `p7_report_quality_audit.json`, `p7_reproduction_replays.json`, `p7_test_results.json`, `p7_cleanup_proof.txt`, `cost-log.md`, `p7_pdf_recheck.txt`, `p7_gate_addendum.md`) now carry full forensic headers including `Runner P7 SHA-256`, and `MANIFEST.sha256` has been updated accordingly.

---

## Part 0(b) — Accuracy Method, Complete 39-Finding Table & Phase 3 Reconciliation

### Complete 39 Production Findings Table

| # | Finding ID | Project | Title | WSTG / CWE | Endpoint | Method | Type | How TP Was Decided |
|---:|---|---|---|---|---|:---:|:---:|---|
| 1 | `b0beaa4a-cd7c-4375-b7ff-8a48feef5880` | `Phase4-Bench-crapi-Run3` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 2 | `f3054322-9069-4790-b1cc-c1c1efc5d51c` | `Phase4-Bench-crapi-Run3` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 3 | `d42679b6-1147-43e6-89c1-fec217388b12` | `Phase4-Bench-crapi-Run2` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 4 | `910283b7-7336-47e8-ab77-3655a13db04d` | `Phase4-Bench-crapi-Run2` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 5 | `d8277970-7bee-4050-b998-616628940d06` | `Phase4-Bench-crapi-Run1` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 6 | `ad0be37d-e928-4d0e-9c2c-3bdaf7600ad4` | `Phase4-Bench-crapi-Run1` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 7 | `644947a9-a758-4f14-8a6e-f373564ed5c6` | `Phase4-Bench-juiceshop-Run3` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 8 | `fdbf013c-e8a5-4783-b477-964529c868ed` | `Phase4-Bench-juiceshop-Run3` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 9 | `dd9e62e0-7517-4e99-b37f-705dce54c962` | `Phase4-Bench-juiceshop-Run2` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 10 | `f7dd2732-92a2-44b4-bc11-8f8882b31b6c` | `Phase4-Bench-juiceshop-Run2` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 11 | `2fc910d2-0fdc-4124-8b16-0a8ce38b713b` | `Phase4-Bench-juiceshop-Run1` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 12 | `85b56a73-a976-497e-abf8-6fce903dafe4` | `Phase4-Bench-juiceshop-Run1` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 13 | `b9c620ba-902e-4730-879a-19865086dd91` | `Phase4-Bench-pentesa-bench-Run3` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/render` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 14 | `3c64403c-8400-4a31-b557-68f72012eae4` | `Phase4-Bench-pentesa-bench-Run3` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 15 | `afee9739-a769-4b45-9225-9e69d87cd75c` | `Phase4-Bench-pentesa-bench-Run2` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/render` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 16 | `23f14bad-ec0d-4269-8330-11fe1b1725e2` | `Phase4-Bench-pentesa-bench-Run2` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 17 | `4adee4d6-4c7b-4644-840e-b2280e5ea2e4` | `Phase4-Bench-pentesa-bench-Run1` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/render` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 18 | `0e668640-dd5f-45c0-b196-5a4dca4a8ef9` | `Phase4-Bench-pentesa-bench-Run1` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 19 | `60247d06-209d-447f-b628-41362194c353` | `Phase3-Bench-pentesa-bench-seeded-Run3` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/render` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 20 | `891dd66b-3eed-4f2c-99f9-4f7ddf52245f` | `Phase3-Bench-pentesa-bench-seeded-Run3` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 21 | `7776e626-d22e-4940-be6f-a565dad6b6ff` | `Phase3-Bench-pentesa-bench-seeded-Run2` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 22 | `3838f7e2-3be8-4661-9d23-009dd23e903f` | `Phase3-Bench-pentesa-bench-seeded-Run2` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/secure) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/secure` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 23 | `585303cd-39a7-4fe3-91b4-798a162d420a` | `Phase3-Bench-pentesa-bench-seeded-Run1` | Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render) | `WSTG-INPV-01` / `CWE-79` | `bench-pentesa-app:8080/ssti/render` (param: `name`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 24 | `c03b79af-b606-4868-8e76-3b54bcd1b67c` | `Phase3-Bench-pentesa-bench-seeded-Run1` | SQL Injection in 'q' Parameter (/sqli/search) | `WSTG-INPV-05` / `CWE-89` | `bench-pentesa-app:8080/sqli/search` (param: `q`) | `GET` | active | ground-truth case (`GT-PB-SQLI-01-V`) + oracle replay |
| 25 | `a5256858-be48-4a48-acf1-d3d9ad817c81` | `Phase3-Bench-crapi-Run3` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 26 | `b6390a70-07dc-421b-be59-6b27afac07e4` | `Phase3-Bench-crapi-Run3` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 27 | `114c23d0-d325-45fd-b2d9-bff68570f661` | `Phase3-Bench-crapi-Run2` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 28 | `7e267ad9-36d2-4526-9b8d-9d01076c0945` | `Phase3-Bench-crapi-Run2` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 29 | `8d88c3f6-8c65-4786-84e7-5c60c45347e2` | `Phase3-Bench-crapi-Run1` | Exposed Environment Configuration File (.env) | `WSTG-CONF-04` / `CWE-200` | `bench-crapi-web/.env` (param: `<none>`) | `GET` | active | oracle replay + `raw_response` pattern (unlisted in frozen GT) |
| 30 | `2111c877-5ebb-4ed6-b7f9-f98afe782b46` | `Phase3-Bench-crapi-Run1` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-crapi-web/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 31 | `27ffba9c-3739-464a-8b59-c4a242928292` | `Phase3-Bench-dvwa-Run3` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-dvwa/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 32 | `cd62cee4-fe76-48af-bf7d-5b146d005bbb` | `Phase3-Bench-dvwa-Run2` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-dvwa/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 33 | `17cad9e1-4b9b-4ec5-81e9-90383bbb3783` | `Phase3-Bench-dvwa-Run1` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CLNT-09` / `CWE-693` | `bench-dvwa/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 34 | `40a72d1c-3ac2-413a-bafd-30ce9254bb23` | `Phase3-Bench-juiceshop-Run3` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 35 | `f1965d27-2114-4b2a-b4fd-79403f9c9f0c` | `Phase3-Bench-juiceshop-Run3` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 36 | `c7bb6551-5cea-42d7-a666-8731eb8ec67a` | `Phase3-Bench-juiceshop-Run2` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 37 | `109e8525-9cf4-4495-bc81-5725c963c2b9` | `Phase3-Bench-juiceshop-Run2` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |
| 38 | `a824593d-ddea-4c28-b619-707a7ecb209e` | `Phase3-Bench-juiceshop-Run1` | SQL Injection in Product Search Parameter | `WSTG-INPV-05` / `CWE-89` | `bench-juiceshop:3000/rest/products/search` (param: `q`) | `GET` | active | ground-truth case (`GT-JS-SQLI-01-V`) + oracle replay |
| 39 | `56c25c1d-4c4d-4dc1-ae74-a360d3fe770c` | `Phase3-Bench-juiceshop-Run1` | Missing Security Headers (CSP, XFO, XCTO) | `WSTG-CONF-02` / `CWE-693` | `bench-juiceshop:3000/` (param: `<none>`) | `GET` | passive-header | other: passive missing-header check on `raw_response` + oracle replay (unlisted in frozen GT) |

### Distinct `(endpoint, parameter, CWE)` Tuples (`n = 8` distinct tuples across 39 rows)

| # | Endpoint | Parameter | CWE | Instance Count | Classification |
|---:|---|---|---|---:|---|
| 1 | `bench-crapi-web/` | `<none>` | `CWE-693` | 6 | Passive-header — unlisted in frozen GT |
| 2 | `bench-crapi-web/.env` | `<none>` | `CWE-200` | 6 | Active probe — unlisted in frozen GT (`.env` exposure) |
| 3 | `bench-dvwa/` | `<none>` | `CWE-693` | 3 | Passive-header — unlisted in frozen GT |
| 4 | `bench-juiceshop:3000/` | `<none>` | `CWE-693` | 6 | Passive-header — unlisted in frozen GT |
| 5 | `bench-juiceshop:3000/rest/products/search` | `q` | `CWE-89` | 6 | Active — matches frozen GT (`GT-JS-SQLI-01-V` / `GT-PB-SQLI-01-V`) |
| 6 | `bench-pentesa-app:8080/sqli/search` | `q` | `CWE-89` | 6 | Active — matches frozen GT (`GT-JS-SQLI-01-V` / `GT-PB-SQLI-01-V`) |
| 7 | `bench-pentesa-app:8080/ssti/render` | `name` | `CWE-79` | 5 | Active — unlisted as CWE-79 in frozen GT (SSTI endpoint / SSTI secure control) |
| 8 | `bench-pentesa-app:8080/ssti/secure` | `name` | `CWE-79` | 1 | Active — unlisted as CWE-79 in frozen GT (SSTI endpoint / SSTI secure control) |

### Breakdown & Reconciliation with Phase 3 (`0 TP` vs Frozen Ground Truth)
- **Composition of the 39 production findings:**
  - **12 / 39 (30.8%)** match a frozen Phase 3 ground-truth vulnerability case (**only 2 distinct tuples**, repeated across 6 runs each: `GT-JS-SQLI-01-V` SQLi on Juice Shop `/rest/products/search?q=`, and `GT-PB-SQLI-01-V` SQLi on `pentesa-bench` `/sqli/search?q=`).
  - **15 / 39 (38.5%)** are **passive missing-security-header** findings (`CWE-693`, 3 distinct host tuples) — unlisted in frozen Phase 3/4 ground truth.
  - **12 / 39 (30.8%)** are **active findings unlisted in frozen ground truth** (3 distinct tuples: 6× `bench-crapi-web/.env` `CWE-200`, 5× `/ssti/render?name=` Reflected XSS `CWE-79` on an SSTI GT endpoint, and 1× `/ssti/secure?name=` Reflected XSS `CWE-79` on an SSTI secure-control endpoint).
- **Why Phase 3 frozen `score.py` reported `0 TP` while Phase 7 reported `39 TP`:**
  1. In Phase 3 (`docs/audit/05-pentest-benchmark-results.md` §3.2), the frozen scorer (`benchmark/score.py`) consumed raw `FindingResponse` JSON payloads directly. Because of **`P1-FIND-02`**, `FindingResponse` omits root `endpoint`, `method`, and `target` strings (`""`), so even the 12 genuine SQLi matches failed strict tuple matching and were scored as `UNLISTED_FINDING` (`0 TP` strict; `1 TP` per seeded/Juice Shop run only in the P1-FIND-02-compensated per-target view).
  2. In Phase 7, `test_runner_p7.py` extracted URLs from `evidence[0].reproduction_curl` and applied a post-hoc pattern/oracle script across the 8 repeated finding archetypes — without independent blinded adjudication over the full 63-case frozen GT vulnerability matrix (where true recall against the 45 vulnerable GT cases remains **2 / 45 = 4.4%** even after manual URL extraction).
- **Status Adjustment & Wording Correction:**
  - TP/FP accuracy adjudication is relabeled **`Partially Verified`** (overall `P7-TC-ACC-01` remains **`Failed`** due to 0/39 CVSS scores = 0.0% CVSS band consistency, `DEFECT-FIND-03`).
  - All `"100% precision"` / `"100.0% adjudicated precision"` claims have been **removed** from `docs/audit/08-findings-quality-assessment.md` and every living audit document (the raw machine-captured `p7_test_results.json` and `score_p7.txt` remain unedited per evidence immutability rules and are superseded in interpretation by this addendum).

---

## Part 0(c) — PDF Fidelity Second-Extractor Recheck (`p7_pdf_recheck.txt`)

Machine-captured verification in `docs/audit/evidence/phase7/p7_pdf_recheck.txt` compared `test_runner_p7.py::extract_pdf_text()` (Method 1) against an independent ReportLab stream parser (Method 2: `stream[\r\n]+(.*?)endstream`, `ASCII85Decode` without leading `<~` stripping trailing `~>`, `FlateDecode`, `BT..ET` `Tj`/`TJ` operators):

- **Root cause of the 6/24 PDF misses (18/24 = 75.0% PDF -> 42/48 = 87.5% overall in `P7-TC-REP-01`):** Method 1 returned **0 characters** on every ReportLab PDF because (1) ReportLab writes `~>endstream` with no newline before `endstream`, and (2) `base64.a85decode(..., adobe=True)` requires a leading `<~` delimiter absent from PDF `ASCII85Decode` streams.
- **Classification of all 6 PDF misses:**

| # | Missed Check in `P7-TC-REP-01` | Method 1 Result | Method 2 Result | Classification |
|---:|---|:---:|:---:|---|
| 1 | `findings_project` PDF Run 1 `titles_ok` | `False` (0 chars) | `True` (both titles present verbatim) | **`EXTRACTION ARTIFACT`** |
| 2 | `findings_project` PDF Run 1 `cwes_ok` | `False` (0 chars) | `True` (`CWE-89` & `CWE-79` present) | **`EXTRACTION ARTIFACT`** |
| 3 | `findings_project` PDF Run 2 `titles_ok` | `False` (0 chars) | `True` (both titles present verbatim) | **`EXTRACTION ARTIFACT`** |
| 4 | `findings_project` PDF Run 2 `cwes_ok` | `False` (0 chars) | `True` (`CWE-89` & `CWE-79` present) | **`EXTRACTION ARTIFACT`** |
| 5 | `findings_project` PDF Run 3 `titles_ok` | `False` (0 chars) | `True` (both titles present verbatim) | **`EXTRACTION ARTIFACT`** |
| 6 | `findings_project` PDF Run 3 `cwes_ok` | `False` (0 chars) | `True` (`CWE-89` & `CWE-79` present) | **`EXTRACTION ARTIFACT`** |

- **Recomputed Factual Fidelity & Adjusted Status:**
  - PDF factual fidelity: **24 / 24 (100.0%)**; HTML factual fidelity: **24 / 24 (100.0%)** -> **48 / 48 (100.0%)** overall factual fidelity, **100.0%** 3-run consistency.
  - **`P7-TC-REP-01` adjusted status:** **`Verified`** (recomputed from `Failed 87.5%`). *Note:* `FR-RP-01` remains **`Partially Verified`** because `renderer.py` uses ReportLab (5-section layout) instead of specified WeasyPrint (17-section layout).
- **Additional REAL DEFECTS Confirmed in PDF by Method 2:**
  - **Empty PDF (`P7-TC-REP-02`, `DEFECT-REP-01`):** Method 2 proves `"STRONG SECURITY POSTURE"` is also rendered in the empty PDF (missed by Method 1's 0-char output).
  - **Mixed-Status PDF (`P7-TC-REP-02`, `DEFECT-REP-01`):** Method 2 confirms `"Detected"` is absent from the PDF (`renderer.py:211-229` omits the `Status` column) — **`REAL DEFECT`**.
  - **Canary Redaction PDF (`P7-TC-REDACT-02`, `DEFECT-REDACT-01`):** Method 2 proves `PENTESA_P7_CANARY_SECRET_9f8e7d6c` also leaks into the PDF report (4/6 surfaces: `raw_response`, `finding_description`, `html_report`, `pdf_report`) — **`REAL DEFECT`**.

---

## Part 0(d) — LLM Groundedness Status Adjustment

- `P7-TC-REP-03` evaluated **6 total statements** across 3 runs on **1 project** (`Phase3-Bench-pentesa-bench-seeded-Run1`, 2 confirmed findings; 2,434 tokens / \$0.0144 USD in final run; 4,816 tokens / \$0.0283 USD cumulative).
- Because sample size is $n = 6$ ($< 30$ statements across $\ge 3$ projects), `P7-TC-REP-03` is relabeled **`Partially Verified (n=6)`** (down from `Verified`) across `docs/audit/08-findings-quality-assessment.md` and `docs/audit/02-requirement-traceability.md`.

---

## Part 0(e), 0(f), 0(g) — Defect Registration, Docs-Sync & npm Advisory Triage

- **Part 0(e):** Registered **`DEFECT-CFG-01` (P3)** in `docs/audit/03-defect-register.md` and `docs/audit/10-improvement-roadmap.md` (`packages/common/config.py:51-55` defaults `database_url` to local SQLite `sqlite+aiosqlite:///./pentesa.db`; `apps/api/main.py:71-79` does not reject SQLite when `PENTESA_ENV=production`).
- **Part 0(f):** Added full **Documentation Synchronization Backlog** (JWT lifetime/refresh, circuit-breaker threshold conflict 15%/30s vs 20%/60s, LangGraph vs custom DAG, bcrypt cost 12 verified in sync, tool list vs wrappers) with exact doc paths and code evidence in `docs/audit/10-improvement-roadmap.md`.
- **Part 0(g):** Added **npm Advisory Triage Plan** (`next@14.2.18` and nested `postcss@8.4.31`, fixed versions, breaking-change risks, interim `images.unoptimized` mitigation — not applied) in `docs/audit/10-improvement-roadmap.md`.
