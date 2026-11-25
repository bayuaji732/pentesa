# Repository Share-Readiness Secrets & PII Scan Report

> **Scan Scope:** Working Tree (uncommitted/tracked excluding `.env*` secrets) + Full Git History (`git log -p --all`).
> **Total Detections:** 1250 (Working Tree: 548, Git History: 702).
> **Masking Policy:** All detected secrets, emails, paths, and internal hostnames are masked per ENV RULES v2.

## 1. Summary by Detection Type

| Detection Type | Working Tree | Git History | Total |
|---|---|---|---|
| `BEARER_TOKEN` | 26 | 26 | 52 |
| `EMPLOYEE_EMAIL` | 8 | 10 | 18 |
| `INTERNAL_HOSTNAME` | 24 | 30 | 54 |
| `INTERNAL_IP_RFC1918` | 134 | 137 | 271 |
| `JWT_TOKEN` | 8 | 11 | 19 |
| `PASSWORD_ASSIGNMENT` | 19 | 22 | 41 |
| `PRIVATE_KEY` | 0 | 3 | 3 |
| `SK_KEY` | 9 | 14 | 23 |
| `URL_CREDENTIAL` | 3 | 1 | 4 |
| `WINDOWS_USER_PATH` | 317 | 448 | 765 |

## 2. Working Tree Detections (Path:Line:Type)

| Source File | Line | Type | Masked Evidence |
|---|---|---|---|
| `.env.example` | 57 | `SK_KEY` | `sk****ey` |
| `ENVIRONMENTS.md` | 33 | `WINDOWS_USER_PATH` | `fi****r2` |
| `ENVIRONMENTS.md` | 46 | `WINDOWS_USER_PATH` | `fi****r2` |
| `ENVIRONMENTS.md` | 80 | `WINDOWS_USER_PATH` | `fi****r2` |
| `agents/authorization/authz_agent.py` | 95 | `WINDOWS_USER_PATH` | `/u****/1` |
| `agents/llm/provider.py` | 146 | `WINDOWS_USER_PATH` | `/u****/1` |
| `agents/llm/provider.py` | 155 | `WINDOWS_USER_PATH` | `/u****/1` |
| `apps/web/src/app/projects/page.tsx` | 466 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `apps/web/src/lib/api.ts` | 105 | `PASSWORD_ASSIGNMENT` | `pa****g)` |
| `apps/web/src/lib/api.ts` | 110 | `PASSWORD_ASSIGNMENT` | `pa****rd` |
| `benchmark/ground_truth.yaml` | 528 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `benchmark/ground_truth.yaml` | 572 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `benchmark/ground_truth.yaml` | 575 | `PASSWORD_ASSIGNMENT` | `pa****rd` |
| `benchmark/ground_truth.yaml` | 599 | `PASSWORD_ASSIGNMENT` | `pa****ng` |
| `benchmark/ground_truth.yaml` | 619 | `BEARER_TOKEN` | `Be****9.` |
| `benchmark/ground_truth.yaml` | 622 | `BEARER_TOKEN` | `Be****9.` |
| `benchmark/ground_truth.yaml` | 644 | `BEARER_TOKEN` | `Be****9.` |
| `benchmark/ground_truth.yaml` | 686 | `BEARER_TOKEN` | `Be****9.` |
| `benchmark/ground_truth.yaml` | 689 | `BEARER_TOKEN` | `Be****9.` |
| `benchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `benchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `benchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `benchmark/run_benchmark.py` | 390 | `INTERNAL_IP_RFC1918` | `17****10` |
| `benchmark/run_benchmark.py` | 391 | `INTERNAL_IP_RFC1918` | `17****10` |
| `benchmark/run_benchmark.py` | 392 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `benchmark/setup_engagement_and_scope_check.py` | 41 | `INTERNAL_IP_RFC1918` | `19****50` |
| `benchmark/p6/cleanup_prod.py` | 40 | `WINDOWS_USER_PATH` | `c:****r2` |
| `benchmark/p6/cleanup_prod.py` | 125 | `WINDOWS_USER_PATH` | `/u****d}` |
| `benchmark/p6/cleanup_prod.py` | 126 | `WINDOWS_USER_PATH` | `/u****d}` |
| `benchmark/p6/seed_sec_environment.py` | 127 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `benchmark/p6/seed_sec_environment.py` | 127 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `benchmark/p6/seed_sec_environment.py` | 172 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `benchmark/p6/test_runner.py` | 326 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `benchmark/p6/test_runner_prod.py` | 131 | `PASSWORD_ASSIGNMENT` | `pw****c[` |
| `benchmark/p6/test_runner_prod.py` | 407 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `benchmark/p6b/hotfix_cleanup_and_demo_prep.py` | 29 | `WINDOWS_USER_PATH` | `c:****r2` |
| `benchmark/p6b/hotfix_cleanup_and_demo_prep.py` | 30 | `WINDOWS_USER_PATH` | `c:****r2` |
| `benchmark/p6b/test_runner_p6b.py` | 148 | `PASSWORD_ASSIGNMENT` | `pw****c[` |
| `benchmark/p6b/test_runner_p6b.py` | 731 | `WINDOWS_USER_PATH` | `/u****d}` |
| `benchmark/p6b/test_runner_p6b.py` | 892 | `BEARER_TOKEN` | `Be****et` |
| `benchmark/p6b/test_runner_p6b.py` | 992 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `benchmark/p7/test_runner_p7.py` | 936 | `PASSWORD_ASSIGNMENT` | `pa****d}` |
| `benchmark/p8/cleanup_p8.py` | 37 | `PASSWORD_ASSIGNMENT` | `pa****t(` |
| `benchmark/p8/cleanup_p8.py` | 86 | `WINDOWS_USER_PATH` | `/u****d}` |
| `benchmark/p8/test_runner_p8.py` | 73 | `PASSWORD_ASSIGNMENT` | `pa****t(` |
| `data/juiceshop_users.json` | 5 | `JWT_TOKEN` | `ey****yY` |
| `data/juiceshop_users.json` | 7 | `JWT_TOKEN` | `ey****yY` |
| `data/juiceshop_users.json` | 7 | `BEARER_TOKEN` | `Be****yY` |
| `data/juiceshop_users.json` | 12 | `JWT_TOKEN` | `ey****4E` |
| `data/juiceshop_users.json` | 14 | `JWT_TOKEN` | `ey****4E` |
| `data/juiceshop_users.json` | 14 | `BEARER_TOKEN` | `Be****4E` |
| `data/juiceshop_users.json` | 19 | `JWT_TOKEN` | `ey****ko` |
| `data/juiceshop_users.json` | 21 | `JWT_TOKEN` | `ey****ko` |
| `data/juiceshop_users.json` | 21 | `BEARER_TOKEN` | `Be****ko` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_167f46ec.html` | 699 | `URL_CREDENTIAL` | `po****!@` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_167f46ec.html` | 699 | `INTERNAL_IP_RFC1918` | `10****45` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_167f46ec.html` | 717 | `WINDOWS_USER_PATH` | `/u****02` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_167f46ec.html` | 732 | `WINDOWS_USER_PATH` | `/u****02` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_5c86c2cf.html` | 699 | `URL_CREDENTIAL` | `po****!@` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_5c86c2cf.html` | 699 | `INTERNAL_IP_RFC1918` | `10****45` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_5c86c2cf.html` | 717 | `WINDOWS_USER_PATH` | `/u****02` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_5c86c2cf.html` | 732 | `WINDOWS_USER_PATH` | `/u****02` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_beb289ac.html` | 538 | `WINDOWS_USER_PATH` | `/u****02` |
| `data/reports/report_be272fd8-1d4a-4d95-b470-7e36bc221050_beb289ac.html` | 553 | `WINDOWS_USER_PATH` | `/u****02` |
| `database/seeds/seed_data.py` | 21 | `PASSWORD_ASSIGNMENT` | `pa****r)` |
| `docs/02-srs.md` | 170 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****42` |
| `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****99` |
| `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/04-agent-architecture.md` | 265 | `WINDOWS_USER_PATH` | `/u****te` |
| `docs/05-agent-specifications.md` | 118 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `docs/05-agent-specifications.md` | 153 | `INTERNAL_IP_RFC1918` | `19****45` |
| `docs/05-agent-specifications.md` | 182 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/05-agent-specifications.md` | 183 | `INTERNAL_IP_RFC1918` | `19****11` |
| `docs/08-scope-enforcement.md` | 55 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `docs/08-scope-enforcement.md` | 66 | `INTERNAL_IP_RFC1918` | `19****54` |
| `docs/08-scope-enforcement.md` | 204 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/08-scope-enforcement.md` | 243 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/08-scope-enforcement.md` | 243 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/08-scope-enforcement.md` | 286 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/08-scope-enforcement.md` | 298 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/10-database-design.md` | 159 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `docs/10-database-design.md` | 214 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/11-api-specification.md` | 217 | `INTERNAL_IP_RFC1918` | `19****10` |
| `docs/13-security-requirements.md` | 128 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/21-architecture-review-report.md` | 222 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/22-production-deployment-guide.md` | 80 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/22-production-deployment-guide.md` | 80 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/22-production-deployment-guide.md` | 194 | `SK_KEY` | `sk****xx` |
| `docs/22-production-deployment-guide.md` | 219 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/22-production-deployment-guide.md` | 275 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/22-production-deployment-guide.md` | 280 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/23-end-to-end-testing-tutorial.md` | 59 | `WINDOWS_USER_PATH` | `c:****r2` |
| `docs/23-end-to-end-testing-tutorial.md` | 81 | `WINDOWS_USER_PATH` | `/u****/1` |
| `docs/23-end-to-end-testing-tutorial.md` | 134 | `WINDOWS_USER_PATH` | `/u****/1` |
| `docs/23-end-to-end-testing-tutorial.md` | 510 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `docs/24-enterprise-ui-ux-redesign-spec.md` | 38 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/ENVIRONMENTS.md` | 29 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/ENVIRONMENTS.md` | 29 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/ENVIRONMENTS.md` | 48 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/ENVIRONMENTS.md` | 48 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/ENVIRONMENTS.md` | 101 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/ENVIRONMENTS.md` | 101 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/00-preflight-report.md` | 244 | `WINDOWS_USER_PATH` | `/u****me` |
| `docs/audit/00-preflight-report.md` | 244 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/03-defect-register.md` | 46 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/03-defect-register.md` | 76 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/03-defect-register.md` | 78 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/03-defect-register.md` | 374 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/03-defect-register.md` | 378 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/03-defect-register.md` | 387 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/05-pentest-benchmark-results.md` | 53 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/05-pentest-benchmark-results.md` | 268 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/05-pentest-benchmark-results.md` | 272 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/audit/05-pentest-benchmark-results.md` | 272 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/05b-advanced-pentest-validation.md` | 104 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/05b-advanced-pentest-validation.md` | 172 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/05b-advanced-pentest-validation.md` | 185 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/05b-advanced-pentest-validation.md` | 185 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/05b-advanced-pentest-validation.md` | 252 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 19 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 20 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 22 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 23 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 78 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 78 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 150 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 157 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 193 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/audit/07-security-assessment.md` | 193 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/07-security-assessment.md` | 193 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 193 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 292 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/07-security-assessment.md` | 296 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/07-security-assessment.md` | 297 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/07-security-assessment.md` | 299 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/07-security-assessment.md` | 354 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/audit/07-security-assessment.md` | 354 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/07-security-assessment.md` | 355 | `WINDOWS_USER_PATH` | `/u****e7` |
| `docs/audit/07-security-assessment.md` | 357 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/audit/07-security-assessment.md` | 357 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/07-security-assessment.md` | 362 | `INTERNAL_HOSTNAME` | `si****om` |
| `docs/audit/07-security-assessment.md` | 362 | `EMPLOYEE_EMAIL` | `ah****om` |
| `docs/audit/07-security-assessment.md` | 388 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 391 | `WINDOWS_USER_PATH` | `c:****r2` |
| `docs/audit/07-security-assessment.md` | 392 | `WINDOWS_USER_PATH` | `c:****r2` |
| `docs/audit/07-security-assessment.md` | 399 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/07-security-assessment.md` | 399 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 9 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 16 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 22 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 23 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 25 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 28 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 31 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 32 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 40 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 41 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 42 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 43 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 44 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 46 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 47 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 48 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 48 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 49 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 50 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 51 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 51 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 51 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 52 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 53 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 54 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 55 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 55 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 56 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 57 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 57 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 58 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 59 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 60 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 74 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 82 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 83 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 141 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08-findings-quality-assessment.md` | 142 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 17 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 22 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 23 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 25 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 26 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 27 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 28 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 31 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 208 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 209 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/08b-reliability-performance.md` | 215 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/09-improvement-plan.md` | 11 | `INTERNAL_IP_RFC1918` | `10****00` |
| `docs/audit/09-improvement-plan.md` | 46 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/09-improvement-plan.md` | 46 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/09-improvement-plan.md` | 129 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/10-improvement-roadmap.md` | 188 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/10-improvement-roadmap.md` | 190 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/10-improvement-roadmap.md` | 436 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/cost-ledger.md` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase2/15_api_contract.txt` | 71 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase2/15_api_contract.txt` | 88 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 25 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 99 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 99 | `INTERNAL_IP_RFC1918` | `17****99` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 101 | `INTERNAL_IP_RFC1918` | `17****99` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 153 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/2A-addendum.md` | 154 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 73 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 83 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 118 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 119 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 192 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/2A-checkpoint.md` | 202 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/cost-log.md` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase2/part2a_results.json` | 21 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `docs/audit/evidence/phase2/part2a_results.json` | 139 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 143 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 152 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/audit/evidence/phase2/part2a_results.json` | 156 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/audit/evidence/phase2/part2a_results.json` | 312 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 315 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 332 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase2/part2a_results.json` | 460 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `docs/audit/evidence/phase2/part2a_results.json` | 461 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `docs/audit/evidence/phase2/part2a_results.json` | 1083 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase2/r1_default_admin.txt` | 218 | `JWT_TOKEN` | `ey****64` |
| `docs/audit/evidence/phase2/r1_default_admin.txt` | 218 | `JWT_TOKEN` | `ey****A4` |
| `docs/audit/evidence/phase3/b0_image_digests.txt` | 25 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase3/b0_image_digests.txt` | 210 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase3/b0_preflight_checks.txt` | 39 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase3/b0_preflight_checks.txt` | 41 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase3/findings_webgoat_baseline.json` | 33 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `docs/audit/evidence/phase3/gt_verification.txt` | 66 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `docs/audit/evidence/phase3/isolation_proof.txt` | 62 | `INTERNAL_IP_RFC1918` | `17****.3` |
| `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `PASSWORD_ASSIGNMENT` | `pa****an` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `PASSWORD_ASSIGNMENT` | `pa****br` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 37 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 38 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 39 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 40 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 41 | `INTERNAL_IP_RFC1918` | `17****12` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 42 | `INTERNAL_IP_RFC1918` | `17****11` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 43 | `INTERNAL_IP_RFC1918` | `17****10` |
| `docs/audit/evidence/phase3/scope_check_proof.txt` | 44 | `INTERNAL_IP_RFC1918` | `17****.9` |
| `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 52 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 72 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 91 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 110 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 134 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 153 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 178 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 227 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 228 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 229 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 230 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 231 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 237 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase5/5A-agent-inventory.md` | 240 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase6/p6b_prompt_injection_responses.json` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `docs/audit/evidence/phase6/p6b_prompt_injection_responses.json` | 38 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 333 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 334 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 341 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 342 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 349 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 350 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 357 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 358 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 365 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 366 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 373 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 374 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 381 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 382 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 389 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 390 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 397 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 398 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 405 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 406 | `WINDOWS_USER_PATH` | `/u****84` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 308 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 309 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 316 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 317 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 324 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 325 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 332 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 333 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 340 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 341 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 348 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 349 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 356 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 357 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 364 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 365 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 372 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 373 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 380 | `WINDOWS_USER_PATH` | `/u****d}` |
| `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 381 | `WINDOWS_USER_PATH` | `/u****e3` |
| `docs/audit/evidence/phase8/8A-spec.md` | 8 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 9 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 12 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 37 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 37 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 39 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/8A-spec.md` | 55 | `WINDOWS_USER_PATH` | `fi****r2` |
| `docs/audit/evidence/phase8/runner_live_output.txt` | 1562 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/full_unit_suite_wave0.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/full_unit_suite_wave0.txt` | 14 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/infra_01_test_after.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/infra_01_test_after.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/infra_01_test_before.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/infra_01_test_before.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/sec_leak_02_test_after.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/sec_leak_02_test_after.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/audit/evidence/phase9/wave0/sec_leak_02_test_before.txt` | 11 | `WINDOWS_USER_PATH` | `C:****r2` |
| `docs/diagrams/scope-validation-flow.mermaid` | 14 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `packages/common/security.py` | 27 | `PASSWORD_ASSIGNMENT` | `pa****r)` |
| `packages/schemas/scope.py` | 14 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `packages/schemas/scope.py` | 15 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `scripts/dummy_vuln_server.py` | 107 | `WINDOWS_USER_PATH` | `/u****/1` |
| `scripts/dummy_vuln_server.py` | 155 | `WINDOWS_USER_PATH` | `/u****1<` |
| `scripts/dummy_vuln_server.py` | 226 | `WINDOWS_USER_PATH` | `/u****d}` |
| `scripts/dummy_vuln_server.py` | 265 | `URL_CREDENTIAL` | `po****!@` |
| `scripts/dummy_vuln_server.py` | 265 | `INTERNAL_IP_RFC1918` | `10****45` |
| `scripts/dummy_vuln_server.py` | 334 | `WINDOWS_USER_PATH` | `/u****/1` |
| `scripts/part2a_runner.py` | 113 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `scripts/part2a_runner.py` | 277 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `scripts/part2a_runner.py` | 281 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `scripts/part2a_runner.py` | 287 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `scripts/part2a_runner.py` | 291 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `scripts/part2a_runner.py` | 293 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `scripts/part2a_runner.py` | 300 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `scripts/part2a_runner.py` | 304 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `scripts/part2a_runner.py` | 306 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `scripts/part2a_runner.py` | 978 | `BEARER_TOKEN` | `Be****45` |
| `scripts/verify_deployment.py` | 174 | `PASSWORD_ASSIGNMENT` | `pa****rd` |
| `services/discovery_engine/extractor.py` | 157 | `WINDOWS_USER_PATH` | `/u****42` |
| `services/discovery_engine/extractor.py` | 157 | `WINDOWS_USER_PATH` | `/u****d}` |
| `services/scope_engine/validator.py` | 92 | `INTERNAL_IP_RFC1918` | `19****.1` |
| `skills/scope-validation/SKILL.md` | 38 | `INTERNAL_IP_RFC1918` | `19****10` |
| `tests/audit/run_r1_real_stack.py` | 58 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_r1_real_stack.py` | 59 | `SK_KEY` | `sk****QA` |
| `tests/audit/run_r1_real_stack.py` | 111 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_r1_real_stack.py` | 112 | `SK_KEY` | `sk****QA` |
| `tests/audit/run_r1_real_stack.py` | 133 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_r1_real_stack.py` | 134 | `SK_KEY` | `sk****QA` |
| `tests/audit/run_r1_real_stack.py` | 164 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_r1_real_stack.py` | 165 | `SK_KEY` | `sk****QA` |
| `tests/audit/run_r6_real_stack.py` | 67 | `BEARER_TOKEN` | `Be****45` |
| `tests/audit/run_v3_verification.py` | 49 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `tests/audit/run_v4_verification.py` | 25 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_v4_verification.py` | 69 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `tests/audit/run_v4_verification.py` | 88 | `INTERNAL_HOSTNAME` | `ua****om` |
| `tests/audit/run_v4_verification.py` | 89 | `SK_KEY` | `sk****QA` |
| `tests/audit/run_v7_verification.py` | 50 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `tests/fixtures/synthetic_benchmark_findings.json` | 167 | `BEARER_TOKEN` | `Be****9.` |
| `tests/fixtures/synthetic_benchmark_findings.json` | 168 | `BEARER_TOKEN` | `Be****9.` |
| `tests/integration/test_discovery_api.py` | 66 | `WINDOWS_USER_PATH` | `/u****d}` |
| `tests/integration/test_discovery_api.py` | 84 | `WINDOWS_USER_PATH` | `/u****d}` |
| `tests/integration/test_e2e_workflow.py` | 62 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `tests/integration/test_tools_api.py` | 204 | `BEARER_TOKEN` | `Be****45` |
| `tests/performance/test_performance_benchmarks.py` | 73 | `BEARER_TOKEN` | `Be****90` |
| `tests/security/test_security_hardening.py` | 36 | `WINDOWS_USER_PATH` | `/u****st` |
| `tests/security/test_security_hardening.py` | 39 | `WINDOWS_USER_PATH` | `/u****..` |
| `tests/security/test_security_hardening.py` | 56 | `BEARER_TOKEN` | `Be****90` |
| `tests/unit/test_audit_chain.py` | 34 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `tests/unit/test_audit_chain.py` | 44 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `tests/unit/test_baseline_adapter.py` | 19 | `PASSWORD_ASSIGNMENT` | `pa****et` |
| `tests/unit/test_credential_encryption_and_redaction.py` | 109 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `tests/unit/test_credential_encryption_and_redaction.py` | 178 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_credential_encryption_and_redaction.py` | 197 | `BEARER_TOKEN` | `Be****78` |
| `tests/unit/test_credential_encryption_and_redaction.py` | 224 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_evidence_engine.py` | 27 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_evidence_engine.py` | 45 | `BEARER_TOKEN` | `Be****Dc` |
| `tests/unit/test_evidence_engine.py` | 101 | `BEARER_TOKEN` | `Be****yz` |
| `tests/unit/test_evidence_engine.py` | 155 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_findings_management.py` | 349 | `WINDOWS_USER_PATH` | `/u****/1` |
| `tests/unit/test_http_testing.py` | 54 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_lab_only_tool_guard.py` | 53 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `tests/unit/test_lab_only_tool_guard.py` | 80 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `tests/unit/test_llm_provider.py` | 126 | `SK_KEY` | `sk****yz` |
| `tests/unit/test_llm_provider.py` | 143 | `SK_KEY` | `sk****yz` |
| `tests/unit/test_llm_provider.py` | 143 | `BEARER_TOKEN` | `Be****yz` |
| `tests/unit/test_parameter_extraction.py` | 100 | `WINDOWS_USER_PATH` | `/u****42` |
| `tests/unit/test_parameter_extraction.py` | 102 | `WINDOWS_USER_PATH` | `/u****d}` |
| `tests/unit/test_safe_redirect_loop.py` | 152 | `BEARER_TOKEN` | `Be****45` |
| `tests/unit/test_scope_engine.py` | 197 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `tests/unit/test_scope_engine.py` | 202 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `tests/unit/test_scope_engine.py` | 208 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `tests/unit/test_scope_engine.py` | 297 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `tests/unit/test_scope_engine.py` | 304 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `tests/unit/test_scope_engine.py` | 314 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `tests/unit/test_security_rbac.py` | 20 | `PASSWORD_ASSIGNMENT` | `pw****3!` |
| `tests/unit/test_specialized_agents.py` | 165 | `WINDOWS_USER_PATH` | `/u****02` |

## 3. Git History Detections (Commit:Path:Type)

| Git Commit & File | Diff Line | Type | Masked Evidence |
|---|---|---|---|
| `GIT_HISTORY (315bbbf0)`: `docs/audit/evidence/phase9/wave0/full_unit_suite_wave0.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (ded03fa4)`: `docs/audit/evidence/phase9/wave0/infra_01_test_after.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (ded03fa4)`: `docs/audit/evidence/phase9/wave0/infra_01_test_after.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (ded03fa4)`: `docs/audit/evidence/phase9/wave0/infra_01_test_before.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (ded03fa4)`: `docs/audit/evidence/phase9/wave0/infra_01_test_before.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (14ce83d3)`: `docs/audit/evidence/phase9/wave0/sec_leak_02_test_after.txt` | 10 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (14ce83d3)`: `docs/audit/evidence/phase9/wave0/sec_leak_02_test_after.txt` | 12 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (14ce83d3)`: `docs/audit/evidence/phase9/wave0/sec_leak_02_test_before.txt` | 11 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (364e0ead)`: `docs/audit/evidence/phase9/wave0/full_unit_suite_wave0.txt` | 11 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (fcd8aaef)`: `docs/audit/09-improvement-plan.md` | 3 | `INTERNAL_IP_RFC1918` | `10****00` |
| `GIT_HISTORY (fcd8aaef)`: `docs/audit/10-improvement-roadmap.md` | 15 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/08b-reliability-performance.md` | 20 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/08b-reliability-performance.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/09-improvement-plan.md` | 41 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/09-improvement-plan.md` | 41 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/09-improvement-plan.md` | 124 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (ebceafd6)`: `docs/audit/evidence/cost-ledger.md` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (77965dad)`: `enchmark/p8/cleanup_p8.py` | 37 | `PASSWORD_ASSIGNMENT` | `pa****t(` |
| `GIT_HISTORY (77965dad)`: `enchmark/p8/cleanup_p8.py` | 86 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (77965dad)`: `enchmark/p8/test_runner_p8.py` | 73 | `PASSWORD_ASSIGNMENT` | `pa****t(` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 17 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 22 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 23 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 25 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 26 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 27 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 28 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 31 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 207 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/08b-reliability-performance.md` | 213 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (77965dad)`: `docs/audit/evidence/phase8/runner_live_output.txt` | 1562 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 8 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 9 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 12 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 37 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 37 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 39 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (054fe704)`: `docs/audit/evidence/phase8/8A-spec.md` | 55 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 1 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 2 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 2 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 3 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 3 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 3 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 4 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 4 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 5 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 5 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 6 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 8 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (aa7fa009)`: `docs/audit/08-findings-quality-assessment.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `enchmark/p7/test_runner_p7.py` | 936 | `PASSWORD_ASSIGNMENT` | `pa****d}` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 9 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 16 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 21 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 22 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 23 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 25 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 28 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 31 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 32 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 40 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 41 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 42 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 43 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 44 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 45 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 46 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 47 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 48 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 49 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 50 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 51 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 52 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 53 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 54 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 55 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 56 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 57 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 58 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 59 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 60 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 124 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 141 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (efb1c383)`: `docs/audit/08-findings-quality-assessment.md` | 142 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (715e08b2)`: `enchmark/p6b/hotfix_cleanup_and_demo_prep.py` | 29 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (715e08b2)`: `enchmark/p6b/hotfix_cleanup_and_demo_prep.py` | 30 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/00-master-prompt.md` | 1 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 308 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 309 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 316 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 317 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 324 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 325 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 332 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 333 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 340 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 341 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 348 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 349 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 356 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 357 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 364 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 365 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 372 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 373 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 380 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (715e08b2)`: `docs/audit/evidence/phase6/p6b_rerun_after_hotfix_rbac_matrix.json` | 381 | `WINDOWS_USER_PATH` | `/u****e3` |
| `GIT_HISTORY (f03ece7b)`: `docs/audit/00-master-prompt.md` | 1 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (f03ece7b)`: `docs/audit/07-security-assessment.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 2 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 3 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 74 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 104 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 104 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 104 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 104 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 137 | `WINDOWS_USER_PATH` | `/u****e7` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 139 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 139 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 144 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 144 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 156 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 159 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/07-security-assessment.md` | 160 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_prompt_injection_responses.json` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_prompt_injection_responses.json` | 38 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 333 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 334 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 341 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 342 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 349 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 350 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 357 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 358 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 365 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 366 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 373 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 374 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 381 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 382 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 389 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 390 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 397 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 398 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 405 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (c94e601c)`: `docs/audit/evidence/phase6/p6b_rbac_matrix.json` | 406 | `WINDOWS_USER_PATH` | `/u****84` |
| `GIT_HISTORY (be7cdf84)`: `ENVIRONMENTS.md` | 1 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `ENVIRONMENTS.md` | 2 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `enchmark/p6/cleanup_prod.py` | 1 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (be7cdf84)`: `enchmark/p6b/test_runner_p6b.py` | 139 | `PASSWORD_ASSIGNMENT` | `pw****c[` |
| `GIT_HISTORY (be7cdf84)`: `enchmark/p6b/test_runner_p6b.py` | 575 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `enchmark/p6b/test_runner_p6b.py` | 736 | `BEARER_TOKEN` | `Be****et` |
| `GIT_HISTORY (be7cdf84)`: `enchmark/p6b/test_runner_p6b.py` | 836 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/03-defect-register.md` | 3 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/03-defect-register.md` | 40 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/03-defect-register.md` | 44 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/03-defect-register.md` | 53 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/05-pentest-benchmark-results.md` | 1 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 7 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 8 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 9 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 10 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 11 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 12 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 85 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 85 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 85 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 114 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 118 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 119 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 121 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 155 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 155 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 156 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 177 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/07-security-assessment.md` | 177 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/10-improvement-roadmap.md` | 10 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (be7cdf84)`: `docs/audit/10-improvement-roadmap.md` | 12 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 13 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 33 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 45 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 46 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 48 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 49 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 51 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 51 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 72 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 79 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `ENVIRONMENTS.md` | 80 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `enchmark/p6/cleanup_prod.py` | 40 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `enchmark/p6/cleanup_prod.py` | 125 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (3e371f58)`: `enchmark/p6/cleanup_prod.py` | 126 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (3e371f58)`: `enchmark/p6/test_runner_prod.py` | 131 | `PASSWORD_ASSIGNMENT` | `pw****c[` |
| `GIT_HISTORY (3e371f58)`: `enchmark/p6/test_runner_prod.py` | 407 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 9 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 25 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 26 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 26 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 32 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 32 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 37 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (3e371f58)`: `docs/audit/07-security-assessment.md` | 51 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e682906a)`: `ENVIRONMENTS.md` | 32 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e682906a)`: `ENVIRONMENTS.md` | 48 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e682906a)`: `ENVIRONMENTS.md` | 65 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e682906a)`: `enchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/ground_truth_p6.yaml` | 72 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/p6/seed_sec_environment.py` | 127 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/p6/seed_sec_environment.py` | 127 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/p6/seed_sec_environment.py` | 172 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (e682906a)`: `enchmark/p6/test_runner.py` | 303 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 52 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 72 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 91 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 110 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 134 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 153 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 178 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 227 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 228 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 229 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 230 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 231 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 237 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a7807844)`: `docs/audit/evidence/phase5/5A-agent-inventory.md` | 240 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/replaced_scores/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (d529941a)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 3 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/05b-advanced-pentest-validation.md` | 11 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/05b-advanced-pentest-validation.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/05b-advanced-pentest-validation.md` | 24 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/05b-advanced-pentest-validation.md` | 86 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_crapi_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_juiceshop_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run1.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run2.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (33a482dd)`: `docs/audit/evidence/phase4/score_pentesa-bench_run3.txt` | 6 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (a8a4b1fc)`: `docs/audit/05b-advanced-pentest-validation.md` | 104 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (ffe530f9)`: `docs/audit/05-pentest-benchmark-results.md` | 120 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (ffe530f9)`: `docs/audit/05-pentest-benchmark-results.md` | 124 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (ffe530f9)`: `docs/audit/05-pentest-benchmark-results.md` | 124 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (1823e363)`: `.env.production.example` | 21 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (1823e363)`: `.env.production.example` | 21 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 29 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 29 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 48 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 48 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 101 | `INTERNAL_HOSTNAME` | `si****om` |
| `GIT_HISTORY (1823e363)`: `docs/ENVIRONMENTS.md` | 101 | `EMPLOYEE_EMAIL` | `ah****om` |
| `GIT_HISTORY (1823e363)`: `docs/audit/05-pentest-benchmark-results.md` | 50 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/findings_webgoat_baseline.json` | 33 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_crapi.json` | 1 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `PASSWORD_ASSIGNMENT` | `pa****an` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `PASSWORD_ASSIGNMENT` | `pa****br` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_dvwa.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_juiceshop.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `GIT_HISTORY (1823e363)`: `docs/audit/evidence/phase3/raw_nuclei_webgoat.json` | 1 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `GIT_HISTORY (55c0a099)`: `enchmark/setup_engagement_and_scope_check.py` | 39 | `INTERNAL_IP_RFC1918` | `19****50` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/b0_image_digests.txt` | 25 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/b0_image_digests.txt` | 210 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 34 | `INTERNAL_IP_RFC1918` | `19****50` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 37 | `INTERNAL_IP_RFC1918` | `17****.8` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 38 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 39 | `INTERNAL_IP_RFC1918` | `17****.7` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 40 | `INTERNAL_IP_RFC1918` | `17****.4` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 41 | `INTERNAL_IP_RFC1918` | `17****12` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 42 | `INTERNAL_IP_RFC1918` | `17****11` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 43 | `INTERNAL_IP_RFC1918` | `17****10` |
| `GIT_HISTORY (55c0a099)`: `docs/audit/evidence/phase3/scope_check_proof.txt` | 44 | `INTERNAL_IP_RFC1918` | `17****.9` |
| `GIT_HISTORY (f78ba05f)`: `docs/audit/03-defect-register.md` | 6 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (f78ba05f)`: `docs/audit/evidence/phase3/b0_preflight_checks.txt` | 39 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (f78ba05f)`: `docs/audit/evidence/phase3/b0_preflight_checks.txt` | 41 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (622db0f9)`: `enchmark/run_benchmark.py` | 338 | `INTERNAL_IP_RFC1918` | `17****10` |
| `GIT_HISTORY (622db0f9)`: `enchmark/run_benchmark.py` | 339 | `INTERNAL_IP_RFC1918` | `17****10` |
| `GIT_HISTORY (622db0f9)`: `enchmark/run_benchmark.py` | 340 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (622db0f9)`: `tests/unit/test_baseline_adapter.py` | 19 | `PASSWORD_ASSIGNMENT` | `pa****et` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 528 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 572 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 575 | `PASSWORD_ASSIGNMENT` | `pa****rd` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 599 | `PASSWORD_ASSIGNMENT` | `pa****ng` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 619 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 622 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 644 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 686 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `enchmark/ground_truth.yaml` | 689 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase2/15_api_contract.txt` | 71 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase2/15_api_contract.txt` | 88 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase2/r1_default_admin.txt` | 218 | `JWT_TOKEN` | `ey****64` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase2/r1_default_admin.txt` | 218 | `JWT_TOKEN` | `ey****A4` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase3/gt_verification.txt` | 66 | `PASSWORD_ASSIGNMENT` | `pa****in` |
| `GIT_HISTORY (afad8b16)`: `docs/audit/evidence/phase3/isolation_proof.txt` | 62 | `INTERNAL_IP_RFC1918` | `17****.3` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 58 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 59 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 111 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 112 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 133 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 134 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 164 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r1_real_stack.py` | 165 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (afad8b16)`: `tests/audit/run_r6_real_stack.py` | 67 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (afad8b16)`: `tests/fixtures/synthetic_benchmark_findings.json` | 167 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (afad8b16)`: `tests/fixtures/synthetic_benchmark_findings.json` | 168 | `BEARER_TOKEN` | `Be****9.` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/gitlab-detect.yaml` | 27 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/gitlab-saml.yaml` | 27 | `WINDOWS_USER_PATH` | `/u****th` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/google-adk-api-exposed.yaml` | 20 | `WINDOWS_USER_PATH` | `/u****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/huginn-panel.yaml` | 20 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/jumpserver-panel.yaml` | 29 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/metasploit-setup-page.yaml` | 33 | `WINDOWS_USER_PATH` | `/u****ew` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/misp-panel.yaml` | 30 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/osasi-panel.yaml` | 18 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/redhat/redhat-satellite-panel.yaml` | 22 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposed-panels/symantec/symantec-phishing-panel.yaml` | 22 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposures/configs/openvpn-as-config-exposure.yaml` | 31 | `PRIVATE_KEY` | `--****--` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/exposures/files/kubernetes-etcd-keys.yaml` | 26 | `PRIVATE_KEY` | `--****--` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/cluster-trino-admin-login.yaml` | 24 | `PASSWORD_ASSIGNMENT` | `pa****h=` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/dragonfly-public-signup.yaml` | 17 | `PASSWORD_ASSIGNMENT` | `pa****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/dragonfly-public-signup.yaml` | 23 | `WINDOWS_USER_PATH` | `/u****up` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/genieacs-default-jwt.yaml` | 28 | `JWT_TOKEN` | `ey****6c` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitea-userenum.yaml` | 21 | `WINDOWS_USER_PATH` | `/u****ml` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitlab/gitlab-api-user-enum.yaml` | 18 | `WINDOWS_USER_PATH` | `/u****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitlab/gitlab-public-signup.yaml` | 19 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitlab/gitlab-public-signup.yaml` | 20 | `WINDOWS_USER_PATH` | `/u****up` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitlab/gitlab-public-signup.yaml` | 28 | `WINDOWS_USER_PATH` | `/u****up` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/gitlab/gitlab-uninitialized-password.yaml` | 23 | `WINDOWS_USER_PATH` | `/u****in` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/jellyfin-public-users-exposure.yaml` | 26 | `WINDOWS_USER_PATH` | `/U****ic` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/jellyfin-public-users-exposure.yaml` | 27 | `WINDOWS_USER_PATH` | `/U****ic` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/laravel-passport-keys-exposed.yaml` | 31 | `PRIVATE_KEY` | `--****--` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/nacos-authentication-bypass.yaml` | 25 | `JWT_TOKEN` | `ey****6g` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/nacos/nacos-create-user.yaml` | 22 | `JWT_TOKEN` | `ey****6g` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/nacos/nacos-create-user.yaml` | 27 | `PASSWORD_ASSIGNMENT` | `pa****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/nacos/nacos-create-user.yaml` | 27 | `WINDOWS_USER_PATH` | `/u****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/nacos/nacos-create-user.yaml` | 35 | `WINDOWS_USER_PATH` | `/u****}}` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/misconfiguration/trino-unauth-cluster.yaml` | 23 | `PASSWORD_ASSIGNMENT` | `pa****h=` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/technologies/fingerprinthub-web-fingerprints.yaml` | 10873 | `PASSWORD_ASSIGNMENT` | `pa****or` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/technologies/wordpress/plugins/wordpress-plugin-detect.yaml` | 52289 | `SK_KEY` | `sk****ha` |
| `GIT_HISTORY (79872869)`: `integrations/nuclei/templates/technologies/wordpress/plugins/wordpress-plugin-detect.yaml` | 52291 | `SK_KEY` | `sk****ha` |
| `GIT_HISTORY (bf709077)`: `docs/audit/evidence/phase2/2A-addendum.md` | 16 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v3_verification.py` | 49 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v4_verification.py` | 25 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v4_verification.py` | 69 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v4_verification.py` | 88 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v4_verification.py` | 89 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (bf709077)`: `tests/audit/run_v7_verification.py` | 50 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (aac2f64f)`: `tests/unit/test_lab_only_tool_guard.py` | 53 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (aac2f64f)`: `tests/unit/test_lab_only_tool_guard.py` | 80 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (b9909a20)`: `docs/audit/evidence/phase2/2A-addendum.md` | 79 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (b9909a20)`: `docs/audit/evidence/phase2/2A-addendum.md` | 79 | `INTERNAL_IP_RFC1918` | `17****99` |
| `GIT_HISTORY (b9909a20)`: `docs/audit/evidence/phase2/2A-addendum.md` | 81 | `INTERNAL_IP_RFC1918` | `17****99` |
| `GIT_HISTORY (b9909a20)`: `docs/audit/evidence/phase2/2A-addendum.md` | 133 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (b9909a20)`: `docs/audit/evidence/phase2/2A-addendum.md` | 134 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a709a7ca)`: `database/seeds/seed_data.py` | 9 | `PASSWORD_ASSIGNMENT` | `pa****r)` |
| `GIT_HISTORY (e888ab16)`: `tests/unit/test_safe_redirect_loop.py` | 152 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (efbcd1ba)`: `docs/audit/03-defect-register.md` | 41 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (efbcd1ba)`: `docs/audit/03-defect-register.md` | 43 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (efbcd1ba)`: `docs/audit/evidence/phase2/part2a_results.json` | 68 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 5 | `JWT_TOKEN` | `ey****yY` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 7 | `JWT_TOKEN` | `ey****yY` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 7 | `BEARER_TOKEN` | `Be****yY` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 12 | `JWT_TOKEN` | `ey****4E` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 14 | `JWT_TOKEN` | `ey****4E` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 14 | `BEARER_TOKEN` | `Be****4E` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 19 | `JWT_TOKEN` | `ey****ko` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 21 | `JWT_TOKEN` | `ey****ko` |
| `GIT_HISTORY (a1af61fa)`: `data/juiceshop_users.json` | 21 | `BEARER_TOKEN` | `Be****ko` |
| `GIT_HISTORY (a1af61fa)`: `docker-compose.phase2.yml` | 58 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `docker-compose.phase2.yml` | 59 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (a1af61fa)`: `docker-compose.phase2.yml` | 97 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `docker-compose.phase2.yml` | 98 | `SK_KEY` | `sk****QA` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/00-preflight-report.md` | 14 | `WINDOWS_USER_PATH` | `/u****me` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/00-preflight-report.md` | 14 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 17 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 29 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 73 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 74 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 83 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 95 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 99 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 105 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 105 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 118 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 119 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 190 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 196 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 200 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 206 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 220 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 220 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 220 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 222 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 226 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 232 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 238 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 249 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 250 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 251 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 252 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 253 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 254 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/2A-checkpoint.md` | 255 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/cost-log.md` | 4 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/cost-log.md` | 35 | `INTERNAL_HOSTNAME` | `ua****om` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 21 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 139 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 143 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 152 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 156 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 312 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 315 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 332 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 349 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 460 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `docs/audit/evidence/phase2/part2a_results.json` | 461 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 113 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 277 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 281 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 287 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 291 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 293 | `INTERNAL_IP_RFC1918` | `17****.5` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 300 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 304 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 306 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (a1af61fa)`: `scripts/part2a_runner.py` | 978 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (2eb3308d)`: `README.md` | 27 | `WINDOWS_USER_PATH` | `/u****me` |
| `GIT_HISTORY (2eb3308d)`: `scripts/smoke_test.py` | 10 | `WINDOWS_USER_PATH` | `/u****e)` |
| `GIT_HISTORY (2eb3308d)`: `scripts/smoke_test.py` | 129 | `WINDOWS_USER_PATH` | `/u****me` |
| `GIT_HISTORY (2eb3308d)`: `scripts/smoke_test.py` | 132 | `WINDOWS_USER_PATH` | `/u****e)` |
| `GIT_HISTORY (2eb3308d)`: `scripts/smoke_test.py` | 134 | `WINDOWS_USER_PATH` | `/u****e)` |
| `GIT_HISTORY (c4acb06a)`: `tests/unit/test_credential_encryption_and_redaction.py` | 109 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (c4acb06a)`: `tests/unit/test_credential_encryption_and_redaction.py` | 177 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (c4acb06a)`: `tests/unit/test_credential_encryption_and_redaction.py` | 196 | `BEARER_TOKEN` | `Be****78` |
| `GIT_HISTORY (c4acb06a)`: `tests/unit/test_credential_encryption_and_redaction.py` | 223 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (a9934ce9)`: `docs/24-enterprise-ui-ux-redesign-spec.md` | 38 | `WINDOWS_USER_PATH` | `C:****r2` |
| `GIT_HISTORY (776fb602)`: `agents/authorization/authz_agent.py` | 59 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (776fb602)`: `apps/web/src/app/projects/page.tsx` | 60 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (776fb602)`: `docs/22-production-deployment-guide.md` | 1 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (776fb602)`: `docs/22-production-deployment-guide.md` | 1 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (776fb602)`: `docs/23-end-to-end-testing-tutorial.md` | 44 | `WINDOWS_USER_PATH` | `c:****r2` |
| `GIT_HISTORY (776fb602)`: `docs/23-end-to-end-testing-tutorial.md` | 54 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (776fb602)`: `docs/23-end-to-end-testing-tutorial.md` | 107 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (776fb602)`: `docs/23-end-to-end-testing-tutorial.md` | 453 | `INTERNAL_IP_RFC1918` | `17****.0` |
| `GIT_HISTORY (776fb602)`: `scripts/dummy_vuln_server.py` | 23 | `WINDOWS_USER_PATH` | `/u****1<` |
| `GIT_HISTORY (776fb602)`: `scripts/dummy_vuln_server.py` | 57 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (776fb602)`: `scripts/verify_deployment.py` | 74 | `PASSWORD_ASSIGNMENT` | `pa****rd` |
| `GIT_HISTORY (776fb602)`: `tests/unit/test_findings_management.py` | 113 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (776fb602)`: `tests/unit/test_scope_engine.py` | 36 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (776fb602)`: `tests/unit/test_scope_engine.py` | 43 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (776fb602)`: `tests/unit/test_scope_engine.py` | 53 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `GIT_HISTORY (b5c82c37)`: `agents/authorization/authz_agent.py` | 8 | `WINDOWS_USER_PATH` | `/u****02` |
| `GIT_HISTORY (b5c82c37)`: `agents/authorization/authz_agent.py` | 10 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (b5c82c37)`: `agents/authorization/authz_agent.py` | 10 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (b5c82c37)`: `agents/llm/provider.py` | 25 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (b5c82c37)`: `agents/llm/provider.py` | 33 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (6217944e)`: `apps/web/src/app/projects/page.tsx` | 374 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (6217944e)`: `docs/23-end-to-end-testing-tutorial.md` | 19 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (6217944e)`: `docs/23-end-to-end-testing-tutorial.md` | 115 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 106 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 145 | `WINDOWS_USER_PATH` | `/u****1<` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 216 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 255 | `URL_CREDENTIAL` | `po****!@` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 255 | `INTERNAL_IP_RFC1918` | `10****45` |
| `GIT_HISTORY (6217944e)`: `scripts/dummy_vuln_server.py` | 300 | `WINDOWS_USER_PATH` | `/u****/1` |
| `GIT_HISTORY (e7033f56)`: `docs/22-production-deployment-guide.md` | 80 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e7033f56)`: `docs/22-production-deployment-guide.md` | 191 | `SK_KEY` | `sk****xx` |
| `GIT_HISTORY (e7033f56)`: `docs/22-production-deployment-guide.md` | 216 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e7033f56)`: `docs/22-production-deployment-guide.md` | 264 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e7033f56)`: `docs/22-production-deployment-guide.md` | 269 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (e7033f56)`: `tests/integration/test_e2e_workflow.py` | 43 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (e7033f56)`: `tests/performance/test_performance_benchmarks.py` | 73 | `BEARER_TOKEN` | `Be****90` |
| `GIT_HISTORY (e7033f56)`: `tests/security/test_security_hardening.py` | 36 | `WINDOWS_USER_PATH` | `/u****st` |
| `GIT_HISTORY (e7033f56)`: `tests/security/test_security_hardening.py` | 39 | `WINDOWS_USER_PATH` | `/u****..` |
| `GIT_HISTORY (e7033f56)`: `tests/security/test_security_hardening.py` | 56 | `BEARER_TOKEN` | `Be****90` |
| `GIT_HISTORY (999da385)`: `.env.example` | 11 | `SK_KEY` | `sk****ey` |
| `GIT_HISTORY (999da385)`: `agents/authorization/authz_agent.py` | 45 | `WINDOWS_USER_PATH` | `/u****02` |
| `GIT_HISTORY (999da385)`: `agents/llm/provider.py` | 136 | `WINDOWS_USER_PATH` | `/u****02` |
| `GIT_HISTORY (999da385)`: `tests/unit/test_llm_provider.py` | 126 | `SK_KEY` | `sk****yz` |
| `GIT_HISTORY (999da385)`: `tests/unit/test_llm_provider.py` | 143 | `SK_KEY` | `sk****yz` |
| `GIT_HISTORY (999da385)`: `tests/unit/test_llm_provider.py` | 143 | `BEARER_TOKEN` | `Be****yz` |
| `GIT_HISTORY (999da385)`: `tests/unit/test_specialized_agents.py` | 102 | `WINDOWS_USER_PATH` | `/u****02` |
| `GIT_HISTORY (32b1c35d)`: `tests/integration/test_discovery_api.py` | 65 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (32b1c35d)`: `tests/integration/test_discovery_api.py` | 83 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (32b1c35d)`: `tests/integration/test_tools_api.py` | 145 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_evidence_engine.py` | 27 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_evidence_engine.py` | 45 | `BEARER_TOKEN` | `Be****Dc` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_evidence_engine.py` | 101 | `BEARER_TOKEN` | `Be****yz` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_evidence_engine.py` | 142 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_http_testing.py` | 54 | `BEARER_TOKEN` | `Be****45` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_parameter_extraction.py` | 100 | `WINDOWS_USER_PATH` | `/u****42` |
| `GIT_HISTORY (32b1c35d)`: `tests/unit/test_parameter_extraction.py` | 102 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (a5d5c843)`: `services/discovery_engine/extractor.py` | 155 | `WINDOWS_USER_PATH` | `/u****42` |
| `GIT_HISTORY (a5d5c843)`: `services/discovery_engine/extractor.py` | 155 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (2e2f7b01)`: `packages/common/security.py` | 13 | `PASSWORD_ASSIGNMENT` | `pa****r)` |
| `GIT_HISTORY (2e2f7b01)`: `packages/schemas/scope.py` | 14 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (2e2f7b01)`: `packages/schemas/scope.py` | 15 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `GIT_HISTORY (2e2f7b01)`: `services/scope_engine/validator.py` | 92 | `INTERNAL_IP_RFC1918` | `19****.1` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_audit_chain.py` | 34 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_audit_chain.py` | 44 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_scope_engine.py` | 197 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_scope_engine.py` | 202 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_scope_engine.py` | 208 | `INTERNAL_IP_RFC1918` | `10****.5` |
| `GIT_HISTORY (2e2f7b01)`: `tests/unit/test_security_rbac.py` | 20 | `PASSWORD_ASSIGNMENT` | `pw****3!` |
| `GIT_HISTORY (84ed2938)`: `docs/21-architecture-review-report.md` | 2 | `WINDOWS_USER_PATH` | `fi****r2` |
| `GIT_HISTORY (2320883c)`: `docs/08-scope-enforcement.md` | 22 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (2320883c)`: `docs/08-scope-enforcement.md` | 22 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (1d2ad883)`: `docs/02-srs.md` | 170 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****42` |
| `GIT_HISTORY (1d2ad883)`: `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****99` |
| `GIT_HISTORY (1d2ad883)`: `docs/03-system-architecture.md` | 181 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (1d2ad883)`: `docs/04-agent-architecture.md` | 265 | `WINDOWS_USER_PATH` | `/u****te` |
| `GIT_HISTORY (1d2ad883)`: `docs/05-agent-specifications.md` | 118 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/05-agent-specifications.md` | 153 | `INTERNAL_IP_RFC1918` | `19****45` |
| `GIT_HISTORY (1d2ad883)`: `docs/05-agent-specifications.md` | 182 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (1d2ad883)`: `docs/05-agent-specifications.md` | 183 | `INTERNAL_IP_RFC1918` | `19****11` |
| `GIT_HISTORY (1d2ad883)`: `docs/08-scope-enforcement.md` | 55 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/08-scope-enforcement.md` | 66 | `INTERNAL_IP_RFC1918` | `19****54` |
| `GIT_HISTORY (1d2ad883)`: `docs/08-scope-enforcement.md` | 204 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (1d2ad883)`: `docs/08-scope-enforcement.md` | 259 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (1d2ad883)`: `docs/08-scope-enforcement.md` | 271 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (1d2ad883)`: `docs/10-database-design.md` | 159 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/10-database-design.md` | 213 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (1d2ad883)`: `docs/11-api-specification.md` | 217 | `INTERNAL_IP_RFC1918` | `19****10` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 201 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 223 | `WINDOWS_USER_PATH` | `/u****rt` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 224 | `INTERNAL_IP_RFC1918` | `19****14` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 232 | `INTERNAL_IP_RFC1918` | `19****.0` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 249 | `WINDOWS_USER_PATH` | `/u****d}` |
| `GIT_HISTORY (1d2ad883)`: `docs/12-ui-ux-specification.md` | 297 | `INTERNAL_IP_RFC1918` | `19****14` |
| `GIT_HISTORY (1d2ad883)`: `docs/13-security-requirements.md` | 128 | `INTERNAL_IP_RFC1918` | `10****.1` |
| `GIT_HISTORY (1d2ad883)`: `docs/diagrams/scope-validation-flow.mermaid` | 14 | `INTERNAL_IP_RFC1918` | `10****.0` |
| `GIT_HISTORY (1d2ad883)`: `skills/scope-validation/SKILL.md` | 38 | `INTERNAL_IP_RFC1918` | `19****10` |
