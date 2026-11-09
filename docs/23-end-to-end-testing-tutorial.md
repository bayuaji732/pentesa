# Pentesa End-to-End Testing Tutorial & Vulnerable Target Guide

This tutorial provides a complete step-by-step walkthrough to test all features of **Pentesa**—from onboarding an engagement and configuring scope guards to multi-agent scanning, empirical patch retests, and cryptographic report generation.

---

## 1. Vulnerable Testing Targets (Dummy Servers & Testbeds)

Pentesa can be tested against three different types of targets depending on your network setup:

### Option A: Built-in Local Dummy Vulnerable Server (Recommended for Fast, Offline Testing)
A dedicated, lightweight, intentional vulnerable web application is included directly in this repository:
[`scripts/dummy_vuln_server.py`](../scripts/dummy_vuln_server.py).

It runs on **`http://127.0.0.1:9000`** with zero external setup, providing:
- **Web Crawler Surface:** `robots.txt`, `sitemap.xml`, and navigation HTML links.
- **SQL Injection (SQLi / WSTG-INPV-05):** `GET /products?search=' OR 1=1--`
- **Reflected XSS (WSTG-INPV-01):** `GET /search?q=<script>alert(1)</script>`
- **IDOR / BOLA (WSTG-ATHZ-02):** `GET /api/v1/users/1` leaking sensitive API keys
- **Information Disclosure (WSTG-INFO-05):** `GET /debug/config` leaking database credentials & AWS keys
- **Interactive Patch Switch:** Endpoints `GET /patch/toggle-sqli` and `GET /patch/toggle-xss` allow you to toggle the security fix ON/OFF to test Pentesa's **Empirical Retest Engine** in real-time!

### Option B: Public Benchmark Target (Online Testing)
- **Target URL:** `http://testphp.vulnweb.com`
- **Description:** Acunetix's official legal public testbed for web vulnerability scanners.

### Option C: Docker Vulnerable Targets (Juice Shop / DVWA)
If you have Docker installed, you can launch industry-standard targets:
```bash
# OWASP Juice Shop (Modern Angular/Node API)
docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop

# Damn Vulnerable Web App (DVWA - PHP/MySQL)
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

---

## 2. Step-by-Step Testing Walkthrough

### Step 1: Launch Services

Open three terminal windows (PowerShell or Bash):

#### Terminal 1 — FastAPI Backend (Port 8000)
```powershell
# In repository root
.venv\Scripts\activate
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload
```
*Verify: Open `http://127.0.0.1:8000/healthz` (returns `{"status":"ok"}`).*

#### Terminal 2 — Next.js Operations Console (Port 3000)
```powershell
cd apps/web
npm run dev
```
*Verify: Open `http://localhost:3000`.*

#### Terminal 3 — Local Dummy Vulnerable Target (Port 9000)
```powershell
.venv\Scripts\python.exe scripts/dummy_vuln_server.py
```
*Verify: Open `http://127.0.0.1:9000` in browser to see the Acme Corporate Portal testbed.*

---

### Step 2: Sign In to Pentesa Operations Console

1. Navigate to **`http://localhost:3000/login`**.
2. Enter the default administrator credentials:
   - **Email:** `admin@example.com`
   - **Password:** `Admin123!Secure`
3. Click **Authenticate & Open Console**. You will be redirected to the Executive Dashboard.

---

### Step 3: Register & Authorize Engagement (`/projects`)

1. Click **Projects** in the sidebar (or navigate to `http://localhost:3000/projects`).
2. Click the **+ New Engagement** button in the top right.
3. Fill in the authorization parameters:
   - **Engagement Name:** `Local Sandbox Assessment`
   - **Description:** `Automated penetration test against local Acme dummy target`
   - **Target In-Scope Domains:** `127.0.0.1` (or `testphp.vulnweb.com` if using Option B)
   - **Allowed CIDRs:** `127.0.0.1/32`
   - **Excluded Paths:** `/logout, /admin/reset`
   - **RoE Authorization Ref:** `ROE-2026-LOCAL-001`
   - **Authorization Dates:** Today to 30 days ahead (pre-filled)
   - **Private Network Checkbox:** Check **`Allow Testing of RFC1918 Private Internal Networks`** *(Crucial for testing localhost/127.0.0.1).*
4. Click **Authorize Engagement**.
5. Click **Switch to Project** to make it your active context.

---

### Step 4: Configure & Validate Scope Boundaries (`/scope`)

1. Click **Scope & Boundaries** in the sidebar.
2. In the **Live Scope Boundary Evaluator** at the top right:
   - Enter: `http://127.0.0.1:9000/products` and click **Evaluate Target**.
     - **Result:** Green badge `IN SCOPE (Passed)`.
   - Enter: `https://google.com` or `https://internal-bank.corp` and click **Evaluate Target**.
     - **Result:** Red badge `BLOCKED (Out of Scope)` with cryptographic violation reason.
3. You can also click **+ Add Scope Rule** to add specific regex patterns or exclude critical paths.

---

### Step 5: Execute Attack Surface Discovery (`/discovery`)

1. Click **Attack Surface** in the sidebar.
2. Click **Launch Attack Surface Crawler**.
3. Set Max Crawl Depth = `2`, Max Pages = `25`, and click **Start Crawler**.
4. Observe the inventory populated:
   - **Discovered Subdomains:** `127.0.0.1`
   - **Endpoints Inventory:** `/products`, `/search`, `/debug/config`, `/api/v1/users/{id}`, `robots.txt`, `sitemap.xml`.
   - **Technology Stack:** Python, FastAPI, Uvicorn, SQLite.

---

### Step 6: Review & Trigger OWASP WSTG Matrix (`/wstg`)

1. Click **OWASP WSTG Plan** in the sidebar.
2. Review the 106-item test catalog across categories:
   - `INPV`: Input Validation Testing (SQLi, XSS, Command Injection)
   - `ATHZ`: Authorization Testing (IDOR / BOLA)
   - `INFO`: Information Gathering (robots.txt, metadata, configuration leakage)
3. Click **Recalculate Dynamic Plan** to re-index the plan against the discovered endpoints.

---

### Step 7: Launch Multi-Agent Autonomous Swarm (`/agents`)

1. Click **Multi-Agent DAG** in the sidebar.
2. Review the visualized pipeline: `Discovery → Recon → Vulnerability Scan → Exploit Validation → Reporting`.
3. In the control panel, click **Start Swarm**:
   - The agents start autonomously executing tool workflows.
   - Watch the active agent status indicators change from `IDLE` to `ACTIVE`.
   - Watch the **Token Burn & Telemetry** counter update with prompt tokens, completion tokens, and dollar cost.
   - The **Live Agent Thought Trace Terminal** streams the internal decision-making rationale (hypotheses, intent, tool selection).

---

### Step 8: Triage Findings, Inspect Forensic Evidence & Retest (`/findings`)

1. Click **Findings & Retest** in the sidebar.
2. Click on a finding (e.g. **SQL Injection in /products** or **Sensitive Debug Config Exposure**).
3. The right-side **Forensic Evidence Suite** drawer opens:
   - **Raw HTTP Request & Response:** Click the tabs to inspect exact streams.
   - **Reproducible cURL:** Copy and paste the command into your terminal to reproduce the exploit manually.
   - **Cryptographic Hashes:** Inspect the SHA-256 request and response digests.
4. **Test the Empirical Patch Retest Engine:**
   - In Pentesa, click **Verify Fix** in the Empirical Patch Retest panel.
     - **Result:** `✘ Vulnerable (Exploit Succeeded) - HTTP 200`.
   - Now simulate a developer fixing the bug: Open `http://127.0.0.1:9000/patch/toggle-sqli` in your browser.
     - The dummy server returns: `{"message": "SQL Injection is now PATCHED"}`.
   - Go back to Pentesa and click **Verify Fix** again:
     - **Result:** `✔ Remediated (Vulnerability Closed) - HTTP 403 / Clean Response`!
5. **Test Deduplication:**
   - Click **Deduplication Clusters** to view findings grouped by `SHA256(project_id || path || method || param || cwe)`.

---

### Step 9: Compile Formal PTES Report (`/reports`)

1. Click **PTES Reports** in the sidebar.
2. In the **Compile Formal PTES Report** panel:
   - Choose **PDF (Print-Ready)** or **HTML (Interactive)**.
   - Enter a title: `Acme Corp Penetration Testing Deliverable`.
   - Keep "Attach Raw HTTP Forensic Streams & cURL" checked.
   - Click **Generate & Publish Report**.
3. When generated, click **Download** to inspect the compiled document containing:
   - Executive summary and CVSS risk metrics.
   - Scope authorization RoE certificates.
   - OWASP WSTG testing coverage breakdown.
   - Forensic evidence with curl commands.
   - Digital cryptographic seal.
4. **Test Seal Verification:**
   - Copy the SHA-256 seal from the report card.
   - Paste it into the **Cryptographic Seal Verification** tool on the left and click **Verify Integrity Seal**.
   - Verification status: `✔ Cryptographic Seal Verified`.

---

### Step 10: Verify Cryptographic Audit Chain (`/audit-logs`)

1. Click **Audit Hash Chain** in the sidebar.
2. Review the immutable audit log table:
   - Notice every operation (`PROJECT_CREATED`, `SCOPE_RULE_CREATED`, `CRAWL_STARTED`, `FINDING_CREATED`, `REPORT_GENERATED`) has a linked hash: `prev_hash → hash`.
3. Click **Inspect Payload** on any row to view the serialized JSON delta of what changed.
4. Check the top banner:
   - Click **Re-verify Chain** to trigger mathematical validation from genesis block to head.
   - Status: `● Cryptographic Hash Chain Valid: All entries verified`.
5. Click **Export Signed Ledger** to download the JSON compliance audit trail.

---

## 3. Automated Command-Line Testing (Pytest Suite)

To run the complete automated test suite covering all 7 phases:
```powershell
# Run all 134 tests with verbose output
pytest -v

# Run only the full end-to-end integration lifecycle test
pytest tests/integration/test_e2e_workflow.py -v

# Run performance and latency benchmarks
pytest tests/performance/test_performance_benchmarks.py -v

# Run security hardening and RBAC tests
pytest tests/security/test_security_hardening.py -v
```

