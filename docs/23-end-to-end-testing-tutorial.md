# Pentesa End-to-End Testing Tutorial & Vulnerable Target Guide

This tutorial provides a complete, step-by-step walkthrough for testing every capability of **Pentesa** using **real LiteLLM inference** (no mock LLM responses and no pre-filled dummy UI values) across both local development and Dockerized deployments:

1. **Section 1 — Local Development Mode:** Running FastAPI (`uvicorn`), Next.js (`apps/web`), and Option A (`scripts/dummy_vuln_server.py`) locally.
2. **Transition — Local Dev to All-Dockerized Production:** Stopping local dev processes, validating `.env.production`, and booting the 5-container production stack (`pentesa-api`, `pentesa-worker`, `pentesa-web`, `pentesa-db`, `pentesa-redis`).
3. **Section 1B — Running Section 1 (Option A) From Dockerized Pentesa:** Testing Option A with Pentesa running in Docker—both in **Hybrid Mode** (`pentesa` in Docker + local `dummy_vuln_server.py` via `host.docker.internal:9000`) and **All-Dockerized Option A** (`dummy_vuln_server.py` running in a container on `pentesa-internal`).
4. **Section 2 — All-Dockerized Production + Option B:** Scanning public legal benchmark target `http://demo.testfire.net` *(Altoro Mutual — plain HTTP over port 80; requires outbound internet access)*, or optional HTTPS alternative `https://ginandjuice.shop/`.
5. **Section 3 — All-Dockerized Production + Option C:** Scanning containerized vulnerable apps (**OWASP Juice Shop**, **DVWA**) directly on the `pentesa-internal` Docker network—ideal for isolated or restricted corporate networks.
6. **Section 4 — Docker Networking Guide & Future Pitfalls When Services Are Dockerized:** Fixing cross-network (`internal Docker` vs `host` vs `external Compose`) connectivity and avoiding common production Docker networking issues.

---

## Operational Prerequisites & Production Baseline

Before starting any walkthrough, note how Pentesa behaves in live production mode:

- **Real LiteLLM Engine Only:** Both `.env` (local dev) and `.env.production` (Docker prod) must set `PENTESA_LLM_PROVIDER=litellm` along with your `PENTESA_LITELLM_BASE_URL`, `PENTESA_LITELLM_API_KEY`, and `PENTESA_LITELLM_MODEL` (e.g., `azure/gpt-5.6-terra-dev-gtw`). Note that `MockLLMProvider` is strictly blocked whenever `PENTESA_ENV=production`.
- **Blank Console Inputs:** All forms in the Operations Console (`/login`, `/projects`, `/scope`, `/discovery`, `/reports`) intentionally start blank (`""`) with placeholder hints only—you enter real values for every engagement.
- **Seeded Login Account Only:** Bootstrapping provisions one administrator user with zero sample engagements (`PENTESA_SEED_DEMO_PROJECT` disabled by default):
  - **Operator Email:** Configured bootstrap admin email (e.g. from `PENTESA_BOOTSTRAP_ADMIN_EMAIL`)
  - **Master Secret Password:** Configured bootstrap admin password (from `PENTESA_BOOTSTRAP_ADMIN_PASSWORD`)

### Autonomous Scan Profiles (`/agents`)

| Profile | Typical Duration | Behavior |
| :--- | :--- | :--- |
| **`⚡ Quick Scan`** | ~10–25s | Live LiteLLM reasoning across all 7 DAG agents, `robots.txt`/`sitemap.xml` discovery, up to 5 WSTG probes, safe diagnostic exposure checks (`/debug/config`, `/.git/config`, `/.env`), security header audit, and IDOR/BOLA check. |
| **`🛡️ Full Scan`** | ~20–45s | Everything in Quick Scan + up to 15 WSTG probes + active error-based SQLi (`' OR '1'='1`) and Reflected XSS probes on discovered/parameterized routes. When **`Auto-Approve Medium`** is unchecked, pauses cleanly at `WAITING_APPROVAL` for operator Human-in-the-Loop sign-off. |
| **`🔬 Deep Scan`** | ~30–60s+ | Everything in Full Scan + up to 30 WSTG probes + extended Nuclei tags (`cve, misconfig, exposure, sqli, xss`) + `ffuf` directory fuzzing + HITL gate support. |

---

## Section 1: Local Development End-to-End Walkthrough (Option A)

Use Option A ([`scripts/dummy_vuln_server.py`](../scripts/dummy_vuln_server.py)) to test the full autonomous workflow end-to-end against deterministic, toggleable vulnerabilities before deploying containers.

### Step 1.1: Prepare Local Environment & Free Ports `3000`, `8000`, `9000`

1. If the Docker production stack is running from an earlier session, stop it so local ports are free:
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml down
   ```
2. Ensure `.env` exists at repository root (copy from `.env.example` if needed) and configure your live LiteLLM gateway *(never commit `.env`)*:
   - `PENTESA_ENV=development`
   - `PENTESA_LLM_PROVIDER=litellm`
   - `PENTESA_LITELLM_BASE_URL=<your-litellm-gateway-v1-url>`
   - `PENTESA_LITELLM_API_KEY=<your-litellm-api-key>`
   - `PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw`
3. Seed local database tables (106 OWASP WSTG tests + admin account) and verify LiteLLM authentication:
   ```powershell
   .venv\Scripts\python.exe -m database.seeds.seed_data
   .venv\Scripts\python.exe scripts/verify_deployment.py
   ```
   Confirm **`[PASS] LLM Provider`**, **`[PASS] LiteLLM Gateway`**, and **`[PASS] OWASP WSTG Catalog`** (`106/106`).

### Step 1.2: Launch Local Services (3 Terminals)

Open three PowerShell terminals in the repository root (`c:\Users\User2\Documents\work\pentesa`):

#### Terminal 1 — FastAPI Core Backend (Port `8000`)
```powershell
.venv\Scripts\activate
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload
```
*Verify in browser or curl:* `http://127.0.0.1:8000/healthz` returns `{"status":"ok","service":"pentesa-api"}`.

#### Terminal 2 — Next.js SOC Operations Console (Port `3000`)
```powershell
npm run dev --prefix apps/web
```
*Verify:* `http://localhost:3000/login` loads the **PENTESA SOC CONSOLE** login form.

#### Terminal 3 — Option A Local Vulnerable Target Server (Port `9000`)
```powershell
.venv\Scripts\python.exe scripts/dummy_vuln_server.py
```
*Verify:* Open `http://127.0.0.1:9000/` in a browser to see **Acme Corporate Portal (Pentesa Authorized Target)** exposing:
- `/products?search=...` — SQL Injection (`CWE-89` / `WSTG-INPV-05`)
- `/search?q=...` — Reflected XSS (`CWE-79` / `WSTG-INPV-01`)
- `/api/v1/users/1` — IDOR / BOLA API Key Leak (`CWE-639` / `WSTG-ATHZ-04`)
- `/debug/config` — Credentials & `.env` Exposure (`CWE-200` / `WSTG-INFO-05`)
- `/patch/toggle-sqli`, `/patch/toggle-xss`, `/patch/toggle-idor` — Live Patch Toggles for Empirical Retesting

### Step 1.3: Sign In (`/login`)

1. Navigate to **`http://localhost:3000/login`**.
2. Enter:
   - **Operator Email:** Your configured bootstrap administrator email
   - **Master Secret Password:** Your configured bootstrap administrator password
3. Click **`Sign In to Operations Console`**.

### Step 1.4: Authorize Engagement (`/projects`)

1. Click **`Projects`** in the left sidebar (`Platform Operations`).
2. Click **`New Engagement`** in the top right.
3. Fill in the modal fields manually:
   - **Engagement Name \*:** `Local Sandbox Assessment`
   - **Description:** `Local end-to-end test against Acme target using live LiteLLM`
   - **Target In-Scope Domains \* (comma-separated):** `127.0.0.1`
   - **Allowed CIDRs:** `127.0.0.1/32`
   - **Excluded Paths:** `/logout, /admin/reset`
   - **RoE Authorization Document Ref \*:** `ROE-2026-LOCAL-001`
   - **Authorization Start \* / Authorization End \*:** Keep valid authorization dates
   - **Private Network Checkbox:** Check **`Allow Testing of RFC1918 Private Internal Networks`** *(mandatory for loopback/private hosts such as `127.0.0.1`)*.
4. Click **`Authorize Engagement`**. The project becomes your `ACTIVE CONTEXT` (for existing projects, click **`Switch to Project`**).

### Step 1.5: Add Port `9000` Scope Rule & Test Boundaries (`/scope`)

> [!IMPORTANT]
> Newly created domain/IP scope rules default to HTTP/HTTPS standard ports (`80, 443`). Because Option A listens on port `9000`, you **must** add a port-scoped rule allowing `9000`.

1. Click **`Scope & Boundaries`** in the sidebar.
2. In **`Add Authorized Boundary Rule`**:
   - **Target Pattern:** `127.0.0.1`
   - **Rule Type:** `EXACT_IP`
   - **Target Type:** `IN_SCOPE (Allow)`
   - **Port Range (Optional):** `9000`
   - Click **`Add Rule`**.
3. Verify in **`Interactive Scope Boundary Tester`**:
   - Enter `http://127.0.0.1:9000/products` -> click **`Evaluate Scope`** -> green **`IN-SCOPE`**.
   - Enter `https://example.com` -> click **`Evaluate Scope`** -> red **`OUT OF SCOPE / BLOCKED`**.
   - Enter `http://169.254.169.254/latest/meta-data/` -> click **`Evaluate Scope`** -> red **`OUT OF SCOPE / BLOCKED`** (IMDS is unconditionally blocked).

### Step 1.6: Execute Attack Surface Discovery (`/discovery`)

1. Click **`Attack Surface`** in the sidebar.
2. In **`Automated Scope-Enforced Web Crawler`**:
   - **Target URL:** `http://127.0.0.1:9000/` *(or leave blank to auto-detect from your port `9000` rule)*
   - **Depth:** `2`
   - **Max Pages:** `25`
   - Click **`Start Crawler`**.
3. Inspect the populated inventory tabs:
   - **`Discovered Endpoints`:** `/`, `/products`, `/search`, `/debug/config`, `/api/v1/users/1`, etc.
   - **`Subdomains`:** `127.0.0.1`
   - **`Detected Technologies`:** `Python`, `Uvicorn`, etc.

### Step 1.7: Recalculate OWASP WSTG Plan (`/wstg`)

1. Click **`OWASP WSTG Plan`** in the sidebar.
2. Click **`Recalculate Applicability`** in the top right.
3. Confirm the 106-test catalog updates across `WSTG-INFO`, `WSTG-CONF`, `WSTG-ATHZ`, `WSTG-INPV`, etc.

### Step 1.8: Run Live LiteLLM Multi-Agent DAG & HITL Gate (`/agents`)

1. Click **`Multi-Agent DAG`** in the sidebar.
2. Run a fast **Quick Scan** first:
   - Select **`⚡ Quick Scan`** and leave **`Auto-Approve Medium`** checked.
   - Click **`Start QUICK Scan`**.
   - Watch KPI cards (`Token Burn (In / Out)`, `Estimated LLM Cost`, `Pipeline Progress`), the 6-step pipeline (`PLANNING` -> `RECON` -> `WSTG_PLANNING` -> `ACTIVE_ASSESSMENT` -> `VALIDATION` -> `REPORTING`), and **`Real-Time Agent Thought Trace & Decisions`** update live via real LiteLLM calls.
3. Now test **Full Scan + Human-in-the-Loop (HITL) Approval Gate**:
   - Select **`🛡️ Full Scan`**.
   - **Uncheck `Auto-Approve Medium`**.
   - Click **`Start FULL Scan`**.
   - The DAG executes `AGT-01`, `AGT-03`, `AGT-05` and then **pauses at `WAITING_APPROVAL`** in `ACTIVE_ASSESSMENT` before `AGT-09` sends active SQLi/XSS payloads.
   - In **`Human-in-the-Loop Approval Gates (1 Pending)`**:
     - Enter **`Operator Audit Justification`** *(minimum 5 characters)*, e.g., `Authorized active SQLi and XSS validation on local sandbox`.
     - Click **`Approve & Resume`**.
   - All 7 agents finish as `COMPLETED` with real non-zero token counts, LLM cost, thought traces, and tool calls (`web_crawler`, `wstg_runner`, `headers_analyzer`, `nuclei_runner`, `check_runner`, `multi_identity_prober`, `repro_harness`, `report_compiler`).

### Step 1.9: Triage Findings, Inspect Evidence & Run Empirical Patch Retest (`/findings`)

1. Click **`Findings & Retest`** in the sidebar.
2. Confirm clean, deduplicated findings are listed (SQL Injection, Sensitive Debug Config Exposure, BOLA / IDOR, Reflected XSS, Missing Security Headers). Click **`Deduplication Clusters`** to confirm `Duplicates Detected = 0` (`SHA256(project_id || path || method || param || cwe)`).
3. Click **`SQL Injection in Product Search Parameter`**:
   - Inspect **`HTTP Request`**, **`HTTP Response`**, **`cURL Proof`**, and **`Req SHA-256`** / **`Resp SHA-256`** in the right-hand drawer.
   - Click **`Verify Fix`** in **`Empirical Patch Retest Engine`**:
     - Result: **`✘ Vulnerable (Exploit Succeeded)`** (`HTTP 200` with `"security_note": "VULNERABLE (Unsanitized SQL concatenation)"` or `HTTP 500` on unmatched-quote syntax error).
   - Now open **`http://127.0.0.1:9000/patch/toggle-sqli`** in another browser tab:
     - Response: `{"message": "SQL Injection is now PATCHED (Prepared Statement)", ...}`.
   - Return to Pentesa and click **`Verify Fix`** again:
     - Result: **`✔ Remediated (Vulnerability Closed)`** (`HTTP 200` — clean parameterized query output without SQL error or unsanitized SQL leakage), and finding lifecycle status updates to **`Remediated`**.

### Step 1.10: Publish Signed PTES Report (`/reports`) & Verify Audit Chain (`/audit-logs`)

1. Click **`PTES Reports`** in the sidebar:
   - Choose **`PDF (Print-Ready)`** (or **`HTML (Interactive)`**).
   - Enter **Deliverable Title:** `Local Sandbox Assessment PTES Report`.
   - Keep **`Attach Raw HTTP Forensic Streams & cURL`** checked.
   - Click **`Generate & Publish Report`**.
   - Click **`Download`** to inspect the vector PDF, then click **`Verify Authenticity →`** -> **`Verify Integrity Seal`** -> **`Cryptographic Seal Verified`**.
2. Click **`Audit Hash Chain`** in the sidebar:
   - Verify the banner shows **`● Cryptographic Hash Chain Valid: All N entries verified`**.
   - Click **`Re-verify Chain`**, inspect any row via **`Inspect Payload →`**, or click **`Export Signed Ledger`** to download the compliance JSON trail.
3. Optional: Run the automated regression test suite (`145 passed`):
   ```powershell
   .venv\Scripts\pytest.exe -v
   ```

---

## Transition: Stopping Local Dev & Starting All-Dockerized Production

Once local dev testing is complete, transition cleanly to the full 5-container production stack defined in [`infrastructure/docker-compose.prod.yml`](../infrastructure/docker-compose.prod.yml):

### Step T.1: Stop Local Dev Servers

1. In all three local terminals (`uvicorn`, `npm run dev`, and `dummy_vuln_server.py`), press **`Ctrl+C`** so ports `8000`, `3000`, and `9000` are released.
2. Confirm no local listeners remain on ports `3000`, `8000`, or `9000`:
   ```powershell
   netstat -ano | findstr ":3000 :8000 :9000"
   ```

### Step T.2: Validate `.env.production`

Ensure `.env.production` at repository root contains strong secrets (`openssl rand -hex 32`) and real LiteLLM gateway settings *(never commit `.env.production`)*:

```ini
PENTESA_ENV=production
PENTESA_DEBUG=false
PENTESA_SECRET_KEY=<64-char-hex-secret>
PENTESA_MASTER_KEY=<64-char-hex-master-key>
PENTESA_LLM_PROVIDER=litellm
PENTESA_LITELLM_BASE_URL=<your-litellm-gateway-v1-url>
PENTESA_LITELLM_API_KEY=<your-litellm-api-key>
PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw
PENTESA_LITELLM_TIMEOUT=120.0
```

### Step T.3: Build, Start & Bootstrap Production Stack

1. *(Recommended for first clean production cutover)* Tear down any stale Docker volumes, then build and boot all 5 containers (`pentesa-db`, `pentesa-redis`, `pentesa-api`, `pentesa-worker`, `pentesa-web`):
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml down -v
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml up -d --build
   ```
2. Verify all containers are healthy (`Up` / `(healthy)`):
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml ps
   ```
3. Initialize PostgreSQL schema, admin account, and 106-item WSTG catalog, and run the 4-part production pre-flight check inside `pentesa-api`:
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api python scripts/verify_deployment.py --init-db
   ```
   Confirm all `[1/4]`–`[4/4]` checks show `[PASS]`, including **`LiteLLM Gateway`** and **`Database Bootstrap`**.
4. Verify live endpoints:
   - API Liveness: `http://localhost:8000/healthz` -> `{"status":"ok","service":"pentesa-api"}`
   - API Readiness (PostgreSQL): `http://localhost:8000/readyz` -> `{"status":"ready","database":"connected"}`
   - Production Console: `http://localhost:3000/login` -> loads Next.js 14 production UI cleanly.

---

## Section 1B: Running Section 1 (Option A) From Dockerized Pentesa

Once Pentesa is running inside Docker (`pentesa-internal` bridge network), **`http://127.0.0.1:9000` inside `pentesa-api` points to the container's own loopback interface—NOT your host machine.**

Choose one of two ways to run Section 1 (`dummy_vuln_server.py`) with Dockerized Pentesa:

| Mode | Where Pentesa Runs | Where `dummy_vuln_server.py` Runs | Target URL Used in Pentesa | Browser URL (Host) |
| :--- | :--- | :--- | :--- | :--- |
| **Mode 1B-1 (Hybrid Host-Bridge)** | Docker (`pentesa-internal`) | Local Python on Host (`0.0.0.0:9000`) | `http://host.docker.internal:9000/` | `http://127.0.0.1:9000/` |
| **Mode 1B-2 (All-Dockerized Option A)** | Docker (`pentesa-internal`) | Docker (`pentesa-dummy-target` on `pentesa-internal`) | `http://pentesa-dummy-target:9000/` | `http://127.0.0.1:9001/` |

---

### Mode 1B-1: Hybrid Mode (Pentesa in Docker + `dummy_vuln_server.py` Local on Host)

Because [`infrastructure/docker-compose.prod.yml`](../infrastructure/docker-compose.prod.yml) already maps `extra_hosts: ["host.docker.internal:host-gateway"]` on both `api` and `worker`, Pentesa containers can reach host services **if** the host service listens on `0.0.0.0` (all interfaces) instead of `127.0.0.1`.

1. **Start Option A on the host bound to `0.0.0.0`:**
   ```powershell
   .venv\Scripts\python.exe scripts/dummy_vuln_server.py --host 0.0.0.0 --port 9000
   ```
   > [!IMPORTANT]
   > Do **not** omit `--host 0.0.0.0`. The default `--host 127.0.0.1` binds strictly to host loopback and drops incoming packets from Docker bridge adapters (`172.x.x.x`). If Windows Defender Firewall blocks container-to-host port `9000`, allow inbound TCP `9000` on Private/vEthernet adapters (or run Mode 1B-2 below instead).

2. **Pre-check reachability from inside `pentesa-api`:**
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api curl -fsS -o /dev/null -w "HTTP %{http_code}\n" --max-time 5 http://host.docker.internal:9000/
   ```
   Confirm **`HTTP 200`**. *(FastAPI returns `405` on `HEAD`/`curl -I`, so use `GET` via `curl -fsS`.)*

3. **Run the full walkthrough in Pentesa (`http://localhost:3000`):**
   - **Login (`/login`):** Sign in using your configured administrator credentials.
   - **Create Project (`/projects`):**
     - **Engagement Name \*:** `Docker Hybrid Option A Assessment`
     - **Target In-Scope Domains \*:** `host.docker.internal`
     - **Excluded Paths:** `/logout, /admin/reset`
     - **RoE Authorization Document Ref \*:** `ROE-2026-DOCKER-HYBRID-A`
     - **Check** **`Allow Testing of RFC1918 Private Internal Networks`** *(mandatory because `host.docker.internal` resolves to the Docker gateway IP)*.
   - **Scope (`/scope`):** Add rule `EXACT_DOMAIN`, pattern `host.docker.internal`, **`Port Range (Optional)`:** `9000`. Verify `http://host.docker.internal:9000/products` -> **`IN-SCOPE`**, `http://169.254.169.254/latest/meta-data/` -> **`OUT OF SCOPE / BLOCKED`**.
   - **Discovery (`/discovery`):** **Target URL:** `http://host.docker.internal:9000/`, **Depth:** `2`, **Max Pages:** `25` -> **`Start Crawler`** (discovers `14` endpoints cleanly).
   - **WSTG (`/wstg`):** Click **`Recalculate Applicability`** (`106` items).
   - **Multi-Agent DAG (`/agents`):** Select **`🛡️ Full Scan`**, uncheck **`Auto-Approve Medium`**, click **`Start FULL Scan`** -> pauses at `WAITING_APPROVAL` -> enter justification & click **`Approve & Resume`**. Confirm 5 findings (`SQL Injection`, `Reflected XSS`, `BOLA / IDOR`, `Sensitive Debug Config`, `Missing Security Headers`) with real LiteLLM token usage.
   - **Empirical Patch Retest (`/findings`):**
     - Open **`SQL Injection in Product Search Parameter`** -> click **`Verify Fix`** -> **`✘ Vulnerable (Exploit Succeeded)`**.
     - From your host browser open **`http://127.0.0.1:9000/patch/toggle-sqli`** (or click **`Toggle SQL Injection Patch`** at `http://127.0.0.1:9000/`).
     - Click **`Verify Fix`** again in Pentesa -> **`✔ Remediated (Vulnerability Closed)`**.
   - **Reports & Audit Chain (`/reports`, `/audit-logs`):** Generate PDF report, download, verify SHA-256 seal, and click **`Re-verify Chain`**.

---

### Mode 1B-2: All-Dockerized Option A (`dummy_vuln_server` Container on `pentesa-internal`)

To eliminate host-firewall differences and run **100% inside Docker** on the same `pentesa-internal` bridge network (while keeping `http://127.0.0.1:9001/` open on your host browser without conflicting with any local port `9000` process), launch [`scripts/dummy_vuln_server.py`](../scripts/dummy_vuln_server.py) in its own container using the built `infrastructure-api` image:

1. **Start `pentesa-dummy-target` on `pentesa-internal` (mapping host `9001` -> container `9000`):**
   ```powershell
   docker run -d --name pentesa-dummy-target --network pentesa-internal -p 9001:9000 infrastructure-api python scripts/dummy_vuln_server.py --host 0.0.0.0 --port 9000
   ```
   *(If you edited `scripts/dummy_vuln_server.py` locally, rebuild the API image first with `docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml up -d --build api worker`.)*

2. **Verify Docker DNS & host browser access:**
   ```powershell
   # Container-to-container check inside pentesa-internal:
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api curl -fsS -o /dev/null -w "HTTP %{http_code}\n" --max-time 5 http://pentesa-dummy-target:9000/
   ```
   Confirm **`HTTP 200`**, and confirm your host browser loads `http://127.0.0.1:9001/`.

3. **Run the full walkthrough in Pentesa (`http://localhost:3000`):**
   - **Project (`/projects`):**
     - **Target In-Scope Domains \*:** `pentesa-dummy-target`
     - **Check** **`Allow Testing of RFC1918 Private Internal Networks`** *(container DNS resolves to a `172.x.x.x` Docker bridge IP)*.
   - **Scope (`/scope`):** Add rule `EXACT_DOMAIN`, pattern `pentesa-dummy-target`, **`Port Range (Optional)`:** `9000` *(always use the internal container port `9000`, not host port `9001`)*. Verify `http://pentesa-dummy-target:9000/products` -> **`IN-SCOPE`**.
   - **Discovery (`/discovery`):** **Target URL:** `http://pentesa-dummy-target:9000/`, **Depth:** `2`, **Max Pages:** `25` -> **`Start Crawler`**.
   - **WSTG / Agents / Findings / Reports / Audit:** Identical to Mode 1B-1 above—when testing **`Verify Fix`**, visit `http://127.0.0.1:9001/patch/toggle-sqli` in your host browser to flip the patch inside `pentesa-dummy-target`, then click **`Verify Fix`** again in Pentesa!

4. **Stop & remove the temporary target container when done:**
   ```powershell
   docker rm -f pentesa-dummy-target
   ```

---

## Section 2: All-Dockerized Production Walkthrough — Option B (`http://demo.testfire.net`)

Option B tests the containerized Pentesa stack against **Altoro Mutual (`http://demo.testfire.net/`)**, IBM/HCL AppScan's official legal public benchmark application.

> [!NOTE]
> **`testphp.vulnweb.com` Replaced Due to Origin Downtime:** Acunetix's `testphp.vulnweb.com` (`44.228.249.3:80`) frequently goes offline or times out externally (`ConnectTimeout`). Section 2 uses `http://demo.testfire.net/` instead; if you prefer an HTTPS public benchmark, you can alternatively substitute PortSwigger's `https://ginandjuice.shop/` (`Target In-Scope Domains`: `ginandjuice.shop`, `Target URL`: `https://ginandjuice.shop/`).

### Important Protocol & Network Check (`http://` vs `https://`)

1. **Plain HTTP Target:** `demo.testfire.net` serves over **plain HTTP (`http://demo.testfire.net/`) on port 80** — do **not** force `https://demo.testfire.net/`. Entering `http://demo.testfire.net/` explicitly in `/discovery` avoids an unnecessary HTTPS handshake probe *(if left blank, `ReconnaissanceAgent` tries HTTPS first and falls back to HTTP automatically)*.
2. **No Local Target Service Needed — Outbound Port 80 Required:** Unlike Option A or Option C, no local target container or script is started for Option B, **provided** your Docker host can reach the public internet on port 80.
3. **Pre-Check Target Reachability from Inside `pentesa-api`:**
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api curl -fsS -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" --max-time 8 http://demo.testfire.net/
   ```
   - **If you receive `HTTP 200`:** Your network reaches `demo.testfire.net` cleanly; proceed with Step 2.1 below.
   - **If you receive a timeout or DNS error:** Your corporate firewall or proxy blocks outbound public test targets. Use **Section 1B (Option A via Docker/Bridge)** or **Section 3 (Option C containers)** instead.

### Step 2.1: Sign In to Production Console (`/login`)

1. Open **`http://localhost:3000/login`**.
2. Sign in with your configured administrator credentials -> **`Sign In to Operations Console`**.

### Step 2.2: Authorize Public Engagement (`/projects`)

1. Navigate to **`Projects`** -> **`New Engagement`**.
2. Fill in the form:
   - **Engagement Name \*:** `Altoro Mutual Public Benchmark Assessment`
   - **Description:** `Docker production E2E validation against demo.testfire.net using real LiteLLM`
   - **Target In-Scope Domains \* (comma-separated):** `demo.testfire.net`
   - **Allowed CIDRs:** *(leave empty)*
   - **Excluded Paths:** `/logout.jsp`
   - **RoE Authorization Document Ref \*:** `ROE-2026-PROD-OPTB-001`
   - **Private Network Checkbox (`Allow Testing of RFC1918 Private Internal Networks`):** **Leave UNCHECKED** *(public target)*.
3. Click **`Authorize Engagement`**.

### Step 2.3: Verify Scope Guard (`/scope`)

1. Go to **`Scope & Boundaries`**.
2. Confirm the automatically generated `EXACT_DOMAIN` rule for `demo.testfire.net` covers `http,https:80,443` (no extra custom port rule needed for port `80`).
3. In **`Interactive Scope Boundary Tester`**, test:
   - `http://demo.testfire.net/search.jsp` -> **`IN-SCOPE`**.
   - `http://127.0.0.1:9000/` -> **`OUT OF SCOPE / BLOCKED`** *(confirms RFC1918 / loopback targets are strictly blocked for public engagements)*.
   - `https://example.com` -> **`OUT OF SCOPE / BLOCKED`**.

### Step 2.4: Crawl Attack Surface (`/discovery`)

1. Go to **`Attack Surface`**.
2. Enter:
   - **Target URL:** `http://demo.testfire.net/`
   - **Depth:** `2`
   - **Max Pages:** `25`
3. Click **`Start Crawler`**.
4. Inspect populated tabs:
   - **`Discovered Endpoints`:** `/`, `/search.jsp` (parameter `query`), `/default.jsp` (parameter `content`), `/index.jsp` (parameter `content`), `/feedback.jsp`, `/cgi.exe`.
   - **`Subdomains`:** `demo.testfire.net`.
   - **`Detected Technologies`:** `Apache HTTP Server`, `Java (Servlet/Spring)` *(via `JSESSIONID`)*.

### Step 2.5: WSTG Matrix, Multi-Agent Scan & HITL (`/wstg` & `/agents`)

1. Go to **`OWASP WSTG Plan`** -> click **`Recalculate Applicability`**.
2. Go to **`Multi-Agent DAG`**:
   - Select **`🛡️ Full Scan`**, optionally uncheck **`Auto-Approve Medium`**, and click **`Start FULL Scan`**.
   - If HITL pauses at `WAITING_APPROVAL`, enter `Operator Audit Justification` (e.g., `Authorized read/probe assessment against public Altoro Mutual testbed`) and click **`Approve & Resume`**.
   - Monitor live LiteLLM token usage (`azure/gpt-5.6-terra-dev-gtw`), agent statuses, **`Real-Time Agent Thought Trace & Decisions`**, and **`Tool Executions Dispatched`**.

### Step 2.6: Review Findings, Report & Audit Trail (`/findings`, `/reports`, `/audit-logs`)

1. **`Findings & Retest`:** Inspect detected findings (such as `Reflected Cross-Site Scripting (XSS) in 'query' Parameter (/search.jsp)` and `Missing Security Headers`) along with `HTTP Request`, `HTTP Response`, `cURL Proof`, and SHA-256 digests. *(Clicking `Verify Fix` executes a live probe showing `✘ Vulnerable (Exploit Succeeded)` since you cannot deploy patches on the public third-party host.)*
2. **`PTES Reports`:** Select **`PDF (Print-Ready)`**, enter a deliverable title, click **`Generate & Publish Report`**, **`Download`**, and **`Verify Integrity Seal`**.
3. **`Audit Hash Chain`:** Click **`Re-verify Chain`** to confirm cryptographic hash chain validity in PostgreSQL.

---

## Section 3: All-Dockerized Production Walkthrough — Option C (Containerized Targets)

Option C runs industry-standard vulnerable web applications **as Docker containers directly on Pentesa's `pentesa-internal` bridge network**. This works 100% offline/behind strict firewalls because `pentesa-api` communicates with target containers by **Docker DNS container name + internal container port**.

> [!TIP]
> **Container Hostname vs. Browser URL:**
> - **Your browser on the host** opens published host ports (`http://localhost:3001` for Juice Shop, `http://localhost:8080` for DVWA).
> - **Pentesa containers (`pentesa-api`)** reach sibling containers using internal Docker DNS and internal ports (`http://juice-shop:3000/` or `http://dvwa/`).
> - Both options resolve to RFC1918 Docker bridge IPs (`172.x.x.x`), so **checking `Allow Testing of RFC1918 Private Internal Networks` is mandatory**.

---

### Option C.1: OWASP Juice Shop (`bkimminich/juice-shop`)

#### Step 3A.1: Launch Juice Shop on `pentesa-internal`
*(Ensure Pentesa's production stack from Step T.3 is already up so the `pentesa-internal` network exists.)*
```powershell
docker run -d --name juice-shop --network pentesa-internal -p 3001:3000 bkimminich/juice-shop
```
- Verify in browser: `http://localhost:3001` loads OWASP Juice Shop.
- Verify from inside `pentesa-api`:
  ```powershell
  docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api curl -I http://juice-shop:3000/
  ```

#### Step 3A.2: Authorize Project & Add Port `3000` Scope Rule
1. In Pentesa (`http://localhost:3000/projects`) -> **`New Engagement`**:
   - **Engagement Name \*:** `Docker Juice Shop Assessment`
   - **Target In-Scope Domains \*:** `juice-shop`
   - **Excluded Paths:** `/#/logout`
   - **RoE Authorization Document Ref \*:** `ROE-2026-DOCKER-JUICESHOP`
   - **Check** **`Allow Testing of RFC1918 Private Internal Networks`**
   - Click **`Authorize Engagement`**.
2. Go to **`Scope & Boundaries`** -> **`Add Authorized Boundary Rule`**:
   - **Target Pattern:** `juice-shop`
   - **Rule Type:** `EXACT_DOMAIN`
   - **Target Type:** `IN_SCOPE (Allow)`
   - **Port Range (Optional):** **`3000`** *(mandatory because Juice Shop listens on internal port `3000`)*
   - Click **`Add Rule`**.
3. Verify in **`Interactive Scope Boundary Tester`**:
   - `http://juice-shop:3000/rest/products/search?q=apple` -> **`IN-SCOPE`**.
   - `https://example.com` -> **`OUT OF SCOPE / BLOCKED`**.

#### Step 3A.3: Discovery, WSTG Plan, Multi-Agent Scan & Reporting
1. **`Attack Surface`** (`/discovery`):
   - **Target URL:** `http://juice-shop:3000/` *(or leave blank to auto-detect)*
   - **Depth:** `2`, **Max Pages:** `25`, click **`Start Crawler`**.
2. **`OWASP WSTG Plan`** (`/wstg`): click **`Recalculate Applicability`**.
3. **`Multi-Agent DAG`** (`/agents`):
   - Select **`🛡️ Full Scan`** (or **`🔬 Deep Scan`**), uncheck **`Auto-Approve Medium`** to test the HITL gate, click **`Start FULL Scan`**, then enter justification and click **`Approve & Resume`**.
   - Monitor live LiteLLM reasoning traces and tool calls (`AGT-09` probes `/rest/products/search?q=`, `AGT-05` audits HTTP headers, `AGT-11` validates evidence).
4. **`Findings & Retest`**, **`PTES Reports`**, **`Audit Hash Chain`**: inspect findings, download signed PDF/HTML report, verify seal, and click **`Re-verify Chain`**.

---

### Option C.2: Damn Vulnerable Web Application (`vulnerables/web-dvwa`)

#### Step 3B.1: Launch DVWA on `pentesa-internal`
```powershell
docker run -d --name dvwa --network pentesa-internal -p 8080:80 vulnerables/web-dvwa
```
1. Open **`http://localhost:8080`** in your browser.
2. Log in with DVWA default credentials (`admin` / `password`) or click **Create / Reset Database** at the bottom of `setup.php` first so DVWA initializes its MySQL tables.
3. Verify reachability from `pentesa-api`:
   ```powershell
   docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api curl -I http://dvwa/
   ```

#### Step 3B.2: Authorize Project, Verify Scope & Execute Full Lifecycle
1. In Pentesa (`http://localhost:3000/projects`) -> **`New Engagement`**:
   - **Engagement Name \*:** `Docker DVWA Assessment`
   - **Target In-Scope Domains \*:** `dvwa`
   - **Excluded Paths:** `/logout.php, /setup.php`
   - **RoE Authorization Document Ref \*:** `ROE-2026-DOCKER-DVWA`
   - **Check** **`Allow Testing of RFC1918 Private Internal Networks`**
   - Click **`Authorize Engagement`**.
2. **`Scope & Boundaries`** (`/scope`): DVWA listens on container port `80`, which is already authorized by the auto-created `dvwa` domain rule (`http,https:80,443`). Verify `http://dvwa/login.php` returns **`IN-SCOPE`**.
3. **`Attack Surface`** (`/discovery`): enter **Target URL:** `http://dvwa/`, click **`Start Crawler`**.
4. **`OWASP WSTG Plan`** (`/wstg`): click **`Recalculate Applicability`**.
5. **`Multi-Agent DAG`** (`/agents`): launch **`🛡️ Full Scan`** or **`🔬 Deep Scan`** (with HITL approval gate if `Auto-Approve Medium` is unchecked).
6. **`Findings & Retest`**, **`PTES Reports`**, **`Audit Hash Chain`**: review verified findings, generate & verify PDF/HTML PTES deliverables, and confirm audit hash chain integrity.

---

### Connecting Your Own External Docker Compose Target Service

If your target application already runs in **another Docker Compose project** (for example `myapp_default` network), Pentesa containers on `pentesa-internal` cannot see it by default. Choose either fix:

1. **Attach Pentesa or the target container dynamically to a shared bridge network:**
   ```powershell
   # Option A: Connect your target container into Pentesa's network
   docker network connect pentesa-internal <your-target-container-name>

   # Option B: Or connect pentesa-api & pentesa-worker to your target's network
   docker network connect <your-target-compose-network> pentesa-api
   docker network connect <your-target-compose-network> pentesa-worker
   ```
   Then create the Pentesa project using the target's **service/container hostname** (`<your-target-container-name>`), enable **`Allow Testing of RFC1918 Private Internal Networks`**, and add a `Port Range` rule for its **internal container port** (not the host-mapped port).

2. **Route through the host via `host.docker.internal`:**
   If you prefer not to attach networks, publish the target container port to host (`0.0.0.0:<host_port>`), use `host.docker.internal` as the Pentesa project domain + RFC1918 checkbox + `<host_port>` scope rule, and scan `http://host.docker.internal:<host_port>/`.

---

## Section 4: Docker Networking Guide & Future Dockerization Pitfalls

When Pentesa and/or the services it tests are Dockerized, watch for these real architectural behaviors in the codebase:

1. **`127.0.0.1` / `localhost` Namespace Isolation & `--host 127.0.0.1` Traps**
   - Inside Docker, `127.0.0.1` refers only to the local container (`pentesa-api`). Host targets or local LLM gateways (`Ollama`, `LiteLLM`) running on `localhost` must bind to `0.0.0.0` (not `127.0.0.1`) and be referenced inside containers via `host.docker.internal` (`extra_hosts: ["host.docker.internal:host-gateway"]`, already configured in [`infrastructure/docker-compose.prod.yml`](../infrastructure/docker-compose.prod.yml)).
   - **Windows Port-Shadowing Pitfall (`127.0.0.1` vs `0.0.0.0`):** On Windows, if a local Python process already binds `127.0.0.1:9000` while a Docker container maps `-p 9000:9000` (`0.0.0.0:9000`), Winsock allows both binds simultaneously and sends host browser/curl requests for `127.0.0.1:9000` to the local process instead of the container. Always check `netstat -ano | findstr ":9000"` or map containers to a distinct host port (`-p 9001:9000`).
   - On Linux hosts with `ufw`/`iptables` or Windows hosts with strict Defender rules, allow inbound traffic from Docker bridge subnets (`172.16.0.0/12`) to the target host port.

2. **RFC1918 Blocking & Anti-DNS-Rebinding Checks ([`ScopeEnforcementService`](../services/scope_engine/service.py) & [`DnsPinningValidator`](../services/scope_engine/dns_pinning.py))**
   - Both `host.docker.internal` and Docker service names resolve to private/gateway IPs (`172.x.x.x`, `192.168.x.x`). Always check **`Allow Testing of RFC1918 Private Internal Networks`** for internal/container targets; otherwise Layer 1 and Layer 2 block every request.
   - Cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) remains unconditionally blocked even when internal networks are enabled.

3. **Standard Port Defaults & HTTP-vs-HTTPS Scheme Inference ([`resolve_project_origin`](../services/execution_engine/runners.py))**
   - Domain/IP scope rules default to ports `{80, 443}`. Microservice containers typically listen on non-standard plain HTTP ports (`3000`, `5000`, `8000`, `8080`, `9000`). Add the explicit `Port Range` scope rule in `/scope`, otherwise [`ScopeValidator`](../services/scope_engine/validator.py) blocks scanning and `resolve_project_origin` falls back to `https://<host>`.

4. **Remote Browser Access vs. `NEXT_PUBLIC_API_URL` Build-Time Baking ([`Dockerfile.web`](../infrastructure/docker/Dockerfile.web))**
   - [`infrastructure/docker-compose.prod.yml`](../infrastructure/docker-compose.prod.yml) bakes `NEXT_PUBLIC_API_URL=http://localhost:8000` into static browser JS at **image build time** (`apps/web/src/lib/api.ts`), while Next.js server-side rewrites (`apps/web/next.config.mjs`) use runtime `API_INTERNAL_URL=http://api:8000`.
   - **Future deployment impact:** If you host Dockerized Pentesa on a shared VM or staging server (`http://10.x.x.x:3000` or `https://pentesa.corp`), remote operators' browsers will fail with `Failed to fetch` trying to hit their own `localhost:8000` unless you rebuild `web` with the external API URL (or empty same-origin prefix routed through a reverse proxy / Next.js rewrites).

5. **`Host` Header Virtual-Host & CORS Rejections**
   - When `pentesa-api` hits a service as `http://host.docker.internal:9000` or `http://my-app:8080`, strict frameworks enforcing `ALLOWED_HOSTS`, Nginx `server_name`, CORS origins, or OAuth `redirect_uri` (expecting `localhost` or `app.corp`) may reject requests with HTTP `400`/`403` unless `host.docker.internal` / the container hostname is allowed in the target's dev/staging config.

6. **Ephemeral Container IPs & Multi-Replica Worker Scaling**
   - Docker Compose assigns dynamic `172.x.x.x` IPs on container recreation—always configure Scope Rules by **Docker service hostname** (`EXACT_DOMAIN`, e.g., `pentesa-dummy-target`, `dvwa`) rather than raw container IPs.
   - Currently [`apps/api/routers/agents.py`](../apps/api/routers/agents.py) tracks async workflows in `_ACTIVE_WORKFLOW_TASKS` inside `pentesa-api` memory (while [`services/execution_engine/worker.py`](../services/execution_engine/worker.py) stays ready on `pentesa-internal`). Scaling `api` beyond `1` replica later requires dispatching workflows over Redis (`PENTESA_REDIS_URL`) to `pentesa-worker`.

7. **Hardened Egress Proxy & OAST Callback Routing (`PENTESA_EGRESS_PROXY_HOST` / `PENTESA_CALLBACK_SINK_HOST`)**
   - If you later enable `internal: true` on `pentesa-internal` or route traffic through an outbound proxy container, ensure the proxy/network policy explicitly permits upstream LLM endpoints (`PENTESA_LITELLM_BASE_URL` / `PENTESA_OLLAMA_BASE_URL`) and target hosts, and publish OAST callback ports so blind SSRF/XSS callbacks can route back from targets to Pentesa.

---

### Post-Testing Cleanup (Production Stack)

Remove temporary Option A / Option C target containers when done, delete temporary projects in `/projects` if desired, and inspect clean state:

```powershell
# Stop & remove temporary target containers
docker rm -f pentesa-dummy-target juice-shop dvwa

# Confirm only Pentesa production services remain healthy
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml ps

# Verify PostgreSQL project count & full audit chain integrity
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T db psql -U pentesa_user -d pentesa -c "SELECT count(*) AS projects_count FROM projects;"
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api python scripts/verify_deployment.py
```

---

## Automated Command-Line Verification (Pytest Suite)

Run the full automated test suite (Unit, Scope Enforcement, Discovery Crawler, Empirical Retest, Multi-Agent Workflows, PDF/HTML Reporting, Security Hardening, and Merkle Audit Chains):

```powershell
# Complete 145-test regression suite
pytest -v

# Individual verification groups
pytest tests/unit/test_crawler.py -v
pytest tests/integration/test_e2e_workflow.py -v
pytest tests/performance/test_performance_benchmarks.py -v
pytest tests/security/test_security_hardening.py -v
```
