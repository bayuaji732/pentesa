# Pentesa Benchmark Environment (Phase 3)

## 1. Overview
The Pentesa Benchmark Environment provides an isolated, multi-architecture benchmark testbed designed to measure penetration testing effectiveness, WSTG coverage, precision, recall, and false-positive rates.

Testing encompasses standard industry targets (`OWASP Juice Shop`, `DVWA`, `WebGoat`, `crAPI`) plus `pentesa-bench`, a purpose-built application providing paired vulnerable and hardened endpoints with deterministic reset controls.

---

## 2. Pinned Benchmark Image Specifications

| Target Container | Base Image / Pinned Tag | Role / Architecture | In-Scope Ports | Status Baseline |
|---|---|---|---|---|
| `bench-juiceshop` | `bkimminich/juice-shop:v17.1.1` | NodeJS / Express / Angular SPA | 3000 | Vulnerable SPA |
| `bench-dvwa` | `vulnerables/web-dvwa:latest` | PHP 7 / Apache / MySQL | 80 | Low (Vuln) & Impossible (Secure) |
| `bench-webgoat` | `webgoat/webgoat:v2023.8` | Java 17 / Spring Boot Enterprise | 8080, 9090 | Enterprise Java Vulns |
| `bench-crapi-web` | `crapi/crapi-web:v0.3.0` | React Web Frontend | 80 | Microservices UI |
| `bench-crapi-identity` | `crapi/crapi-identity:v0.3.0` | Go / Identity Service (BOLA/JWT) | 8080 | Microservices Identity |
| `bench-crapi-community` | `crapi/crapi-community:v0.3.0` | Java / Community Forum Service | 8087 | Microservices Forum |
| `bench-crapi-workshop` | `crapi/crapi-workshop:v0.3.0` | Python / Workshop Service | 8088 | Microservices Workshop |
| `bench-crapi-db` | `postgres:14-alpine` | PostgreSQL Database for crAPI | 5432 | Internal DB |
| `bench-crapi-mongodb` | `mongo:4.4.18` | MongoDB Database for crAPI | 27017 | Internal NoSQL DB |
| `bench-crapi-mailhog` | `mailhog/mailhog:v1.0.1` | Fake SMTP Test Mail Server | 8025 | Dev Mail Trap |
| `bench-pentesa-app` | `pentesa-bench:latest` (built local) | Python 3.12 / FastAPI Paired Tests | 8080 | Paired Vuln & Secure Endpoints |
| `bench-canary-sensor` | `pentesa-canary:latest` (built local) | Python 3.12 / HTTP SSRF Sensor | 9099 | Out-of-Scope Trap Sensor |

---

## 3. Network Isolation & Egress Invariants

1. **Target Network (`pentesa-bench-net`):**
   Configured with `internal: true`. Containers attached solely to this network cannot initiate or receive outbound connections to or from the public internet.
2. **Scanner Egress Posture (NI-03 Disclosure):**
   The Pentesa API and Worker containers must communicate with the upstream LLM gateway (`azure/gpt-5.6-terra-dev-gtw`). Therefore, scanner containers are also connected to an egress-capable bridge network.
   **Crucial Safety Note:** Because scanner containers have an internet route for the AI gateway, Docker network isolation does NOT protect tool subprocesses (nuclei, ffuf) from outbound egress. The fail-closed application-level lab guardrail (FIX-08) and strict CLI flag sanitation (`-dr`, non-recursive) serve as the primary barriers preventing tool egress until the dedicated Layer-2 egress proxy (NI-03) is deployed in Phase 9.
3. **Authorized Target Limitation:** Only targets explicitly declared in `docker-compose.bench.yml` may ever be included in scan scopes.
4. **Canary Trap:** Any HTTP request reaching `bench-canary:9099` from an unapproved host or non-SSRF probe constitutes an immediate **P0 Scope Failure**, requiring immediate scan termination.

---

## 4. How to Bring the Benchmark Up

### Step 1: Build Local Benchmark Images
```bash
docker compose -f benchmark/docker-compose.bench.yml build
```

### Step 2: Start Target Fleet in Background
```bash
docker compose -f benchmark/docker-compose.bench.yml up -d
```

### Step 3: Verify Health Status
```bash
docker compose -f benchmark/docker-compose.bench.yml ps
```
Ensure all targets report `healthy` or `running`.

### Step 4: Deterministic Reset Between Benchmark Runs
To reset seeded database records and in-memory test states between scan runs without recreating containers:
```bash
# Reset pentesa-bench paired app
curl -s -X POST http://localhost:8080/api/reset
```

### Step 5: Tear Down
```bash
docker compose -f benchmark/docker-compose.bench.yml down -v
```
