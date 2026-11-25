# ADR-007: Database Migration Architecture & Schema Evolution Strategy

> **Document Identifier:** `ADR-007-DB-MIGRATION-STRATEGY`  
> **Status:** ACCEPTED with conditions  
> **Date:** 2026-11-25  
> **Auditors / Authors:** Principal Database Architect & Platform Engineering Team  
> **Target Release:** Phase 9 Wave 1b Implementation  
> **Reference Issues:** `P1-FIND-02`, `DEFECT-FIND-03`, `DEFECT-DEDUP-01`, `DEFECT-LIFE-01`, `DEFECT-REPRO-01`, `DEFECT-AUD-02`, Password Change  

---

## 1. Context & Problem Statement

Pentesa historically relied on SQLAlchemy's `Base.metadata.create_all()` executed during API server startup (`apps/api/main.py:lifespan`). While sufficient for initial prototyping and greenfield database bootstrapping, this approach exhibits severe operational limitations during platform evolution:

1. **Inability to Mutate Existing Tables:** `create_all()` only creates missing tables. It cannot alter columns, add constraints, create new indexes, or add foreign keys to existing tables without dropping data or executing manual ad-hoc SQL.
2. **Impending Wave 1b Schema Evolution Requirements:**
   - `DEFECT-LIFE-01`: Requires `assigned_to UUID REFERENCES users(id) ON DELETE SET NULL` on `findings`.
   - `DEFECT-DEDUP-01`: Requires `dedup_signature VARCHAR(64)` and `occurrence_count INTEGER DEFAULT 1` on `findings`.
   - `DEFECT-FIND-03`: Requires `cvss_source VARCHAR(20) DEFAULT 'ESTIMATED'` on `findings`.
   - `DEFECT-REPRO-01`: Requires structured redirect tracking (`final_url`, `redirect_chain_json`).
   - `DEFECT-AUD-02`: Requires altering audit log foreign keys (`user_id`, `project_id`) from `ON DELETE SET NULL` to `ON DELETE RESTRICT` (or unconstrained UUID) to protect Merkle hash chain immutability.
   - Self-Service Password Change: Requires optional `must_change_password BOOLEAN DEFAULT FALSE` on `users`.
3. **Data Preservation Invariant (ENV RULES v2):** Production audit chains and existing engagement benchmark findings must not be destroyed or corrupted during deployment (`zero -v` policy).

A formalized, safe, and automated database migration architecture is required.

---

## 2. Decision: Alembic with Baseline Stamping (ACCEPTED with Conditions)

We adopt **Alembic** using an async SQLAlchemy engine under the following **six mandatory operational conditions**:

### Condition 1: Dual-Path Schema Bootstrapping (Fresh DB vs Existing Prod)
1. **Fresh Installation Baseline:**
   - Running `docker compose up -d` on an empty PostgreSQL database MUST automatically bring up a fully working schema.
   - The initial baseline migration `0001_initial_schema.py` defines the complete current schema so `alembic upgrade head` creates all tables, indexes, and constraints from scratch without depending on legacy `create_all()`.
2. **Existing Production Stamping:**
   - Existing running databases (e.g. `pentesa-prod`) are NOT dropped or recreated.
   - Before stamping, an automated check runs `alembic check` / autogenerate diff against current SQLAlchemy models. Stamping (`alembic stamp 0001_initial_schema`) is permitted ONLY when the diff against current models is completely empty, or any documented drift is explicitly registered in the audit log.

### Condition 2: One-Shot Locked Execution (Advisory Lock)
- To prevent race conditions when multiple API containers or task workers start simultaneously, migrations execute inside a PostgreSQL transactional advisory lock:
  ```python
  # PostgreSQL transactional advisory lock prevents concurrent migration runners
  await connection.execute(text("SELECT pg_advisory_xact_lock(84729103);"))
  ```
- Alternatively, run migrations as a dedicated one-shot entrypoint or init container prior to web/worker startup.

### Condition 3: Ephemeral Pre-Migration Safety Dump
- Immediately prior to executing migrations on `pentesa-prod`, a temporary database dump is created via `pg_dump`:
  ```bash
  docker compose -p pentesa-prod exec -T pentesa-db pg_dump -U pentesa pentesa > /tmp/pentesa_pre_wave1b_backup.sql
  ```
- This backup is strictly ephemeral: once the migration and verification suite pass, the temporary file is securely purged, maintaining compliance with ENV RULES v2.

### Condition 4: Authoritative Backfill Rules for Existing Findings
- For all existing findings currently stored in `pentesa-prod` (e.g. 39 benchmark findings):
  1. `cvss_source`: Backfilled with `"ESTIMATED"`.
  2. `occurrence_count`: Backfilled with `1`.
  3. `dedup_signature`: Computed deterministically from `sha256(project_id:endpoint_path:http_method:cwe_id:title)`.
  4. `endpoint_path` and `http_method`: Backfilled from joined `endpoints` table, or parsed from `raw_request` request lines where `endpoint_id` is null.
  5. `assigned_to`: Initialized as `NULL`.

### Condition 5: Verified Downgrade Capability
- Every migration revision file must implement both `upgrade()` and `downgrade()`.
- The downgrade path must be tested on a throwaway staging database to prove clean rollback capability before applying to production.

### Condition 6: Comprehensive Test Matrix
- Automated test suite must verify migration execution on two distinct target archetypes:
  1. **Fresh Database:** `alembic upgrade head` executed against an empty SQLite/PostgreSQL instance succeeds with zero errors.
  2. **Stamped Production Database:** Baseline stamp followed by `upgrade head` succeeds on an existing seeded database without table collision or data loss.

---

## 3. Wave Phasing Alignment

- **Wave 1a (Zero Schema Changes):**
  - No Alembic or database alterations are introduced in Wave 1a.
  - `P1-FIND-02` populates `endpoint` and `method` in `FindingResponse` via dynamic SQLAlchemy relationship join on `finding.endpoint` with fallback to `raw_request` parsing.
  - All Wave 1a enhancements (`P1-AGENT-01`, `DEFECT-REP-01`, `DEFECT-REP-02`, `DEFECT-REDACT-01`) operate entirely in-memory and in application service layers.
- **Wave 1b (Alembic Migration Implementation):**
  - Implements `ADR-007` requirements under Conditions 1–6.
  - Executes schema additions for `DEFECT-FIND-03`, `DEFECT-DEDUP-01`, `DEFECT-LIFE-01`, `DEFECT-REPRO-01`, `DEFECT-AUD-02`, and Password Change.
