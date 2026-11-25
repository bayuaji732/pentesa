# ADR-007: Database Migration Architecture & Schema Evolution Strategy

> **Document Identifier:** `ADR-007-DB-MIGRATION-STRATEGY`  
> **Status:** PROPOSED  
> **Date:** 2026-11-25  
> **Auditors / Authors:** Principal Database Architect & Platform Engineering Team  
> **Target Release:** Phase 9 Wave 1 Implementation  
> **Reference Issues:** `P1-FIND-02`, `DEFECT-FIND-03`, `DEFECT-DEDUP-01`, `DEFECT-LIFE-01`  

---

## 1. Context & Problem Statement

Pentesa currently relies on SQLAlchemy's `Base.metadata.create_all()` executed during API server startup (`apps/api/main.py:lifespan`). While sufficient for initial prototyping and greenfield database bootstrapping, this approach exhibits severe operational limitations during platform evolution:

1. **Inability to Mutate Existing Tables:** `create_all()` only creates missing tables. It cannot alter columns, add constraints, create new indexes, or add foreign keys to existing tables without dropping data or executing manual ad-hoc SQL.
2. **Impending Wave 1 Schema Evolution Requirements:**
   - `DEFECT-LIFE-01`: Requires `assigned_to UUID REFERENCES users(id) ON DELETE SET NULL` on `findings`.
   - `DEFECT-DEDUP-01`: Requires `dedup_signature VARCHAR(64)` and `occurrence_count INTEGER DEFAULT 1` on `findings`.
   - `DEFECT-FIND-03`: Requires `cvss_source VARCHAR(20) DEFAULT 'ESTIMATED'` on `findings`.
   - `P1-FIND-02`: Requires denormalized `endpoint_path VARCHAR(2048)` and `http_method VARCHAR(16)` on `findings` (or maintaining joined relation views).
3. **Data Preservation Invariant (ENV RULES v2):** Production audit chains (1,676 records) and existing engagement benchmark findings must not be destroyed or corrupted during deployment (`zero -v` policy).

A formalized, safe, and automated database migration architecture is required.

---

## 2. Evaluation of Architectural Options

### Option A: Alembic Baseline Migration with Autogenerate (Recommended)

- **Architecture:** Initialize Alembic (`alembic init -t async migrations`). Create an initial baseline migration stamping the current production schema version (`phase8_baseline`), followed by versioned, sequential migration scripts for Wave 1 and beyond.
- **Pros:**
  - Standard industry practice for SQLAlchemy and FastAPI applications.
  - Supports automatic schema diffing (`alembic revision --autogenerate`).
  - Supports bidirectional migrations (upgrade & downgrade).
  - Integrates seamlessly into CI/CD and container entrypoint scripts (`alembic upgrade head`).
  - Safe for production: records applied revision hashes in `alembic_version` table.
- **Cons:**
  - Requires adding `alembic` package to production dependencies.
  - Requires initial baseline synchronization so existing production databases don't attempt to re-create existing tables.

### Option B: Idempotent Raw SQL Migration Scripts (`database/migrations/*.sql`)

- **Architecture:** Maintain raw SQL migration scripts executed sequentially by a lightweight Python runner on startup. Each script uses `ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...`.
- **Pros:**
  - Zero external dependencies beyond `asyncpg`/`psql`.
  - Simple to inspect, audit, and review.
  - Idempotent execution via `IF NOT EXISTS` syntax.
- **Cons:**
  - No rollback/downgrade capability.
  - Manual authoring required for complex constraints, type changes, and index creation.
  - Schema drift between SQLAlchemy models and SQL scripts must be manually guarded.

### Option C: In-Place Schema Mutation via `Base.metadata.create_all()` + Manual Psql

- **Architecture:** Retain `create_all()`, execute ad-hoc `ALTER TABLE` commands manually via `docker exec pentesa-db psql`.
- **Pros:**
  - Zero code changes.
- **Cons:**
  - Completely unacceptable for production engineering: error-prone, untracked, non-reproducible, and violates auditability requirements.

---

## 3. Decision Matrix

| Evaluation Criteria | Option A: Alembic Async | Option B: Idempotent SQL | Option C: Manual Ad-hoc |
|---|:---:|:---:|:---:|
| **Reproducibility & Audit Trail** | **High** (Revision tree) | Medium (Sequential files) | Low (Untracked) |
| **Safety on Production (Zero Data Loss)** | **High** (`alembic_version`) | High (`IF NOT EXISTS`) | Low (Manual risk) |
| **Model Synchronization** | **High** (Autogenerate diffs) | Medium (Manual sync) | None |
| **Rollback / Downgrade Support** | **Full** (Downgrade scripts) | None | None |
| **Implementation Complexity** | Medium (Setup baseline) | Low | None |

---

## 4. Proposed Strategy & Phased Adoption

We propose adopting **Option A (Alembic with Baseline Stamping)** under a fail-safe, 3-step transition:

### Step 1: Baseline Stamping (Wave 1 Prep)
1. Initialize Alembic configuration (`alembic.ini` and `database/migrations/`).
2. Generate baseline migration `0001_phase8_baseline.py` representing current production state.
3. On existing production database (`pentesa-prod`), stamp the baseline without re-running DDL:
   ```bash
   alembic stamp head
   ```

### Step 2: Wave 1 Additive Migration (`0002_wave1_findings_enhancements.py`)
Add strictly non-breaking, nullable or default-valued columns to `findings`:
```sql
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assigned_to UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_signature VARCHAR(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS occurrence_count INTEGER DEFAULT 1 NOT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_source VARCHAR(20) DEFAULT 'ESTIMATED' NOT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS endpoint_path VARCHAR(2048);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS http_method VARCHAR(16);

CREATE INDEX IF NOT EXISTS ix_findings_assigned_to ON findings(assigned_to);
CREATE INDEX IF NOT EXISTS ix_findings_dedup_sig ON findings(project_id, dedup_signature);
```

### Step 3: Startup Integration
In `apps/api/main.py:lifespan`, replace raw `create_all()` with:
```python
# Execute pending Alembic migrations safely on startup
from alembic.config import Config
from alembic import command

alembic_cfg = Config("alembic.ini")
command.upgrade(alembic_cfg, "head")
```

---

## 5. Consequences & Rollback Plan

- **Positive:** Guarantees zero data loss on schema changes; provides clean traceability between code and database schema; eliminates manual psql interventions.
- **Negative:** Adds `alembic>=1.13.0` to `requirements.txt` (+~450KB).
- **Rollback Plan:** Each migration script must provide a fully tested `downgrade()` function to reverse column additions cleanly if unexpected errors arise.
