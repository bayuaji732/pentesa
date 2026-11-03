# ADR-003: PostgreSQL 16 with Relational Core and JSONB for Schemaless Endpoint Data

## Status
Accepted

## Context
Pentesa requires persisting structured security data (users, projects, scope, findings, WSTG catalog) alongside highly variable, semi-structured data:
- Discovered HTTP endpoint parameter schemas (varying widely between REST, GraphQL, and form-urlencoded endpoints).
- Tool execution configurations and raw JSON output streams.
- Agent thought traces and decision logs.

We evaluated:
1. Pure Document Store (MongoDB): High flexibility for dynamic payloads, but lacks ACID guarantees for critical financial/project scope associations, complex joins, and mature migration tooling.
2. Relational Database with JSONB (PostgreSQL 16): ACID relational integrity for core entities with indexed JSONB columns for dynamic parameter schemas and tool outputs.

## Decision
We chose **PostgreSQL 16** with SQLAlchemy 2.0 ORM and Alembic migrations.

## Rationale & Justification
- Core domain models (projects, scope targets, exclusions, findings, WSTG instances) require strict foreign key constraints and cascade rules.
- PostgreSQL's `JSONB` data type combined with GIN indexing provides high-performance querying inside dynamic parameter lists and tool outputs:
  `CREATE INDEX idx_endpoints_params_gin ON endpoints USING GIN (parameter_schema);`
- Built-in `pgcrypto` extension enables native database encryption functions.
- Immutable audit ledger triggers can be enforced natively via PostgreSQL SQL rules.

## Consequences & Trade-offs
### Positive:
- Best of both worlds: strict relational integrity for governance, dynamic document flexibility for endpoint parameters.
- Robust ecosystem of backup, replication, and migration tooling.
- Single database engine to operate and maintain in Docker Compose.

### Negative:
- Schema migrations require Alembic management.
- Deep nested querying inside complex JSONB structures requires specialized PostgreSQL operators (`->`, `->>`, `@>`).
