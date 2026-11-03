# Pentesa Directory Structure & Architecture Mapping

This repository follows the modular monorepo architecture defined in `docs/03-system-architecture.md`:

- `apps/api`: FastAPI backend and REST API engine (Phase 1)
- `apps/web`: Next.js 14 SOC dashboard frontend (Phase 1 & Phase 7)
- `services/scope_engine`: Dual-layer scope validation and DNS anti-rebinding service (Phase 1)
- `services/discovery_engine`: Attack surface discovery, crawling, and parameter inventory (Phase 2)
- `services/execution_engine`: Deterministic security tool runner & subprocess sandbox (Phase 4)
- `services/orchestrator`: LangGraph multi-agent workflow orchestrator (Phase 5)
- `services/evidence_engine`: Cryptographic evidence collector and artifact hasher (Phase 6)
- `services/reporting_engine`: PTES WeasyPrint PDF/HTML generator (Phase 6)
- `agents/`: AI penetration testing agent definitions and prompt templates (Phase 5)
- `skills/`: OWASP WSTG testing skills with deterministic tool workflows (Phase 3 & Phase 4)
- `integrations/`: Subprocess wrappers for native tools (Nuclei, Katana, Ffuf, Playwright) (Phase 4)
- `packages/common`: Security primitives, JWT, bcrypt, config, and audit logging (Phase 1)
- `packages/schemas`: Domain Pydantic models (Phase 1)
- `packages/tool_sdk`: Common CLI tool execution SDK (Phase 4)
- `database/`: SQLAlchemy 2.0 async models, connection pooling, and seeds (Phase 1)
- `database/migrations`: Alembic schema migrations (Phase 1)
- `tests/`: Automated test suite (Unit, Integration, Security, E2E)
- `infrastructure/`: Docker Compose and deployment configurations

