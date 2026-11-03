# ADR-001: Adoption of Monolithic-First Modular Architecture

## Status
Accepted

## Context
Pentesa is an autonomous web application penetration testing platform that requires orchestrating multiple subsystems: project management, scope enforcement, network crawling, security scanning, multi-agent AI reasoning, evidence capture, and report generation.

We evaluated two architectural patterns for v1.0:
1. Microservices Architecture: Deploying separate containerized services for each agent, tool runner, and data service communicating over gRPC/Kafka.
2. Modular Monolith Architecture: A single unified backend application (FastAPI) structured into discrete, domain-isolated modules sharing a relational database, with long-running tasks distributed via Celery/Redis.

## Decision
We chose the **Modular Monolith** pattern for Pentesa v1.0.

The codebase is organized into strict internal domain packages (`app.modules.projects`, `app.modules.scope`, `app.modules.discovery`, `app.modules.wstg`, `app.modules.findings`, `app.modules.agents`, `app.modules.reporting`). Modules communicate through documented Python interfaces and service classes rather than raw database coupling.

## Consequences & Trade-offs
### Positive Consequences:
- **Deployment Simplicity:** A single Docker Compose bundle runs on developer laptops and private client servers without needing Kubernetes or service meshes.
- **Transactional Integrity:** Cross-entity transactions (e.g. project creation with scope and RoE) leverage standard ACID database transactions.
- **Performance:** Zero network serialization overhead between internal modules.
- **Development Velocity:** Simplified refactoring, debugging, and continuous integration testing via pytest.

### Negative Consequences / Trade-offs:
- Single programming language constraint (Python 3.12) across backend services.
- If a background task consumes excessive memory, it shares the worker container (mitigated via Celery task concurrency limits and Docker cgroups).
- Future scaling to multi-server distributed worker clusters will require extracting the worker queue (which Celery already natively supports).

