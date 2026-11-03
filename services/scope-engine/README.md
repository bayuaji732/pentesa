# Scope Engine Service

Core Dual-Layer Scope Enforcement Service implemented in `services/scope_engine/`.

- Layer 1: Application-level mathematical dot-boundary regex & CIDR validator (`validator.py`)
- Layer 2: Network-level DNS resolution & anti-rebinding guard (`dns_pinning.py`)
- Orchestration: High-level target evaluator (`service.py`)
