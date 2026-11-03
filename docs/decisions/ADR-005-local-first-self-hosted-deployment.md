# ADR-005: Local-First, Sovereign Deployment Model with Offline Ollama Support

## Status
Accepted

## Context
Commercial vulnerability assessment platforms (e.g., Qualys, Rapid7, Veracode) rely on multi-tenant cloud control planes. For enterprise penetration testing, sending confidential customer vulnerability data, active test session credentials, and internal network IP ranges to third-party cloud infrastructure creates severe compliance, regulatory (GDPR/HIPAA/PCI-DSS), and intellectual property liabilities.

We evaluated:
1. Cloud SaaS Control Plane: Fast setup, centralized model hosting, but zero data sovereignty and high liability.
2. Local-First Containerized Platform: Self-hosted via Docker Compose, storing all data locally, supporting completely offline local LLMs (Ollama) or secure private on-premises API endpoints.

## Decision
We chose the **Local-First, Sovereign Deployment Model**.

Pentesa is distributed as a self-contained Docker Compose application that deploys on a security engineer's workstation or a private VPC server.
- All target data, logs, credentials, and reports remain strictly on-premises.
- Supports running 100% offline using a local Ollama container (running quantized Llama 3.1 8B or Qwen 2.5 14B).
- Optionally supports configuring a corporate on-premises or private OpenAI-compatible API endpoint if higher reasoning capacity is required.

## Consequences & Trade-offs
### Positive:
- Total data sovereignty: zero customer data or vulnerability disclosures leave the operator's perimeter.
- Works in air-gapped internal test environments.
- Zero per-scan cloud SaaS licensing or consumption fees.

### Negative:
- The operator must provide adequate local compute hardware (minimum 16GB RAM; recommended NVIDIA GPU with 12GB+ VRAM for local 14B models).
- Model updates and tool binary updates must be managed locally via container image pulls.

