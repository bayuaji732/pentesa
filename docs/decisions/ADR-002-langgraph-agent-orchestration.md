# ADR-002: LangGraph for State Machine Multi-Agent Orchestration

## Status
Accepted

## Context
Pentesa requires an AI agent orchestration system to coordinate 15 specialized agents through a multi-phase penetration testing lifecycle: reconnaissance, surface mapping, WSTG test planning, specialized vulnerability testing, validation, false positive analysis, and reporting.

We evaluated three candidate orchestration frameworks:
1. Microsoft AutoGen: Conversational multi-agent framework based on free-form message exchanges.
2. CrewAI: Role-based sequential/hierarchical agent execution framework.
3. LangGraph: Directed graph-based orchestration framework with explicit state transitions, cyclic loops, and durable checkpointing.

## Decision
We chose **LangGraph** (backed by LangChain Core).

## Rationale & Justification
- **Stateful Directed Graphs:** Offensive security workflows are inherently state-driven. Phase gates (e.g. "Do not begin scanning until discovery is complete") map directly to directed graph edges.
- **Cyclic Graph Support:** Vulnerability testing and validation require loops (detect $\to$ probe $\to$ verify $\to$ retry). LangGraph natively supports cyclical graphs without infinite recursion.
- **Durable Checkpointing (`PostgresSaver`):** Security scans can run for hours. LangGraph persists full graph state to PostgreSQL after every node execution. If a worker container crashes or restarts, the workflow resumes seamlessly from the last state.
- **Human-in-the-Loop Interceptors:** LangGraph provides native support for interrupting graph execution before high-risk nodes (e.g. directory fuzzing $> 5,000$ requests) and resuming upon operator approval.

## Consequences & Trade-offs
### Positive:
- Predictable token consumption and execution flow compared to unconstrained conversational agents.
- Full observability into agent transitions and state diffs.
- Clean separation between agent reasoning nodes and deterministic tool execution nodes.

### Negative:
- Steeper learning curve than linear chaining libraries.
- Requires strict typing and schema serialization across all graph state variables.

