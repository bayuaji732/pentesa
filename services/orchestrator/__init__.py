"""Orchestrator package."""

from services.orchestrator.state import PentestWorkflowState

__all__ = ["PentestWorkflowState", "WorkflowSupervisor"]

def __getattr__(name: str):
    if name == "WorkflowSupervisor":
        from services.orchestrator.supervisor import WorkflowSupervisor
        return WorkflowSupervisor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

