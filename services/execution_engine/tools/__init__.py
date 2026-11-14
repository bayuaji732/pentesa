"""Security tools execution package."""

from services.execution_engine.tools.base import (
    BaseToolWrapper,
    ToolExecutionResult
)
from services.execution_engine.tools.http_client import RawHttpClient

__all__ = [
    "BaseToolWrapper",
    "ToolExecutionResult",
    "RawHttpClient",
    "ToolService"
]


def __getattr__(name: str):
    if name == "ToolService":
        from services.execution_engine.tools.service import ToolService
        return ToolService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
