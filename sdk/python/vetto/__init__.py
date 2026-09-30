"""Vetto Python SDK: rootless kernel-level sandbox and policy enforcement runtime.

Provides single-line execution containment for AI agent frameworks (CrewAI,
AutoGen, LangGraph, OpenHands, Smolagents) with strict fail-closed Exit 125
semantics and sub-4ms cold-start latency.
"""

from __future__ import annotations

from vetto.langgraph import VettoExecutionTool, VettoToolNode
from vetto.policy import PolicyBuilder
from vetto.sandbox import (
    VettoError,
    VettoNotFoundError,
    VettoResult,
    VettoSandbox,
    VettoSecurityError,
    VettoTimeoutError,
)

__version__ = "0.5.13"

__all__ = [
    "VettoSandbox",
    "VettoResult",
    "VettoError",
    "VettoSecurityError",
    "VettoTimeoutError",
    "VettoNotFoundError",
    "VettoToolNode",
    "VettoExecutionTool",
    "PolicyBuilder",
]
