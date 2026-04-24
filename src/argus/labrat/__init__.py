"""
argus.labrat — in-process target simulation framework.

Each ``*_shaped`` module ships an ARGUS adapter that behaves like a
real deployment of the named framework (crewAI, AutoGen, LangGraph,
LlamaIndex, Parlant, Hermes). The engagement registry wires each to
its corresponding scheme (``crewai://labrat``, ``autogen://labrat``,
etc.) so ``argus <scheme>://labrat`` drops straight into a ready
target.

These are in-process adapters — no Docker, no network isolation.
When an operator wants a fully-sandboxed (containerised) target they
launch a real MCP server subprocess under ``argus --sandbox``, which
wraps it in ``docker run --network none --read-only --cap-drop ALL``
via ``argus.adapter.sandboxed_stdio``. That is the production path
for untrusted-server isolation.
"""
from argus.labrat.crewai_shaped import CrewAILabrat
from argus.labrat.autogen_shaped import AutoGenLabrat
from argus.labrat.langgraph_shaped import LangGraphLabrat
from argus.labrat.llamaindex_shaped import LlamaIndexLabrat
from argus.labrat.parlant_shaped import ParlantLabrat
from argus.labrat.hermes_shaped import HermesLabrat

__all__ = [
    "CrewAILabrat", "AutoGenLabrat", "LangGraphLabrat",
    "LlamaIndexLabrat", "ParlantLabrat", "HermesLabrat",
]
