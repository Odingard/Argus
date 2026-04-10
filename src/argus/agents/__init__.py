"""ARGUS Attack Agents.

Each agent is a specialized offensive AI agent targeting a distinct
AI-specific attack domain. Agents are short-lived, narrowly scoped,
and deployed simultaneously at T=0.

Phase 1 Agents:
  1. Prompt Injection Hunter — all input surfaces, direct/indirect/encoded/multi-step
  2. Tool Poisoning Agent — MCP tool definitions, hidden instructions, cross-tool chaining
  9. Supply Chain Agent — external MCP trust, dependency confusion, tool integrity
"""

from argus.agents.base import LLMAttackAgent
from argus.agents.prompt_injection import PromptInjectionHunter
from argus.agents.supply_chain import SupplyChainAgent
from argus.agents.tool_poisoning import ToolPoisoningAgent

__all__ = [
    "LLMAttackAgent",
    "PromptInjectionHunter",
    "ToolPoisoningAgent",
    "SupplyChainAgent",
]
