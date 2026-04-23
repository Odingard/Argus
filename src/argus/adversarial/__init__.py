"""
argus.adversarial — attacker-side tooling.

Everything ARGUS has been about attacking DEPLOYED AI systems.
This module is the other side of that coin — tools ARGUS uses AS
the attacker:

  typosquat         scans npm + PyPI for typosquats of legit MCP
                    packages. Any package whose name is a homoglyph /
                    edit-distance-1 / scope-lookalike of a legitimate
                    server, and which actually exists in a registry,
                    is a publishable supply-chain finding.

  mcp_server        a real MCP server we control, with deliberately
                    poisoned tool / prompt / resource definitions.
                    Point a target AI client at this server and
                    observe whether the client rejects it, warns the
                    operator, or silently installs its tools.

Per the integrity contract: this module exists to DEMONSTRATE attack
classes that exist in the wild. Nothing here ships payloads that
compromise production systems — the adversarial MCP server only ever
produces poisoned metadata, never exec primitives.
"""
from argus.adversarial.typosquat import (
    Squat, TyposquatResult, TyposquatScanner, scan,
)

__all__ = ["Squat", "TyposquatResult", "TyposquatScanner", "scan"]
