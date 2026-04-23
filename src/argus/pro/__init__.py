"""
argus.pro — commercial / source-available tier.

Modules placed under this package are gated by `argus.license.require()`
at import time. Today the gate is a stub that always permits access;
the seam exists so that when the first paying PRO customer lands, the
gate tightens in one place without touching any PRO module.

What belongs here (planned):
    - mcts/        Monte Carlo Tree Search exploit-chain planner
    - consensus/   Multi-model agreement gate for CRITICAL findings
    - fleet/       Redis/SQS-backed webhook store + worker pool
    - pcap/        eBPF / tcpdump L7 traffic capture
    - wilson_ent/  HSM-backed signing key lifecycle

What does NOT belong here:
    - Anything an OSS community user needs to run the 12 agents
    - Anything required for the published PyPI `argus-core` package
    - Stubs or placeholders — features land here only when working

Every new submodule must call `argus.license.require("<name>")` at
module top-level so absence of a license fails fast and loud rather
than mid-run.
"""
from __future__ import annotations

from argus.license import LicenseError, require, has, subject

__all__ = ["LicenseError", "require", "has", "subject"]
