"""
argus.swarm — cross-agent chain synthesis.

ARGUS's coordinated 12-agent swarm runtime lives in
``argus.engagement.runner`` — it iterates the agent slate, collects
findings, and feeds them through the chain synthesiser here. Chain
synthesis is the patent-claimed "live correlation" piece; the
orchestration around it is engagement-runner-side.

This package used to carry a blackboard + live correlator + thread-
pool runtime (removed 2026-04-24). That architecture was built for
static-scan-era agents that took ``(target, repo_path)`` constructor
args; modern agents require an ``adapter_factory`` so the runtime
doesn't fit. Chain synthesis v2 is the live piece; the rest is
history.
"""
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain

__all__ = ["synthesize_compound_chain"]
