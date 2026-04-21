"""
argus.swarm — true multi-agent coordination runtime.

Replaces the thread-pool `_run_parallel_swarm` in cli.py with a coordinated
swarm: shared blackboard, supervisor that reprioritizes work dynamically,
continuous correlator that fires chain hypotheses in-flight, and a
devil's-advocate worker that filters hallucinations before they ever reach
the L7 sandbox.

See README / memory for the patent mapping: parallel specialized agents +
live correlation + deterministic validation. The thread pool gave us the
first. The swarm gives us the second. L7 was already the third.
"""
from argus.swarm.blackboard import Blackboard, HotFile, ChainHypothesis

__all__ = ["Blackboard", "HotFile", "ChainHypothesis"]
