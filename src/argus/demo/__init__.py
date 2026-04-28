"""argus.demo — packaged end-to-end demo runs.

Each demo is a self-contained, reproducible ARGUS engagement against
a labrat target that exercises a specific attack class end-to-end
and produces the full artifact package an operator would ship to a
customer:

    results/
      findings/         per-agent JSON finding files
      evidence/         DeterministicEvidence JSON (pcap / logs / OOB)
      chain.json        CompoundChain v2 with OWASP Agentic Top-10 map
      impact.json       BlastRadiusMap with harm score + regulatory tags
      SUMMARY.txt       one-screen operator summary

Public Core ships ``evolver`` only — a corpus-evolution demo that
shows MAP-Elites elite-promotion from a seed corpus to a diverse
high-fitness grid. Multi-agent end-to-end demos (crewAI roster,
generic-agent showcase) live in the Enterprise tree alongside the
full 11-agent kit.
"""
from argus.demo.evolver import run as run_evolver

__all__ = ["run_evolver"]
