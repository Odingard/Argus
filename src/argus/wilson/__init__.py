"""
argus.wilson — Wilson-Proof forensic bundle packager.

A "Wilson Bundle" is a reproducible, signed artifact set for a single
validated exploit chain. It's what a bug-bounty triage officer (the
"Wilson") needs to stop marking findings as "theoretical" and start
paying them out:

  - chain.json        — the exploit chain exactly as ARGUS synthesized it
  - poc.py            — the real-library PoC the sandbox ran
  - sandbox_stdout.txt — verbatim Docker stdout that proves it landed
  - fingerprint.json  — L0 target version + git tag + scan date
  - pheromone.jsonl   — relevant slice of the swarm blackboard log
  - rationale.md      — correlator / Opus reasoning for this chain
  - manifest.json     — SHA-256 of every file in the bundle, plus a
                        HMAC over the manifest keyed on the run_id so the
                        bundle is tamper-evident
  - README.md         — triager-readable summary with copy/paste repro

This is the kinetic-verification pillar: evidence defensible enough that
a rejection has to come with specific technical reasoning, not a blanket
"not reproducible".
"""
from argus.wilson.bundle import WilsonBundle, build_bundle_for_chain

__all__ = ["WilsonBundle", "build_bundle_for_chain"]
