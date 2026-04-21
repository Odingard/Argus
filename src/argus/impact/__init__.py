"""
argus.impact — Phase 9 Impact Optimization.

Per Agent_Specs.docx §Impact Optimization: "the final step of the
Mythos-Aligned Attack Chain is Impact. A finding without a blast
radius is a bug report. A finding with a blast radius is a
business case. ARGUS renders every validated chain as a
BlastRadiusMap so the operator can answer, on the spot: 'if we
don't fix this, what exactly is at stake?'"

Two cooperating modules:

  classify      Pure-function data classification — identify PII,
                PCI, HIPAA, secret-shape, and regulatory-tagged
                content in the evidence reached by the chain. No
                LLM in the classification path.

  optimizer     Compound-chain → BlastRadiusMap synthesis. Walks
                the chain's steps + every step's evidence artifacts,
                attaches classified data, then applies a trust-
                transitivity model to expand from directly-reached
                surfaces to the transitively-reachable ecosystem.
                Emits a regulatory-impact set and a numeric harm
                score so the Wilson bundle carries a prioritised
                remediation narrative.
"""
from argus.impact.classify import (
    DataClassification, DataClass, classify_text, classify_evidence,
)
from argus.impact.optimizer import (
    BlastRadiusMap, TrustEdge, optimize_impact,
)

__all__ = [
    "DataClassification", "DataClass", "classify_text", "classify_evidence",
    "BlastRadiusMap", "TrustEdge", "optimize_impact",
]
