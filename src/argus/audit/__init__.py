"""
argus.audit — second-pass auditing of LLM-produced reasoning.

Opus may hallucinate premises that look plausible. Before a chain
earns an ARS boost or a Wilson bundle, we re-check every premise it
claims to rest on against the actual source code. A premise of the
shape "file X at line L contains pattern P" is trivially falsifiable:
we open X, check near L, and grep for P. If the evidence isn't there,
the premise is marked unverified and the chain loses reproducibility
credit.

This is the Pillar-3 defense against sinkhole S4 (regulatory
defensibility): every claim in an ARGUS advisory is either verified
against source or flagged as unverified. Triagers can't accuse us of
running a black box when the audit trail shows which premises survived.
"""
from argus.audit.reasoning import (
    ReasoningAudit, Premise, PremiseVerdict, audit_chain_premises,
)

__all__ = [
    "ReasoningAudit", "Premise", "PremiseVerdict", "audit_chain_premises",
]
