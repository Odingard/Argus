"""
argus/shared/ars.py — Argus Risk Score (ARS).

Composite 0–100 score per finding and per chain. Replaces raw CVSS as the
headline number on the ARGUS dashboard. Auditable: every input is visible
in the breakdown, so a triage officer can reconstruct why a chain scored
87 vs 45. No black-box scoring.

ARS formula:

    severity_points      (0–40)   from AgentFinding.severity / chain blast
    blast_points         (0–30)   from chain blast radius (chain-only)
    reproducibility      (0–15)   L7 validated = 15, unvalidated = 0
    exploitability       (0–15)   confidence × entry_weight / preconditions
                                           score             multiplier
    asset_multiplier     client-provided, default 1.0 (0.5 suppresses
                                          non-critical assets, 1.5 boosts)

    ARS = min(100, round((s + b + r + e) * asset_multiplier))

Compared against CASI (Composite Agentic Severity Index) in industry
literature: we expose the same axes but compute fully locally, no
third-party dependency, and we publish the breakdown next to the number
so operators aren't asked to trust a scalar on faith.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ── Coefficient tables (auditable) ────────────────────────────────────────────

_SEVERITY_POINTS = {
    "CRITICAL": 40,
    "HIGH":     28,
    "MEDIUM":   15,
    "LOW":       5,
}

_BLAST_POINTS = {
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       3,
}

_ENTRY_WEIGHT = {
    "unauthenticated": 1.00,
    "network":         0.85,
    "low_priv":        0.65,
    "authenticated":   0.45,
    "local":           0.35,
    "unknown":         0.55,
}


# ── Output shape ──────────────────────────────────────────────────────────────

@dataclass
class ARSBreakdown:
    """Per-component contributions that sum into the final ARS."""
    severity_points:      int   = 0    # 0–40
    blast_points:         int   = 0    # 0–30
    reproducibility:      int   = 0    # 0–15
    exploitability:       int   = 0    # 0–15
    asset_multiplier:     float = 1.0
    score:                int   = 0    # 0–100, rounded
    rationale:            list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity_points":      self.severity_points,
            "blast_points":          self.blast_points,
            "reproducibility":       self.reproducibility,
            "exploitability":        self.exploitability,
            "asset_multiplier":      self.asset_multiplier,
            "score":                 self.score,
            "rationale":             list(self.rationale),
        }


# ── Scoring — findings ────────────────────────────────────────────────────────

def score_finding(
    severity:              str,
    is_validated:          bool = False,
    confidence:            float = 0.5,
    entry_point:           str = "unknown",
    preconditions_count:   int = 0,
    asset_multiplier:      float = 1.0,
) -> ARSBreakdown:
    """
    Score a single AgentFinding. Findings don't have a blast_radius of
    their own (that's a chain concept), so the blast slot mirrors
    severity at half weight.
    """
    b = ARSBreakdown(asset_multiplier=_clamp(asset_multiplier, 0.5, 1.5))

    sev = (severity or "LOW").upper()
    b.severity_points = _SEVERITY_POINTS.get(sev, 0)
    b.blast_points    = _BLAST_POINTS.get(sev, 0) // 2   # half weight for atomic findings
    b.reproducibility = 15 if is_validated else 0

    ew = _ENTRY_WEIGHT.get((entry_point or "unknown").lower(), 0.55)
    pre_damp = 1.0 / max(preconditions_count, 1)
    b.exploitability = int(round(15 * _clamp(confidence, 0.0, 1.0) * ew * pre_damp))

    raw = b.severity_points + b.blast_points + b.reproducibility + b.exploitability
    b.score = min(100, max(0, int(round(raw * b.asset_multiplier))))

    b.rationale = [
        f"severity {sev} → {b.severity_points} pts",
        f"blast (half-weight, atomic) → {b.blast_points} pts",
        f"reproducibility {'validated' if is_validated else 'unvalidated'} "
        f"→ {b.reproducibility} pts",
        f"exploitability {confidence:.2f} × entry({entry_point})={ew:.2f} / "
        f"pre={max(preconditions_count, 1)} → {b.exploitability} pts",
        f"asset multiplier × {b.asset_multiplier:.2f}",
    ]
    return b


# ── Scoring — chains ──────────────────────────────────────────────────────────

def score_chain(
    severity:         str = "",          # optional override; else derive from blast
    blast_radius:     str = "MEDIUM",
    is_validated:     bool = False,
    combined_score:   float = 0.5,       # Opus-reported confidence 0–1
    entry_point:      str = "unknown",
    preconditions_count: int = 0,
    asset_multiplier: float = 1.0,
) -> ARSBreakdown:
    """
    Score an ExploitChain. The chain carries its own blast radius
    separate from severity, and a combined_score that serves as our
    confidence signal.
    """
    b = ARSBreakdown(asset_multiplier=_clamp(asset_multiplier, 0.5, 1.5))

    # If no explicit severity, inherit from blast radius.
    sev = (severity or blast_radius or "MEDIUM").upper()
    b.severity_points = _SEVERITY_POINTS.get(sev, 0)
    b.blast_points    = _BLAST_POINTS.get((blast_radius or "MEDIUM").upper(), 0)
    b.reproducibility = 15 if is_validated else 0

    ew = _ENTRY_WEIGHT.get((entry_point or "unknown").lower(), 0.55)
    pre_damp = 1.0 / max(preconditions_count, 1)
    b.exploitability = int(round(15 * _clamp(combined_score, 0.0, 1.0) * ew * pre_damp))

    raw = b.severity_points + b.blast_points + b.reproducibility + b.exploitability
    b.score = min(100, max(0, int(round(raw * b.asset_multiplier))))

    b.rationale = [
        f"severity {sev} → {b.severity_points} pts",
        f"blast {blast_radius or 'MEDIUM'} → {b.blast_points} pts",
        f"reproducibility {'validated' if is_validated else 'unvalidated'} "
        f"→ {b.reproducibility} pts",
        f"exploitability combined={combined_score:.2f} × "
        f"entry({entry_point})={ew:.2f} / pre={max(preconditions_count, 1)} "
        f"→ {b.exploitability} pts",
        f"asset multiplier × {b.asset_multiplier:.2f}",
    ]
    return b


# ── Banding (optional, for dashboards) ────────────────────────────────────────

def band(score: int) -> str:
    if score >= 85:   return "CRITICAL"
    if score >= 65:   return "HIGH"
    if score >= 40:   return "MEDIUM"
    if score >= 20:   return "LOW"
    return "INFO"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))
