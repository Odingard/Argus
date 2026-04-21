"""
argus/drift/compare.py — diff two ARGUS run directories (sinkhole S1).

Context drift is the "ghost vulnerability" problem: a finding reported
on Monday may be silently patched (or silently re-worded, or silently
deprioritised) by a model / prompt update on Tuesday. If we don't
compare runs we happily re-report ghosts and miss regressions.

compare_runs(prior_dir, current_dir) emits a DriftReport with:

  - ghosts   findings / chains in prior that are NOT in current
             (patched, silenced, or lost)
  - new      findings / chains in current that were NOT in prior
             (regression or new feature surface)
  - changed  same id, different severity / blast_radius / is_validated
             (something about this finding moved; inspect why)
  - unchanged  present on both sides with identical shape

Pure-offline: loads layer1.json + layer5.json from each run. No LLM
call. Safe to run as part of CI nightly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class FindingDiff:
    id:      str
    kind:    str            # "finding" | "chain"
    status:  str            # "ghost" | "new" | "changed" | "unchanged"
    prior:   Optional[dict] = None
    current: Optional[dict] = None
    delta:   dict = field(default_factory=dict)  # key -> (before, after)


@dataclass
class DriftReport:
    prior_dir:    str
    current_dir:  str
    findings:     list[FindingDiff] = field(default_factory=list)
    chains:       list[FindingDiff] = field(default_factory=list)

    @property
    def ghost_findings(self) -> list[FindingDiff]:
        return [f for f in self.findings if f.status == "ghost"]

    @property
    def new_findings(self) -> list[FindingDiff]:
        return [f for f in self.findings if f.status == "new"]

    @property
    def changed_findings(self) -> list[FindingDiff]:
        return [f for f in self.findings if f.status == "changed"]

    @property
    def ghost_chains(self) -> list[FindingDiff]:
        return [f for f in self.chains if f.status == "ghost"]

    @property
    def new_chains(self) -> list[FindingDiff]:
        return [f for f in self.chains if f.status == "new"]

    def to_dict(self) -> dict:
        return {
            "prior_dir":    self.prior_dir,
            "current_dir":  self.current_dir,
            "findings": {
                "ghosts":    [d.__dict__ for d in self.ghost_findings],
                "new":       [d.__dict__ for d in self.new_findings],
                "changed":   [d.__dict__ for d in self.changed_findings],
            },
            "chains": {
                "ghosts":    [d.__dict__ for d in self.ghost_chains],
                "new":       [d.__dict__ for d in self.new_chains],
            },
        }


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_layer1_findings(run_dir: Path) -> dict[str, dict]:
    path = run_dir / "layer1.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    out: dict[str, dict] = {}
    for f in (data.get("production_findings", []) + data.get("example_findings", [])):
        fid = f.get("id") or f.get("title")
        if fid:
            out[fid] = f
    return out


def _load_layer5_chains(run_dir: Path) -> dict[str, dict]:
    path = run_dir / "layer5.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {c.get("chain_id"): c for c in data.get("chains", []) if c.get("chain_id")}


# ── Comparators ───────────────────────────────────────────────────────────────

_WATCHED_FINDING_FIELDS = ("severity", "vuln_class", "file", "title")
_WATCHED_CHAIN_FIELDS   = ("blast_radius", "is_validated", "combined_score",
                           "cvss_estimate", "entry_point")


def _diff_fields(a: dict, b: dict, fields: tuple[str, ...]) -> dict:
    out: dict[str, tuple[Any, Any]] = {}
    for k in fields:
        va, vb = a.get(k), b.get(k)
        if va != vb:
            out[k] = (va, vb)
    return out


def compare_runs(prior_dir: str, current_dir: str) -> DriftReport:
    prior = Path(prior_dir)
    current = Path(current_dir)
    report = DriftReport(prior_dir=str(prior), current_dir=str(current))

    # Findings (L1)
    prior_findings   = _load_layer1_findings(prior)
    current_findings = _load_layer1_findings(current)
    all_ids = set(prior_findings) | set(current_findings)
    for fid in sorted(all_ids):
        p = prior_findings.get(fid)
        c = current_findings.get(fid)
        if p and not c:
            report.findings.append(FindingDiff(id=fid, kind="finding",
                                               status="ghost", prior=p))
        elif c and not p:
            report.findings.append(FindingDiff(id=fid, kind="finding",
                                               status="new", current=c))
        elif p and c:
            delta = _diff_fields(p, c, _WATCHED_FINDING_FIELDS)
            status = "changed" if delta else "unchanged"
            report.findings.append(FindingDiff(
                id=fid, kind="finding", status=status,
                prior=p, current=c, delta=delta,
            ))

    # Chains (L5)
    prior_chains   = _load_layer5_chains(prior)
    current_chains = _load_layer5_chains(current)
    all_cids = set(prior_chains) | set(current_chains)
    for cid in sorted(all_cids):
        p = prior_chains.get(cid)
        c = current_chains.get(cid)
        if p and not c:
            report.chains.append(FindingDiff(id=cid, kind="chain",
                                             status="ghost", prior=p))
        elif c and not p:
            report.chains.append(FindingDiff(id=cid, kind="chain",
                                             status="new", current=c))
        elif p and c:
            delta = _diff_fields(p, c, _WATCHED_CHAIN_FIELDS)
            status = "changed" if delta else "unchanged"
            report.chains.append(FindingDiff(
                id=cid, kind="chain", status=status,
                prior=p, current=c, delta=delta,
            ))

    return report


def render_drift_text(report: DriftReport) -> str:
    lines: list[str] = []
    lines.append(f"Drift: {report.prior_dir}  →  {report.current_dir}")
    lines.append(f"")
    lines.append(f"Findings:")
    lines.append(f"  ghosts   {len(report.ghost_findings):>4}")
    lines.append(f"  new      {len(report.new_findings):>4}")
    lines.append(f"  changed  {len(report.changed_findings):>4}")
    lines.append(f"Chains:")
    lines.append(f"  ghosts   {len(report.ghost_chains):>4}")
    lines.append(f"  new      {len(report.new_chains):>4}")
    lines.append(f"")

    if report.ghost_findings:
        lines.append("Top ghost findings (candidates for 'ghost vulnerability' flag):")
        for d in report.ghost_findings[:10]:
            pf = d.prior or {}
            lines.append(f"  GHOST [{pf.get('severity','?')}] "
                         f"{pf.get('vuln_class','?')} {d.id}: "
                         f"{(pf.get('title','') or '')[:72]}")
        lines.append("")

    if report.new_findings:
        lines.append("Top new findings (regressions or new surface):")
        for d in report.new_findings[:10]:
            cf = d.current or {}
            lines.append(f"  NEW   [{cf.get('severity','?')}] "
                         f"{cf.get('vuln_class','?')} {d.id}: "
                         f"{(cf.get('title','') or '')[:72]}")
        lines.append("")

    if report.changed_findings:
        lines.append("Changed findings (same id, moved values):")
        for d in report.changed_findings[:10]:
            lines.append(f"  CHG   {d.id}: {d.delta}")

    return "\n".join(lines)
