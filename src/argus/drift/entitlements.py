"""
argus/drift/entitlements.py — cumulative per-agent entitlement drift (sinkhole S3).

Autonomous agents are high-privilege identities. Over an engagement
they tend to accumulate access to more tools / files / resources than
they started with — that's the Privilege Accumulation Trap. This
module walks a series of ARGUS run directories in chronological order
and tracks, per agent, the cumulative set of:

  - tool / technique names the agent produced findings about
  - files the agent flagged
  - vuln classes the agent has emitted

Each new run adds to the agent's cumulative set. We flag agents whose
set grew in the current run compared to the prior baseline — those are
the agents whose effective scope is expanding.

Not prescriptive about "good" or "bad" growth — the operator decides
whether a given expansion is warranted. The value is visibility, not
an automatic block.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class EntitlementSnapshot:
    agent_id:       str
    run_dir:        str
    tools:          set[str]     = field(default_factory=set)
    files:          set[str]     = field(default_factory=set)
    vuln_classes:   set[str]     = field(default_factory=set)
    finding_count:  int          = 0


@dataclass
class EntitlementDriftReport:
    runs_seen:      list[str]    = field(default_factory=list)
    per_agent:      dict[str, list[EntitlementSnapshot]] = field(default_factory=dict)
    growths:        list[dict]   = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "runs_seen": list(self.runs_seen),
            "per_agent": {
                aid: [
                    {
                        "run_dir":       s.run_dir,
                        "tools":         sorted(s.tools),
                        "files":         sorted(s.files),
                        "vuln_classes":  sorted(s.vuln_classes),
                        "finding_count": s.finding_count,
                    }
                    for s in snaps
                ]
                for aid, snaps in self.per_agent.items()
            },
            "growths": list(self.growths),
        }


# ── Loader ────────────────────────────────────────────────────────────────────

def _snapshot_run(run_dir: Path) -> dict[str, EntitlementSnapshot]:
    """Return {agent_id: EntitlementSnapshot} for one run."""
    agents_dir = run_dir / "agents"
    out: dict[str, EntitlementSnapshot] = {}
    if not agents_dir.exists():
        return out
    for agent_subdir in sorted(agents_dir.iterdir()):
        if not agent_subdir.is_dir():
            continue
        for findings_file in agent_subdir.glob("*_findings.json"):
            try:
                data = json.loads(findings_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            agent_id = data.get("agent_id") or agent_subdir.name
            snap = out.setdefault(agent_id, EntitlementSnapshot(
                agent_id=agent_id, run_dir=str(run_dir),
            ))
            for f in data.get("findings", []):
                snap.finding_count += 1
                if f.get("technique"):
                    snap.tools.add(f["technique"])
                if f.get("file"):
                    snap.files.add(f["file"])
                if f.get("vuln_class"):
                    snap.vuln_classes.add(f["vuln_class"])
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def entitlement_drift(run_dirs: Iterable[str]) -> EntitlementDriftReport:
    """
    Walk ``run_dirs`` in the given order (chronological = caller's
    responsibility — typically sorted by run timestamp) and accumulate
    per-agent entitlement sets. Flag each run where any agent's
    cumulative set grew.
    """
    report = EntitlementDriftReport()
    cumulative: dict[str, EntitlementSnapshot] = {}

    for run_dir_str in run_dirs:
        run_dir = Path(run_dir_str)
        report.runs_seen.append(str(run_dir))
        snaps = _snapshot_run(run_dir)

        for agent_id, fresh in snaps.items():
            cum = cumulative.setdefault(agent_id, EntitlementSnapshot(
                agent_id=agent_id, run_dir=str(run_dir),
            ))
            prev_sizes = (
                len(cum.tools), len(cum.files), len(cum.vuln_classes)
            )

            cum.tools        |= fresh.tools
            cum.files        |= fresh.files
            cum.vuln_classes |= fresh.vuln_classes
            cum.finding_count += fresh.finding_count
            cum.run_dir = str(run_dir)

            new_sizes = (
                len(cum.tools), len(cum.files), len(cum.vuln_classes)
            )
            grew = {
                k: (old, new)
                for k, old, new in zip(
                    ("tools", "files", "vuln_classes"),
                    prev_sizes, new_sizes,
                )
                if new > old
            }
            if grew:
                report.growths.append({
                    "run_dir":  str(run_dir),
                    "agent_id": agent_id,
                    "grew":     grew,
                })

            # Snapshot the per-run state for history
            report.per_agent.setdefault(agent_id, []).append(
                EntitlementSnapshot(
                    agent_id=agent_id, run_dir=str(run_dir),
                    tools=set(cum.tools), files=set(cum.files),
                    vuln_classes=set(cum.vuln_classes),
                    finding_count=cum.finding_count,
                )
            )

    return report


def render_entitlement_text(report: EntitlementDriftReport) -> str:
    lines: list[str] = []
    lines.append(f"Entitlement drift across {len(report.runs_seen)} run(s)")
    for r in report.runs_seen:
        lines.append(f"  - {r}")
    lines.append("")

    if not report.per_agent:
        lines.append("No agent findings in any of these runs.")
        return "\n".join(lines)

    # Current cumulative state, sorted by most-entitled first.
    last_snapshots = {
        aid: snaps[-1] for aid, snaps in report.per_agent.items() if snaps
    }
    ranked = sorted(
        last_snapshots.values(),
        key=lambda s: -(len(s.tools) + len(s.files) + len(s.vuln_classes)),
    )
    lines.append("Top cumulative entitlements (at latest run):")
    for s in ranked[:10]:
        lines.append(
            f"  {s.agent_id:<8s}  tools={len(s.tools):>3}  "
            f"files={len(s.files):>4}  vuln_classes={len(s.vuln_classes):>2}  "
            f"total_findings={s.finding_count}"
        )

    if report.growths:
        lines.append("")
        lines.append("Growth events (agent scope expanded this run):")
        for g in report.growths[-15:]:
            bits = ", ".join(
                f"{k}: {old}→{new}" for k, (old, new) in g["grew"].items()
            )
            lines.append(f"  {g['run_dir']}: {g['agent_id']}  {bits}")

    return "\n".join(lines)
