"""ARGUS Gauntlet — Scoring Engine.

Reads a tool's findings JSON file and produces a deterministic score
against the benchmark rubric. No human judgment required.

Usage:
    python score.py --findings findings.json
    python score.py --findings findings.json --scenario 01-poisoned-mcp
    python score.py --findings findings.json --output score-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

RUBRIC_PATH = Path(__file__).parent / "rubric.json"


def load_rubric() -> dict[str, Any]:
    return json.loads(RUBRIC_PATH.read_text())


def load_findings(findings_path: Path) -> dict[str, Any]:
    """Load findings JSON. Accepts either ARGUS report format or generic format.

    ARGUS format:
        {"findings": [{"agent_type": ..., "title": ..., "technique": ..., ...}]}

    Generic format:
        {"findings": [{"scenario": "01", "vulnerability": "...", "validated": bool}]}
    """
    return json.loads(findings_path.read_text())


def _finding_text(finding: dict[str, Any]) -> str:
    """Concatenate all text fields of a finding for indicator matching."""
    parts = [
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("technique", ""),
        finding.get("target_surface", ""),
        finding.get("agent_type", ""),
        str(finding.get("raw_request", "")),
        str(finding.get("raw_response", "")),
    ]
    # Include attack chain steps
    for step in finding.get("attack_chain", []) or []:
        parts.append(step.get("description", "") if isinstance(step, dict) else "")
        parts.append(step.get("technique", "") if isinstance(step, dict) else "")
    return " ".join(parts).lower()


def _matches_indicators(text: str, indicators: list[str]) -> bool:
    """Check if any indicator from the list appears in the text."""
    return any(ind.lower() in text for ind in indicators)


def _is_validated(finding: dict[str, Any]) -> bool:
    """Check if a finding is validated."""
    if finding.get("status") == "validated":
        return True
    validation = finding.get("validation")
    if isinstance(validation, dict) and validation.get("validated"):
        return True
    return False


def score_scenario(
    scenario_id: str,
    scenario_rubric: dict[str, Any],
    findings: list[dict[str, Any]],
    all_scenarios: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score a single scenario against findings.

    Returns a dict with detection/validation/chaining points and details.
    """
    result = {
        "scenario_id": scenario_id,
        "name": scenario_rubric.get("name", scenario_id),
        "difficulty": scenario_rubric.get("difficulty", "unknown"),
        "max_score": scenario_rubric.get("max_score", 6),
        "score": 0,
        "tiers": {
            "detection": {"earned": 0, "max": 1, "evidence": []},
            "validation": {"earned": 0, "max": 2, "evidence": []},
            "chaining": {"earned": 0, "max": 3, "evidence": []},
        },
        "vulnerabilities_found": [],
        "false_positives": [],
    }

    rubric_vulns = scenario_rubric.get("vulnerabilities", [])
    if not rubric_vulns:
        result["note"] = "Scenario rubric has no vulnerabilities defined (Phase 2+ scenario)"
        return result

    # Phase 1: detect which scenario vulnerabilities each finding maps to
    found_vuln_ids: set[str] = set()
    validated_vuln_ids: set[str] = set()

    for finding in findings:
        finding_text = _finding_text(finding)
        for vuln in rubric_vulns:
            if _matches_indicators(finding_text, vuln.get("indicators", [])):
                found_vuln_ids.add(vuln["id"])
                if _is_validated(finding):
                    validated_vuln_ids.add(vuln["id"])
                result["vulnerabilities_found"].append(
                    {
                        "vuln_id": vuln["id"],
                        "vuln_name": vuln["name"],
                        "finding_title": finding.get("title", ""),
                        "validated": _is_validated(finding),
                    }
                )

    # Phase 2: detect false positives (clean surfaces flagged as vulnerable)
    # A finding is only a FP for THIS scenario if:
    #   - it does NOT match any vulnerability in THIS scenario, AND
    #   - it does NOT match any vulnerability in ANY OTHER scenario
    # This prevents cross-scenario bleed (e.g., scenario 01's tool_output findings
    # being flagged as FP for scenario 02's clean tool_output surface).
    fp_surfaces = scenario_rubric.get("false_positive_surfaces", [])
    for finding in findings:
        finding_text = _finding_text(finding)

        # Skip findings that match real vulnerabilities for this scenario
        if any(
            _matches_indicators(finding_text, v.get("indicators", []))
            for v in rubric_vulns
        ):
            continue

        # Skip findings that match a vulnerability in any OTHER scenario
        if all_scenarios:
            matched_other = False
            for other_id, other_rubric in all_scenarios.items():
                if other_id == scenario_id:
                    continue
                for v in other_rubric.get("vulnerabilities", []):
                    if _matches_indicators(finding_text, v.get("indicators", [])):
                        matched_other = True
                        break
                if matched_other:
                    break
            if matched_other:
                continue

        finding_target = finding.get("target_surface", "").lower()

        for fp_surface in fp_surfaces:
            if fp_surface.lower() == finding_target:
                result["false_positives"].append(
                    {
                        "surface": fp_surface,
                        "finding_title": finding.get("title", ""),
                    }
                )
                break

    thresholds = scenario_rubric.get("tier_thresholds", {})

    # ----- Detection tier -----
    det_threshold = thresholds.get("detection", {}).get("min_vulnerabilities_found", 1)
    if len(found_vuln_ids) >= det_threshold:
        result["tiers"]["detection"]["earned"] = 1
        result["tiers"]["detection"]["evidence"] = sorted(found_vuln_ids)

    # ----- Validation tier -----
    val_threshold = thresholds.get("validation", {}).get("min_vulnerabilities_validated", 2)
    max_fp = thresholds.get("validation", {}).get("max_false_positives", 999)
    if len(validated_vuln_ids) >= val_threshold and len(result["false_positives"]) <= max_fp:
        result["tiers"]["validation"]["earned"] = 2
        result["tiers"]["validation"]["evidence"] = sorted(validated_vuln_ids)

    # ----- Chaining tier -----
    chain_required = thresholds.get("chaining", {}).get("compound_chain_required", False)
    if chain_required:
        compound_chain = scenario_rubric.get("compound_chain", {})
        chain_indicators = compound_chain.get("indicators", [])
        # Look for compound paths in findings
        compound_paths = []
        for finding in findings:
            finding_text = _finding_text(finding)
            if _matches_indicators(finding_text, chain_indicators):
                compound_paths.append(finding.get("title", "compound"))
        # Also check the top-level "compound_attack_paths" field if present
        if compound_paths:
            result["tiers"]["chaining"]["earned"] = 3
            result["tiers"]["chaining"]["evidence"] = compound_paths[:5]

    result["score"] = (
        result["tiers"]["detection"]["earned"]
        + result["tiers"]["validation"]["earned"]
        + result["tiers"]["chaining"]["earned"]
    )
    return result


def score_all(rubric: dict[str, Any], findings_doc: dict[str, Any]) -> dict[str, Any]:
    """Score all scenarios. Returns full report."""
    findings = findings_doc.get("findings", [])
    compound_paths = findings_doc.get("compound_attack_paths", [])

    # Treat compound paths as additional findings for chaining detection
    enriched_findings = list(findings)
    for path in compound_paths:
        # Synthesize a finding-like object for compound path matching
        enriched_findings.append(
            {
                "title": path.get("title", "compound attack"),
                "description": path.get("description", ""),
                "technique": "compound_chain",
                "attack_chain": path.get("attack_path_steps", []),
                "raw_response": path.get("compound_impact", ""),
            }
        )

    scenarios = rubric.get("scenarios", {})
    scenario_results = {}
    total_earned = 0
    total_max = 0

    for scenario_id, scenario_rubric in scenarios.items():
        result = score_scenario(scenario_id, scenario_rubric, enriched_findings, all_scenarios=scenarios)
        scenario_results[scenario_id] = result
        total_earned += result["score"]
        total_max += result["max_score"]

    return {
        "benchmark": rubric.get("benchmark", "ARGUS Gauntlet"),
        "version": rubric.get("version", "1.0.0"),
        "total_score": total_earned,
        "total_max": total_max,
        "percentage": round(100 * total_earned / total_max, 2) if total_max else 0,
        "scenarios": scenario_results,
    }


def render_text_report(report: dict[str, Any]) -> str:
    """Render a human-readable text report."""
    lines = [
        "=" * 70,
        f"  {report['benchmark']} — Score Report",
        "=" * 70,
        f"  Total Score: {report['total_score']}/{report['total_max']} ({report['percentage']}%)",
        "=" * 70,
        "",
    ]

    for scenario_id, result in report["scenarios"].items():
        lines.append(f"  [{result['difficulty'].upper()}] {scenario_id} — {result['name']}")
        lines.append(f"    Score: {result['score']}/{result['max_score']}")
        if result.get("note"):
            lines.append(f"    Note: {result['note']}")
        else:
            for tier_name, tier_data in result["tiers"].items():
                status = "PASS" if tier_data["earned"] == tier_data["max"] else "FAIL"
                lines.append(
                    f"    {tier_name.title():12s}: {tier_data['earned']}/{tier_data['max']}  [{status}]"
                )
            if result["vulnerabilities_found"]:
                lines.append(f"    Vulnerabilities found: {len(result['vulnerabilities_found'])}")
            if result["false_positives"]:
                lines.append(f"    False positives: {len(result['false_positives'])}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="ARGUS Gauntlet — Scoring Engine")
    parser.add_argument("--findings", type=Path, required=True, help="Path to findings JSON file")
    parser.add_argument("--scenario", type=str, help="Score only a specific scenario (e.g., 01-poisoned-mcp)")
    parser.add_argument("--output", type=Path, help="Write JSON report to file")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout instead of text")
    args = parser.parse_args()

    if not args.findings.exists():
        print(f"ERROR: findings file not found: {args.findings}", file=sys.stderr)
        return 1

    rubric = load_rubric()
    findings_doc = load_findings(args.findings)

    report = score_all(rubric, findings_doc)

    if args.scenario:
        if args.scenario not in report["scenarios"]:
            print(f"ERROR: scenario {args.scenario} not in rubric", file=sys.stderr)
            return 1
        report = {
            "benchmark": report["benchmark"],
            "scenarios": {args.scenario: report["scenarios"][args.scenario]},
        }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text_report(report))

    if args.output:
        args.output.write_text(json.dumps(report, indent=2))
        print(f"\nReport written to: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
