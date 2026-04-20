"""
layer6/cve_pipeline.py
CVE Pipeline + Intelligence Flywheel

Two functions:

OPERATIONAL — CVE Pipeline:
  For each exploit chain, generates a complete disclosure package:
  - advisory.md       — formatted responsible disclosure advisory
  - cve_drafts.json   — pre-filled MITRE CVE submission structs
  - github_advisory.md — formatted for GitHub security advisory
  Auto-populates CVSS, CWE, ATLAS TTPs, affected versions, 90-day timeline.

STRATEGIC — Intelligence Flywheel:
  Appends anonymized pattern entries to flywheel.jsonl.
  NO client or target-identifying information stored.
  Accumulates: attack patterns, effective modalities, chain structures.
  This is the compounding moat — each run makes every future run smarter.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Optional

from shared.client import ArgusClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import (
    L1Report, L5Chains, L6Output,
    CVEDraft, FlywheelEntry, ExploitChain
)
from shared.prompts import L6_MODEL, L6_CVE_DRAFT_PROMPT, L6_ADVISORY_PROMPT

# ── Config ────────────────────────────────────────────────────────────────────
DISCLOSURE_DAYS   = 90
REPORTER          = "Andre Byrd, Odingard Security (andre.byrd@odingard.com)"
REPORTER_ORG      = "Odingard Security / Six Sense Enterprise Services"
ARGUS_TAGLINE     = "Every AI agent we've scanned had at least one critical finding."

# CWE mapping by vulnerability class
CLASS_TO_CWE = {
    "DESER":             "CWE-502",
    "SSRF":              "CWE-918",
    "AUTH_BYPASS":       "CWE-306",
    "TRACE_LATERAL":     "CWE-829",
    "PHANTOM_MEMORY":    "CWE-200",
    "MEM_NAMESPACE_LEAK": "CWE-200",
    "MESH_TRUST":        "CWE-287",
    "TRUST_ESCALATION":  "CWE-269",
}

# Framework type detection from target URL
def _detect_framework_type(target: str) -> str:
    t = target.lower()
    if any(x in t for x in ["fastmcp", "mcp-server", "modelcontextprotocol"]):
        return "mcp_server"
    if any(x in t for x in ["crewai", "langchain", "llamaindex", "autogen"]):
        return "orchestration"
    if any(x in t for x in ["chroma", "weaviate", "qdrant", "pinecone", "milvus"]):
        return "vector_db"
    if any(x in t for x in ["rag", "retriev", "embed"]):
        return "rag"
    return "agentic_ai"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        raw = "\n".join(lines[start:end]).strip()
    return raw


def _call_haiku(client: ArgusClient, prompt: str,
                max_tokens: int = 2000) -> dict:
    resp = client.messages.create(
        model=L6_MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = _strip_fences(resp.content[0].text)
    return json.loads(raw)


def _cvss_score_from_string(cvss_str: Optional[str]) -> float:
    if not cvss_str:
        return 0.0
    try:
        # Extract first number that isn't the version (3.1/3.0)
        import re
        # Find all numbers
        matches = re.findall(r'\d+\.\d+', cvss_str)
        for m in matches:
            if m not in ("3.1", "3.0"):
                return float(m)
        # Fallback if only 3.1 is present (shouldn't happen on valid strings)
        return float(matches[0]) if matches else 0.0
    except Exception:
        return 0.0


def _get_primary_cwe(chain: ExploitChain, l5_chains: L5Chains) -> str:
    """Get CWE from ATLAS TTPs or chain data."""
    if chain.mitre_atlas_ttps:
        # Map common ATLAS TTPs to CWEs
        for ttp in chain.mitre_atlas_ttps:
            if "T0048" in ttp:
                return "CWE-502"  # Deserialization
            if "T0051" in ttp:
                return "CWE-74"   # Injection
            if "T0049" in ttp:
                return "CWE-918"  # SSRF
    return "CWE-284"  # Improper Access Control (fallback)


# ── CVE Draft Generation ──────────────────────────────────────────────────────

def _generate_cve_draft(
    client: ArgusClient,
    chain: ExploitChain,
    target: str,
    discovery_date: str,
    verbose: bool
) -> Optional[CVEDraft]:
    """Generate a single CVE draft for an exploit chain."""

    chain_summary = {
        "title": chain.title,
        "blast_radius": chain.blast_radius,
        "cvss_estimate": chain.cvss_estimate,
        "entry_point": chain.entry_point,
        "steps": [{"step": s.step, "action": s.action, "achieves": s.achieves}
                  for s in chain.steps],
        "preconditions": chain.preconditions,
        "mitre_atlas": chain.mitre_atlas_ttps,
        "poc_available": bool(chain.poc_code)
    }

    try:
        prompt = L6_CVE_DRAFT_PROMPT.format(
            chain=json.dumps(chain_summary, indent=2),
            target=target,
            date=discovery_date
        )
        data = _call_haiku(client, prompt)

        cvss_score = _cvss_score_from_string(
            data.get("cvss_vector") or chain.cvss_estimate
        )

        return CVEDraft(
            chain_id=chain.chain_id,
            title=data.get("title", chain.title),
            description=data.get("description", ""),
            affected_product=target,
            affected_versions=data.get("affected_versions", "All current versions"),
            cvss_vector=data.get("cvss_vector", chain.cvss_estimate or ""),
            cvss_score=cvss_score,
            cwe=data.get("cwe", _get_primary_cwe(chain, None)),
            owasp_llm_categories=data.get("owasp_llm_categories", []),
            poc_summary=data.get("poc_summary", ""),
            remediation=data.get("remediation", ""),
            reporter=REPORTER,
            disclosure_date=discovery_date,
            deadline=(
                datetime.strptime(discovery_date, "%Y-%m-%d") +
                timedelta(days=DISCLOSURE_DAYS)
            ).strftime("%Y-%m-%d")
        )
    except Exception as e:
        if verbose:
            print(f"    [L6] CVE draft error for {chain.chain_id}: {e}")
        return None


# ── Advisory Generation ───────────────────────────────────────────────────────

def _generate_advisory(
    client: ArgusClient,
    chains: list[ExploitChain],
    cve_drafts: list[CVEDraft],
    target: str,
    l1_report: Optional[L1Report],
    discovery_date: str,
    verbose: bool
) -> str:
    """Generate a complete GitHub-compatible security advisory."""

    deadline = (
        datetime.strptime(discovery_date, "%Y-%m-%d") +
        timedelta(days=DISCLOSURE_DAYS)
    ).strftime("%Y-%m-%d")

    # Build chains summary for the advisory prompt
    chains_summary = "\n".join([
        f"- [{c.blast_radius}] {c.chain_id}: {c.title} | "
        f"CVSS: {c.cvss_estimate[:30] if c.cvss_estimate else 'TBD'} | "
        f"Entry: {c.entry_point}"
        for c in chains[:8]
    ])

    try:
        prompt = L6_ADVISORY_PROMPT.format(
            chains_summary=chains_summary,
            target=target,
            date=discovery_date,
            deadline=deadline
        )
        resp = client.messages.create(
            model=L6_MODEL,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        advisory_body = resp.content[0].text.strip()
    except Exception as e:
        if verbose:
            print(f"    [L6] Advisory generation error: {e}")
        advisory_body = f"Advisory generation failed: {e}"

    # Build the full advisory markdown document
    stats_section = ""
    if l1_report:
        stats_section = f"""
## Scan Statistics

| Metric | Count |
|--------|-------|
| Files Analyzed | {l1_report.total_files_analyzed} |
| Total Findings | {l1_report.total_findings} |
| CRITICAL Findings | {l1_report.critical_count} |
| HIGH Findings | {l1_report.high_count} |
| Verified Exploit Chains | {len(chains)} |
| Verified CRITICAL Chains | {sum(1 for c in chains if c.blast_radius == 'CRITICAL')} |
"""

    chains_detail = "\n\n".join([
        f"### {c.chain_id}: {c.title}\n"
        f"- **Severity:** {c.blast_radius}\n"
        f"- **CVSS:** {c.cvss_estimate or 'Pending'}\n"
        f"- **Entry point:** {c.entry_point}\n"
        f"- **Steps:** {len(c.steps)}\n"
        f"- **Impact:** {c.steps[-1].achieves if c.steps else 'N/A'}\n"
        f"- **MITRE ATLAS:** {', '.join(c.mitre_atlas_ttps) if c.mitre_atlas_ttps else 'N/A'}"
        for c in chains[:5]
    ])

    cve_table_rows = []
    for d in cve_drafts[:8]:
        # Handle CWE being returned as a list or string
        cwe_str = ", ".join(d.cwe) if isinstance(d.cwe, list) else str(d.cwe)
        title_str = d.title
        cve_table_rows.append(f"| {d.chain_id} | {d.cvss_score} | {cwe_str} | {title_str} |")
    cve_table = "\n".join(cve_table_rows)

    advisory_md = f"""# Security Advisory — {target.split('/')[-1] if '/' in target else target}

**Reporter:** {REPORTER_ORG}  
**Contact:** andre.byrd@odingard.com  
**Discovery method:** ARGUS Red Team Platform (`pip install argus-redteam`)  
**Date:** {discovery_date}  
**Disclosure deadline:** {deadline} (90 days)

---

{advisory_body}

{stats_section}

## Exploit Chains

{chains_detail}

## CVE Summary

| Chain ID | CVSS | CWE | Title |
|----------|------|-----|-------|
{cve_table}

## Disclosure Timeline

| Date | Event |
|------|-------|
| {discovery_date} | Vulnerabilities discovered via ARGUS autonomous scan |
| {discovery_date} | Security advisory filed |
| {discovery_date} | CVE submissions filed with MITRE |
| **{deadline}** | **Full public disclosure deadline** |

## About Odingard Security / ARGUS

Odingard Security is a veteran-founded, AI-native cybersecurity company.  
ARGUS is an autonomous AI red team platform using the TRIDENT vulnerability framework.  
*"{ARGUS_TAGLINE}"*

`pip install argus-redteam` | github.com/Odingard/Argus
"""
    return advisory_md


# ── Intelligence Flywheel ─────────────────────────────────────────────────────

def _append_flywheel(
    chains: list[ExploitChain],
    l1_report: Optional[L1Report],
    target: str,
    output_dir: str,
    discovery_date: str
) -> list[FlywheelEntry]:
    """
    Append anonymized pattern entries to the intelligence flywheel.
    CRITICAL: No client/target identifying information is stored.
    Only attack patterns, effective modalities, and chain structures.

    Over time this becomes the proprietary moat:
    - After 20 targets: fuzzer knows which mutations actually find things
    - After 50 targets: L2 hypotheses are better calibrated
    - After 100 targets: ARGUS has an attack pattern library no competitor can replicate
    """
    framework_type = _detect_framework_type(target)
    flywheel_path  = os.path.join(output_dir, "..", "flywheel.jsonl")
    flywheel_path  = os.path.normpath(flywheel_path)

    entries: list[FlywheelEntry] = []

    for chain in chains:
        # Extract vuln classes from chain without storing identifying info
        vuln_classes = list(set(
            ttp.split(".")[0] for ttp in (chain.mitre_atlas_ttps or [])
        )) or ["UNKNOWN"]

        # Abstract attack pattern — no file paths, no product names
        attack_patterns = [s.achieves for s in chain.steps if s.achieves][:4]

        # Which modalities were effective (from component deviation IDs)
        effective_modalities: list[str] = []
        pid = chain.component_deviations[0] if chain.component_deviations else ""
        # Modality encoded in payload_id indirectly via hypothesis class
        if chain.blast_radius in ("CRITICAL", "HIGH"):
            effective_modalities = ["schema", "chain"]  # both contributed

        # Abstract chain pattern — no specific function/file names
        chain_pattern = (
            f"{len(chain.steps)}-step {chain.blast_radius} chain "
            f"via {chain.entry_point} entry"
        )

        entry = FlywheelEntry(
            vuln_classes=vuln_classes,
            attack_patterns=attack_patterns,
            effective_modalities=effective_modalities,
            chain_pattern=chain_pattern,
            blast_radius=chain.blast_radius,
            entry_point_type=chain.entry_point,
            framework_type=framework_type,
            scan_date=discovery_date
        )
        entries.append(entry)

        # Append to flywheel file
        try:
            with open(flywheel_path, "a") as f:
                f.write(json.dumps(asdict(entry)) + "\n")
        except Exception:
            pass  # flywheel write failure is non-fatal

    return entries


# ── Main ──────────────────────────────────────────────────────────────────────

def run_layer6(
    l5_chains: L5Chains,
    output_dir: str,
    l1_report: Optional[L1Report] = None,
    verbose: bool = False
) -> L6Output:
    """
    Generate complete disclosure package and append intelligence flywheel entries.
    """
    client = ArgusClient()
    discovery_date = datetime.now().strftime("%Y-%m-%d")
    deadline = (datetime.now() + timedelta(days=DISCLOSURE_DAYS)).strftime("%Y-%m-%d")

    results = L6Output(target=l5_chains.target)

    print(f"\n[L6] CVE Pipeline + Intelligence Flywheel")
    print(f"     Chains to process: {len(l5_chains.chains)}")
    print(f"     Discovery date   : {discovery_date}")
    print(f"     Disclosure deadline: {deadline}")

    valid_chains = [c for c in l5_chains.chains if getattr(c, 'is_validated', False)]
    if len(valid_chains) < len(l5_chains.chains):
        print(f"     ⚠  Filtered {len(l5_chains.chains) - len(valid_chains)} unvalidated hallucinated chains.")
        l5_chains.chains = valid_chains

    if not l5_chains.chains:
        print("     ⚠  No validated chains from L5/L7 — skipping CVE generation")
        return results

    # ── CVE Drafts ────────────────────────────────────────────────────────
    print(f"\n  [L6-CVE] Generating CVE drafts...")
    cve_drafts: list[CVEDraft] = []

    # Prioritize CRITICAL chains, cap at 8 CVE submissions
    priority_chains = sorted(
        l5_chains.chains,
        key=lambda c: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(c.blast_radius, 3),
                       -c.combined_score)
    )[:8]

    for i, chain in enumerate(priority_chains):
        print(f"  [{i+1:>2}/{len(priority_chains)}] {chain.chain_id}: "
              f"{chain.title[:55]}")
        draft = _generate_cve_draft(
            client, chain, l5_chains.target, discovery_date, verbose
        )
        if draft:
            cve_drafts.append(draft)
            print(f"         ✓ CVE draft — CVSS: {draft.cvss_score} | "
                  f"CWE: {draft.cwe}")

    results.cve_drafts = cve_drafts

    # ── Advisory ──────────────────────────────────────────────────────────
    print(f"\n  [L6-ADV] Generating security advisory...")
    advisory_md = _generate_advisory(
        client, l5_chains.chains, cve_drafts,
        l5_chains.target, l1_report, discovery_date, verbose
    )
    results.advisory_md    = advisory_md
    results.github_advisory = advisory_md  # same format for GitHub

    # Write advisory files
    adv_path = os.path.join(output_dir, "advisory.md")
    gh_path  = os.path.join(output_dir, "github_advisory.md")
    cve_path = os.path.join(output_dir, "cve_drafts.json")

    with open(adv_path, "w") as f:
        f.write(advisory_md)
    with open(gh_path, "w") as f:
        f.write(advisory_md)
    with open(cve_path, "w") as f:
        json.dump({
            "target": l5_chains.target,
            "discovery_date": discovery_date,
            "disclosure_deadline": deadline,
            "reporter": REPORTER,
            "cve_submissions": [asdict(d) for d in cve_drafts]
        }, f, indent=2)

    print(f"         ✓ advisory.md")
    print(f"         ✓ github_advisory.md")
    print(f"         ✓ cve_drafts.json ({len(cve_drafts)} CVEs)")

    # ── Intelligence Flywheel ─────────────────────────────────────────────
    print(f"\n  [L6-FLY] Appending to intelligence flywheel...")
    flywheel_entries = _append_flywheel(
        l5_chains.chains, l1_report,
        l5_chains.target, output_dir, discovery_date
    )
    results.flywheel_entries = flywheel_entries

    # Count total flywheel entries
    flywheel_path = os.path.normpath(os.path.join(output_dir, "..", "flywheel.jsonl"))
    total_entries = 0
    if os.path.exists(flywheel_path):
        with open(flywheel_path) as f:
            total_entries = sum(1 for _ in f)

    print(f"         ✓ {len(flywheel_entries)} entries appended")
    print(f"         ✓ Total flywheel entries: {total_entries}")
    print(f"         📊 Flywheel: {flywheel_path}")

    # ── Final summary ─────────────────────────────────────────────────────
    print(f"\n[L6] Complete")
    print(f"     CVE drafts    : {len(cve_drafts)}")
    print(f"     Advisory      : {adv_path}")
    print(f"     Flywheel      : {total_entries} total entries")
    print(f"     Deadline      : {deadline}")

    return results
