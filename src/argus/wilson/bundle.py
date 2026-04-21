"""
argus/wilson/bundle.py — forensic artifact packaging per validated chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from argus.shared.ars import score_chain, band
from argus.shared.models import ExploitChain
from argus.wilson.keys import (
    load_key as _load_key,
    key_fingerprint as _key_fingerprint,
    is_default_key as _is_default_key,
)


# HMAC key fallback for tests that don't set an env var. Real customer-
# facing builds resolve through argus.wilson.keys.load_key() which
# prefers ARGUS_WILSON_KEY / ARGUS_WILSON_KEYFILE / ~/.argus/wilson.key
# over this default. Warns loudly if the default is actually used to
# sign a bundle.
_DEFAULT_KEY = b"argus-wilson-default-key-rotate-per-engagement"


@dataclass
class WilsonBundle:
    """A packaged, signed evidence bundle ready for disclosure."""
    bundle_dir:   Path
    chain_id:     str
    manifest:     dict        # sha256 of each file + hmac
    files:        list[str]   # filenames inside the bundle


# ── Public API ────────────────────────────────────────────────────────────────

def build_bundle_for_chain(
    chain:        ExploitChain,
    run_dir:      str,
    output_root:  Optional[str] = None,
    hmac_key:     Optional[bytes] = None,
) -> WilsonBundle:
    """
    Build a Wilson-Proof bundle for ``chain`` under
    ``<output_root or run_dir>/wilson/<chain_id>/``.

    Collects:
      - chain.json        (from the ExploitChain dataclass)
      - poc.py            (chain.poc_code, or a placeholder explaining absence)
      - sandbox_stdout.txt (chain.validation_output, trimmed to 64 KiB)
      - fingerprint.json  (L0 fingerprinter output if layer0.json exists)
      - pheromone.jsonl   (slice of swarm_blackboard.jsonl mentioning any of
                           chain.component_deviations; empty if no swarm run)
      - rationale.md      (per-chain explanation derived from chain metadata)
      - README.md         (triage-readable top-level summary)

    Then writes ``manifest.json`` with SHA-256 of every bundle file and an
    HMAC-SHA256 over those hashes keyed by ``hmac_key`` (env
    ``ARGUS_WILSON_KEY`` or the default).
    """
    out_root = Path(output_root or run_dir) / "wilson" / (chain.chain_id or "chain")
    out_root.mkdir(parents=True, exist_ok=True)

    # Clean an existing bundle so repeated builds are deterministic.
    for existing in out_root.iterdir():
        if existing.is_file():
            existing.unlink()

    # chain.json
    from dataclasses import asdict as _asdict
    (out_root / "chain.json").write_text(
        json.dumps(_asdict(chain), indent=2, default=str),
        encoding="utf-8",
    )

    # poc.py
    poc_path = out_root / "poc.py"
    if chain.poc_code:
        poc_path.write_text(chain.poc_code, encoding="utf-8")
    else:
        poc_path.write_text(
            "# No PoC available for this chain. Validation did not run "
            "or the chain was accepted on static evidence alone.\n",
            encoding="utf-8",
        )

    # sandbox_stdout.txt
    sandbox_txt = getattr(chain, "validation_output", "") or ""
    (out_root / "sandbox_stdout.txt").write_text(
        sandbox_txt[:65_536], encoding="utf-8",
    )

    # fingerprint.json — copy layer0.json if present
    l0_path = Path(run_dir) / "layer0.json"
    if l0_path.exists():
        shutil.copyfile(l0_path, out_root / "fingerprint.json")
    else:
        (out_root / "fingerprint.json").write_text(
            json.dumps({"note": "layer0.json absent at package time"},
                       indent=2),
            encoding="utf-8",
        )

    # pheromone.jsonl — relevant slice of the swarm blackboard log
    phero_in = Path(run_dir) / "swarm_blackboard.jsonl"
    phero_out = out_root / "pheromone.jsonl"
    component_ids = set(chain.component_deviations or [])
    if phero_in.exists() and component_ids:
        with open(phero_in, "r", encoding="utf-8") as fh_in, \
                open(phero_out, "w", encoding="utf-8") as fh_out:
            for line in fh_in:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                data = rec.get("data", {})
                # Keep events that mention any component deviation id
                serialized = json.dumps(data, default=str)
                if any(cid and cid in serialized for cid in component_ids):
                    fh_out.write(line)
    else:
        phero_out.write_text("", encoding="utf-8")

    # rationale.md
    rationale = _build_rationale_md(chain)
    (out_root / "rationale.md").write_text(rationale, encoding="utf-8")

    # README.md — triager-readable summary
    readme = _build_readme_md(chain, out_root)
    (out_root / "README.md").write_text(readme, encoding="utf-8")

    # manifest.json
    key = hmac_key or _load_key()
    if _is_default_key(key):
        print("  [wilson] WARNING: signing with the built-in default key. "
              "Rotate via `python -c \"from argus.wilson.keys import "
              "rotate_key; print(rotate_key())\"` before customer delivery.")
    files = sorted(p.name for p in out_root.iterdir()
                   if p.is_file() and p.name != "manifest.json")
    manifest = {
        "chain_id":        chain.chain_id,
        "generated_at":    datetime.utcnow().isoformat(),
        "files":           {},
        "hmac_algorithm":  "HMAC-SHA256",
        "key_fingerprint": _key_fingerprint(key),
    }
    for name in files:
        manifest["files"][name] = _sha256_file(out_root / name)
    # HMAC over the canonical json of the files map
    canonical = json.dumps(manifest["files"], sort_keys=True).encode()
    manifest["hmac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8",
    )

    return WilsonBundle(
        bundle_dir=out_root,
        chain_id=chain.chain_id or "",
        manifest=manifest,
        files=files + ["manifest.json"],
    )


def verify_bundle(
    bundle_dir: Path,
    hmac_key:   Optional[bytes] = None,
) -> tuple[bool, str]:
    """
    Re-hash every file in the bundle and re-compute the HMAC. Returns
    (ok, message). Triagers / downstream tooling can call this to prove
    the bundle hasn't been tampered with since generation.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        return False, "manifest.json missing"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest.get("files", {}).items():
        actual = _sha256_file(bundle_dir / name)
        if actual != expected:
            return False, f"sha256 mismatch on {name}"
    key = hmac_key or _load_key()
    canonical = json.dumps(manifest.get("files", {}), sort_keys=True).encode()
    expected_hmac = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, manifest.get("hmac", "")):
        return False, "HMAC mismatch — bundle or key altered"
    return True, "ok"


# ── Internals ─────────────────────────────────────────────────────────────────

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_rationale_md(chain: ExploitChain) -> str:
    steps_md = "\n".join(
        f"{s.step}. **{s.action}** — payload: `{(s.payload or '')[:120]}` "
        f"→ achieves: {s.achieves}"
        for s in (chain.steps or [])
    )
    mitre = ", ".join(chain.mitre_atlas_ttps or []) or "—"
    owasp = ", ".join(chain.owasp_llm_categories or []) or "—"
    pre   = "\n".join(f"  - {p}" for p in (chain.preconditions or [])) or "  - none"

    ars = score_chain(
        blast_radius=chain.blast_radius,
        is_validated=bool(getattr(chain, "is_validated", False)),
        combined_score=chain.combined_score,
        entry_point=chain.entry_point,
        preconditions_count=len(chain.preconditions or []),
    )
    ars_md = "\n".join(f"  - {line}" for line in ars.rationale)

    return f"""# Rationale — {chain.chain_id}

**Title**: {chain.title}
**Blast radius**: {chain.blast_radius}
**Entry point**: {chain.entry_point}
**Combined score**: {chain.combined_score:.2f}
**CVSS**: {chain.cvss_estimate or '—'}
**ARS (Argus Risk Score)**: {ars.score} / 100 — **{band(ars.score)}**

### ARS breakdown
{ars_md}

## Steps

{steps_md or '*(no steps recorded)*'}

## Preconditions
{pre}

## Frameworks
- **MITRE ATLAS**: {mitre}
- **OWASP LLM**: {owasp}

## Component deviations

The following deviation IDs composed this chain (see `pheromone.jsonl`
for each one's full event history on the blackboard):

{chr(10).join(f'- `{c}`' for c in chain.component_deviations or []) or '- none'}
"""


def _build_readme_md(chain: ExploitChain, out_root: Path) -> str:
    validated = "✓ validated in sandbox" if chain.is_validated else "○ not validated"
    ars = score_chain(
        blast_radius=chain.blast_radius,
        is_validated=bool(getattr(chain, "is_validated", False)),
        combined_score=chain.combined_score,
        entry_point=chain.entry_point,
        preconditions_count=len(chain.preconditions or []),
    )
    return f"""# ARGUS Wilson Bundle — {chain.chain_id}

**{chain.title}**

- Blast radius: **{chain.blast_radius}**
- Entry point: {chain.entry_point}
- Validation: {validated}
- CVSS estimate: {chain.cvss_estimate or '—'}
- **ARS: {ars.score} / 100 ({band(ars.score)})**

## Reproduce

```bash
# 1. Inspect the bundle contents
ls {out_root.name}/

# 2. Verify the bundle has not been tampered with
python -c "from argus.wilson.bundle import verify_bundle; \\
  from pathlib import Path; \\
  ok, msg = verify_bundle(Path('{out_root.name}')); \\
  print(ok, msg)"

# 3. Re-run the PoC against an installed target
python {out_root.name}/poc.py
# Exit 0 + 'ARGUS_POC_LANDED:<id>' in stdout => exploit reproduces.
# Exit non-zero or missing marker => not reproducible in your env.
```

## Files

| File | Purpose |
|------|---------|
| `chain.json` | Full exploit chain as synthesized |
| `poc.py` | Minimal proof-of-concept (real-library imports) |
| `sandbox_stdout.txt` | Verbatim Docker stdout from the ARGUS L7 run |
| `fingerprint.json` | Target version / git tag at scan time |
| `pheromone.jsonl` | Swarm blackboard events referencing this chain |
| `rationale.md` | Step-by-step reasoning, MITRE / OWASP mapping |
| `manifest.json` | SHA-256 of each file + HMAC for tamper evidence |
| `README.md` | This file |

Generated by ARGUS — an autonomous AI red-team platform for agentic
AI / MCP systems. For questions on this bundle, contact the reporter
listed in the disclosing security advisory.
"""
