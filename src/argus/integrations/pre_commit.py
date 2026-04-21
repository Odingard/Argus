"""
argus/integrations/pre_commit.py — run a fast ARGUS scan on staged files.

Intended install:

    # .pre-commit-config.yaml
    repos:
      - repo: local
        hooks:
          - id: argus-staged
            name: ARGUS L1 scan on staged files
            entry: argus-pre-commit
            language: system
            stages: [pre-commit]

or run directly:

    python -m argus.integrations.pre_commit

Exits non-zero if any staged file produces a CRITICAL L1 finding. L5 /
L7 are deliberately skipped — pre-commit must be sub-second to 30s, not
multi-minute. For deep validation use the GitHub Action in CI.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _staged_files() -> list[str]:
    """Return repo-relative paths of files staged for commit."""
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _relevant(fs: list[str]) -> list[str]:
    keep = (".py", ".js", ".ts", ".go", ".rs", ".java", ".rb")
    return [f for f in fs if f.endswith(keep) and os.path.exists(f)]


def run_pre_commit() -> int:
    """Entry point. Returns exit code (0 pass, non-zero fail)."""
    files = _relevant(_staged_files())
    if not files:
        print("[argus-pre-commit] no relevant staged files — skipping")
        return 0

    print(f"[argus-pre-commit] scanning {len(files)} staged file(s)")

    # Copy staged files into a tempdir mirroring their paths so we can
    # point `argus` at a clean tree. Using the working copy directly
    # would pick up uncommitted edits outside the staging index.
    with tempfile.TemporaryDirectory(prefix="argus-precommit-") as tmp:
        for f in files:
            dst = Path(tmp) / f
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                content = subprocess.check_output(["git", "show", f":{f}"])
                dst.write_bytes(content)
            except subprocess.CalledProcessError:
                # File staged but not in index (e.g. deletion) — skip.
                continue

        try:
            subprocess.check_call([
                "argus", tmp,
                "-o", os.path.join(tmp, "_out"),
                "--only-layer", "1",
                "--skip-poc",
            ])
        except FileNotFoundError:
            print("[argus-pre-commit] argus CLI not found on PATH; install "
                  "the package first")
            return 0   # don't block commits if argus isn't installed
        except subprocess.CalledProcessError as e:
            print(f"[argus-pre-commit] argus exited {e.returncode}")
            return e.returncode

        # Inspect L1 output for CRITICALs.
        import json
        l1 = Path(tmp) / "_out" / "layer1.json"
        if not l1.exists():
            print("[argus-pre-commit] no layer1.json emitted; pass")
            return 0
        data = json.loads(l1.read_text())
        crit = int(data.get("critical_count", 0) or 0)
        if crit > 0:
            print(f"[argus-pre-commit] FAIL: {crit} CRITICAL finding(s) in "
                  f"staged files. Run `argus <path> --verbose` locally for "
                  f"details, or bypass this hook with --no-verify if you "
                  f"accept the risk.")
            return 2
        print(f"[argus-pre-commit] PASS: no CRITICAL findings "
              f"({int(data.get('total_findings', 0) or 0)} total)")
        return 0


if __name__ == "__main__":
    sys.exit(run_pre_commit())
