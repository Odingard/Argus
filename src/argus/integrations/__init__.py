"""
argus.integrations — Pillar-4 workflow-integration entry points.

  pre_commit     fast-path scan for staged files, suitable for use as
                 a git pre-commit hook; bails out non-zero if an ARS
                 threshold is crossed.
  webhook        FastAPI MVP that accepts a POST /scan payload and
                 kicks off a background scan, exposing status + results
                 over HTTP. Runs via `argus --serve`.
  github_action  (YAML lives at .github/actions/argus/action.yml).
"""
from argus.integrations.pre_commit import run_pre_commit
from argus.integrations.webhook import build_app, run_server

__all__ = ["run_pre_commit", "build_app", "run_server"]
