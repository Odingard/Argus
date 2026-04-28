"""Top-level pytest config for the ARGUS test suite.

Registers custom markers and the skip-conditions that go with them.
The goal is a green floor in offline mode (ARGUS_OFFLINE=1, no provider
keys) so CI runs and pre-commit gates don't have to wade through known
reds — and a comprehensive suite when an operator opts in to live LLM
calls via ARGUS_JUDGE=1 plus at least one provider key.

Markers registered:

    @pytest.mark.requires_judge
        Test exercises a code path that hits the LLM judge. Skips
        unless ARGUS_JUDGE=1 is set AND at least one provider key
        (ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY) is in
        env. Documented in KNOWN_REDS.md under "Per-agent tests
        requiring ARGUS_JUDGE".

    @pytest.mark.requires_runtime_deps
        Test spawns out-of-process runtime dependencies (npx
        subprocesses for MCP servers, framework labrats running
        their own LLM clients, etc.). Skips unless
        ARGUS_RUNTIME_TESTS=1 is set. Documented in KNOWN_REDS.md
        under "Acceptance / e2e tests requiring runtime deps".

Both markers are intentionally opt-in: the default gate stays fast
and offline; operators flip the env var when they want to exercise
the full suite.
"""
from __future__ import annotations

import os

import pytest


def _judge_available() -> bool:
    """True iff the judge gate (ARGUS_JUDGE=1) is set AND at least one
    provider key is in env. Mirrors LLMJudge.available()."""
    if os.environ.get("ARGUS_JUDGE", "0") != "1":
        return False
    return any(
        os.environ.get(name)
        for name in (
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
        )
    )


def _runtime_tests_enabled() -> bool:
    """True iff ARGUS_RUNTIME_TESTS=1 is set. Gates tests that spawn
    out-of-process npx / framework subprocesses."""
    return os.environ.get("ARGUS_RUNTIME_TESTS", "0") == "1"


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers so pytest doesn't warn about them."""
    config.addinivalue_line(
        "markers",
        "requires_judge: test requires ARGUS_JUDGE=1 + at least one "
        "provider API key. Skipped in offline mode by default.",
    )
    config.addinivalue_line(
        "markers",
        "requires_runtime_deps: test spawns out-of-process runtime "
        "dependencies (npx, framework labrats). Skipped unless "
        "ARGUS_RUNTIME_TESTS=1 is set.",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Apply skip markers to tests whose preconditions aren't met."""
    judge_skip = pytest.mark.skip(
        reason="requires ARGUS_JUDGE=1 and a provider API key "
               "(set ARGUS_JUDGE=1 ANTHROPIC_API_KEY=... to run)",
    )
    runtime_skip = pytest.mark.skip(
        reason="requires ARGUS_RUNTIME_TESTS=1 (test spawns "
               "out-of-process runtime dependencies)",
    )
    judge_ok = _judge_available()
    runtime_ok = _runtime_tests_enabled()
    for item in items:
        if "requires_judge" in item.keywords and not judge_ok:
            item.add_marker(judge_skip)
        if "requires_runtime_deps" in item.keywords and not runtime_ok:
            item.add_marker(runtime_skip)
