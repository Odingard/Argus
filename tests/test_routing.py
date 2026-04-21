"""tests/test_routing.py — offline tests for the model router."""
from __future__ import annotations


import pytest

from argus.routing import JOBS, ModelRouter, default_router


def test_all_jobs_have_non_empty_chain():
    for job in JOBS:
        chain = default_router().chain_for(job)
        assert chain, f"job {job!r} has no chain"
        for provider, model in chain:
            assert provider in {"anthropic", "openai", "google"}, \
                f"unknown provider in {job}: {provider}"
            assert model, f"empty model id in {job}"


def test_router_resolves_to_first_keyed_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-anth")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    r = ModelRouter()
    provider, _ = r.resolve("L5_SYNTH")
    assert provider == "anthropic"


def test_router_falls_over_when_primary_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "key-gemini")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    r = ModelRouter()
    provider, _ = r.resolve("L5_SYNTH")
    assert provider == "google"


def test_router_cooldown_skips_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    r = ModelRouter()
    # Cool the Anthropic provider.
    r.cooldown("anthropic", secs=120)
    provider, _ = r.resolve("L5_SYNTH")
    assert provider == "google"


def test_router_raises_when_no_keys_anywhere(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    r = ModelRouter()
    with pytest.raises(LookupError):
        r.resolve("L5_SYNTH")


def test_unknown_job_raises():
    with pytest.raises(LookupError):
        default_router().resolve("NOT_A_REAL_JOB_12345")


def test_ship_defaults_cover_all_critical_paths():
    """Guard against someone removing a critical job from the default chain."""
    required = {
        "L1_ANALYZE", "L1_POC", "L4_DEVIATION", "L5_SYNTH",
        "AGENT_HAIKU", "CORRELATOR_JUDGE", "CORRELATOR_OPUS",
        "REASONING_AUDIT", "MCP_SYNTH",
    }
    available = set(JOBS)
    missing = required - available
    assert not missing, f"missing required jobs in default router: {missing}"
