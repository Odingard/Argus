"""
tests/test_typosquat.py — npm + PyPI typosquat scanner.

No real HTTP calls — tests pass a stub resolver that returns fixture
metadata for specific squat names.
"""
from __future__ import annotations

from argus.adversarial.typosquat import (
    Squat, TyposquatResult, TyposquatScanner,
    _generate_npm_candidates, _generate_pypi_candidates,
    _homoglyph_distance,
    KNOWN_NPM_MCP_PACKAGES, KNOWN_PYPI_MCP_PACKAGES,
    scan,
)


# ── Candidate generators ──────────────────────────────────────────────────

def test_npm_candidates_include_homoglyph_substitutions():
    cands = _generate_npm_candidates("@modelcontextprotocol/server-filesystem")
    # 'l' → '1' somewhere in scope or name.
    assert any("1" in c for c in cands)
    # Scope lookalike with "official" bolt-on.
    assert any("official" in c for c in cands)


def test_npm_candidates_respect_scope():
    cands = _generate_npm_candidates("@modelcontextprotocol/server-memory")
    # A candidate that flips the scope to an impostor.
    assert any(c.startswith("@modelcontextprotoco1/") for c in cands)


def test_npm_candidates_do_not_include_legit():
    legit = "mcp-handler"
    cands = _generate_npm_candidates(legit)
    assert legit not in cands


def test_pypi_candidates_cover_separator_swap():
    cands = _generate_pypi_candidates("mcp-server-fetch")
    assert "mcp_server_fetch" in cands


def test_pypi_candidates_cover_order_swap():
    cands = _generate_pypi_candidates("mcp-server-fetch")
    # Reversed hyphenated parts.
    assert "fetch-server-mcp" in cands


def test_pypi_candidates_do_not_include_legit():
    legit = "crewai"
    assert legit not in _generate_pypi_candidates(legit)


# ── Homoglyph distance ───────────────────────────────────────────────────

def test_homoglyph_distance_treats_known_pairs_as_same():
    # 'l' ↔ '1' normalise to the same char; one raw-edit becomes 0.
    assert _homoglyph_distance("mcp-handler", "mcp-hand1er") == 0
    assert _homoglyph_distance("mcp-handler", "mcp-hand1erx") == 1


def test_homoglyph_distance_counts_genuine_edits():
    assert _homoglyph_distance("mcp-handler", "mcp-handlerx") == 1
    assert _homoglyph_distance("abc", "abd") == 1


# ── Scanner with a stub resolver (no network) ─────────────────────────────

def _fake_resolver(exists: set[str]):
    """Return a resolver that says 'package exists' only for names
    in ``exists``. Metadata is canned."""
    def resolver(name: str):
        if name not in exists:
            return None
        return {
            "name":        name,
            "description": f"ostensibly {name}",
            "author":      "some-squatter",
            "created":     "2026-04-01T00:00:00Z",
        }
    return resolver


def test_scanner_finds_registered_squat(tmp_path):
    squatted = "@modelcontextprotoco1/server-filesystem"     # l → 1 scope
    scanner = TyposquatScanner(
        registry="npm",
        resolver=_fake_resolver({squatted}),
    )
    result = scanner.scan(["@modelcontextprotocol/server-filesystem"])
    assert isinstance(result, TyposquatResult)
    assert result.targets_scanned == 1
    assert result.candidates_checked > 0
    assert len(result.squats_found) == 1
    s = result.squats_found[0]
    assert s.squat == squatted
    assert s.legit == "@modelcontextprotocol/server-filesystem"
    assert "scope_lookalike" in s.signals
    assert s.registry == "npm"


def test_scanner_reports_multiple_squats():
    legit = "mcp-handler"
    squats = {"mcp-hand1er", "mcp-handlerofficial", "mcp_handler"}
    scanner = TyposquatScanner(registry="npm",
                               resolver=_fake_resolver(squats))
    result = scanner.scan([legit])
    found = {s.squat for s in result.squats_found}
    # Not every candidate we generate necessarily appears in this
    # specific fixture — but at least one should.
    assert found & squats


def test_scanner_returns_empty_when_nothing_exists():
    scanner = TyposquatScanner(registry="npm",
                               resolver=_fake_resolver(set()))
    result = scanner.scan(["mcp-handler"])
    assert result.squats_found == []
    assert result.candidates_checked > 0


def test_scanner_pypi_uses_pypi_candidate_set():
    squatted = "mcp_server_fetch"      # separator swap
    scanner = TyposquatScanner(registry="pypi",
                               resolver=_fake_resolver({squatted}))
    result = scanner.scan(["mcp-server-fetch"])
    assert any(s.squat == squatted for s in result.squats_found)


def test_scanner_rejects_partial_name_matches():
    """A resolver that returns a DIFFERENT name than requested
    (i.e. npm's search returned a fuzzy match) must be discarded —
    we only accept exact-name squats."""
    def sneaky_resolver(name: str):
        # Always returns the LEGIT name instead of the squat. Simulates
        # a registry that 302s near-matches.
        return {"name": "mcp-handler",
                "description": "legit",
                "author": "", "created": ""}
    scanner = TyposquatScanner(registry="npm",
                               resolver=sneaky_resolver)
    result = scanner.scan(["mcp-handler"])
    assert result.squats_found == []


def test_classify_signals_detects_official_suffix(tmp_path):
    squats = {"@modelcontextprotocol-official/server-filesystem"}
    scanner = TyposquatScanner(registry="npm",
                               resolver=_fake_resolver(squats))
    result = scanner.scan(["@modelcontextprotocol/server-filesystem"])
    assert result.squats_found
    assert "official_suffix" in result.squats_found[0].signals


def test_scan_convenience_function():
    squats = {"mcp_server_fetch"}
    result = scan(
        targets=["mcp-server-fetch"],
        registry="pypi",
        resolver=_fake_resolver(squats),
    )
    assert result.squats_found


def test_scan_default_targets_use_seed_list_for_registry():
    """When targets is None, scan() uses the registry's default
    seed list. Resolver mocked to zero hits — verifies the list
    was used without hitting the network."""
    result = scan(registry="npm", targets=None,
                  resolver=lambda _name: None)
    assert result.targets_scanned == len(KNOWN_NPM_MCP_PACKAGES)
    result2 = scan(registry="pypi", targets=None,
                   resolver=lambda _name: None)
    assert result2.targets_scanned == len(KNOWN_PYPI_MCP_PACKAGES)


# ── Squat serialisation ───────────────────────────────────────────────────

def test_squat_to_dict_round_trip():
    s = Squat(registry="npm", legit="mcp-handler", squat="mcp-hand1er",
              description="desc", author="a", created="c",
              signals=["homoglyph_1"])
    d = s.to_dict()
    assert d["squat"] == "mcp-hand1er"
    assert "homoglyph_1" in d["signals"]


def test_result_to_dict_is_json_serialisable():
    import json
    result = scan(targets=["mcp-handler"],
                  registry="npm",
                  resolver=lambda _n: None)
    blob = json.dumps(result.to_dict())
    assert "targets_scanned" in blob
