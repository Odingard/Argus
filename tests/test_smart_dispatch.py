"""
tests/test_smart_dispatch.py — the one-input dispatcher.

Tests dispatch decisions WITHOUT hitting the network (no git clone,
no npm install). Detection helpers operate on a tmp_path repo
skeleton so GitHub dispatch is exercised end-to-end minus the
actual clone step (we construct the cloned state ourselves).
"""
from __future__ import annotations

import json

import pytest

from argus.engagement.smart import (
    Dispatch, _detect_launch_command, _looks_like_github,
    _looks_like_npm_package, describe, dispatch,
)


# ── Scheme pass-through ───────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "crewai://labrat",
    "autogen://labrat",
    "mcp://localhost:3000/api/sse",
    "stdio-mcp://labrat",
    "generic-agent://labrat",
])
def test_known_scheme_passes_through_as_engage(url):
    d = dispatch(url)
    assert d.ok()
    assert d.action == "engage"
    assert d.target == url


def test_unknown_scheme_fails_loud():
    d = dispatch("ftp://example.com/x")
    assert not d.ok()
    assert "unrecognised URL scheme" in d.reason


# ── HTTP smart routing ────────────────────────────────────────────────────

def test_http_sse_path_reroutes_through_mcp_scheme():
    d = dispatch("http://localhost:3000/api/sse")
    assert d.action == "engage"
    assert d.target.startswith("mcp://")


def test_http_mcp_path_bridges_through_mcp_remote():
    d = dispatch("http://localhost:3000/api/mcp")
    assert d.action == "engage"
    assert d.target.startswith("stdio-mcp://")
    assert "mcp-remote" in d.target


def test_http_generic_passes_through_as_http():
    d = dispatch("http://localhost:5000/agent")
    assert d.action == "engage"
    # Generic HTTP agent scheme handled by the registry's http target.
    assert d.target.startswith("http://")


# ── npm package detection ────────────────────────────────────────────────

@pytest.mark.parametrize("pkg,expected", [
    ("@modelcontextprotocol/server-filesystem", True),
    ("@scope/pkg",                               True),
    ("some-package",                             True),
    ("mcp-handler",                              True),
    ("/usr/bin/foo",                             False),
    ("@scope/sub/extra",                         False),      # not scoped-only
    ("pkg with space",                           False),
])
def test_looks_like_npm_package(pkg, expected):
    assert _looks_like_npm_package(pkg) is expected


def test_dispatch_npm_scoped_package():
    d = dispatch("@modelcontextprotocol/server-filesystem")
    assert d.action == "engage"
    assert d.target.startswith("stdio-mcp://npx+-y+@modelcontextprotocol")
    assert d.command == ["npx", "-y", "@modelcontextprotocol/server-filesystem"]


# ── Bare-name default is npm (npx); pip users pass `uvx <pkg>`. ──────────

def test_bare_name_defaults_to_npx():
    """Ambiguous bare names are treated as npm — npx is the dominant
    MCP launcher. PyPI targets take the explicit `uvx <pkg>` form
    via `argus mcp uvx <pkg>`."""
    d = dispatch("some-mcp-server")
    assert d.action == "engage"
    assert d.target.startswith("stdio-mcp://npx+-y+some-mcp-server")
    assert d.command == ["npx", "-y", "some-mcp-server"]


# ── GitHub URL detection ─────────────────────────────────────────────────

@pytest.mark.parametrize("url,owner,name", [
    ("github.com/vercel/mcp-handler",         "vercel", "mcp-handler"),
    ("https://github.com/vercel/mcp-handler", "vercel", "mcp-handler"),
    ("https://github.com/vercel/mcp-handler.git", "vercel", "mcp-handler"),
    ("https://www.github.com/anthropic/claude", "anthropic", "claude"),
    # npm-shorthand — previously fell through to npx and silently
    # failed for Python packages. Now routed through the clone +
    # pyproject-aware detection path like the full URL forms.
    ("github:dhruvpatel1706/mcp-zettel", "dhruvpatel1706", "mcp-zettel"),
    ("github:vercel/mcp-handler",        "vercel",         "mcp-handler"),
])
def test_looks_like_github_parses(url, owner, name):
    got = _looks_like_github(url)
    assert got is not None
    assert got["owner"] == owner
    assert got["name"] == name


def test_looks_like_github_rejects_non_github_urls():
    assert _looks_like_github("https://gitlab.com/foo/bar") is None
    assert _looks_like_github("not a url at all") is None


# ── GitHub detection against a mock-cloned repo ──────────────────────────

def test_detect_launch_from_mcp_json_manifest(tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({
        "command": "python",
        "args":    ["server.py", "--port", "8080"],
    }))
    assert _detect_launch_command(tmp_path) == [
        "python", "server.py", "--port", "8080",
    ]


def test_detect_launch_from_package_json_with_mcp_name(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "my-mcp-server",
        "bin":  {"my-mcp-server": "./bin/run"},
    }))
    assert _detect_launch_command(tmp_path) == [
        "npx", "-y", "my-mcp-server",
    ]


def test_detect_launch_skips_package_without_bin(tmp_path):
    """vercel/mcp-handler pattern — 'mcp' in name, no `bin` entry.
    It's a LIBRARY, not a runnable server; detector must return None
    so the dispatcher falls through to README / entrypoint / fail."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "mcp-handler",
        "main": "./dist/index.js",
        "peerDependencies": {"next": "^15"},
    }))
    assert _detect_launch_command(tmp_path) is None


def test_framework_hint_detects_nextjs_adapter(tmp_path):
    from argus.engagement.smart import _framework_hint
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "mcp-handler",
        "peerDependencies": {"next": "^15", "nuxt": "^3"},
    }))
    hint = _framework_hint(tmp_path)
    assert "FRAMEWORK ADAPTER" in hint
    assert "next" in hint


def test_framework_hint_detects_library_shape(tmp_path):
    from argus.engagement.smart import _framework_hint
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "some-mcp-sdk",
        "main": "./lib/index.js",
    }))
    hint = _framework_hint(tmp_path)
    assert "LIBRARY" in hint


def test_framework_hint_silent_on_runnable_package(tmp_path):
    from argus.engagement.smart import _framework_hint
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "my-server",
        "bin":  {"my-server": "./bin/run"},
    }))
    assert _framework_hint(tmp_path) == ""


def test_detect_launch_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "my-mcp-server"\n'
    )
    assert _detect_launch_command(tmp_path) == ["uvx", "my-mcp-server"]


def test_detect_launch_prefers_server_entry_over_package_name(tmp_path):
    """mcp-zettel pattern: package name is 'mcp-zettel' but the
    runnable entry is 'mcp-zettel-server'. We want the server entry,
    not the bare package name (which would launch the interactive CLI
    and hang in stdio mode)."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "mcp-zettel"\n'
        '\n'
        '[project.scripts]\n'
        'mcp-zettel        = "mcp_zettel.cli:app"\n'
        'mcp-zettel-server = "mcp_zettel.server:main"\n'
    )
    assert _detect_launch_command(tmp_path) == [
        "uvx", "mcp-zettel-server",
    ]


def test_detect_launch_ignores_pyproject_without_mcp_signals(tmp_path):
    """A generic Python library with no MCP-shaped entry points must
    NOT be dispatched via uvx — it would install fine but has no
    runnable server and will hang/error at handshake."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "some-random-lib"\n'
        '\n'
        '[project.scripts]\n'
        'some-cli = "some_random_lib.cli:main"\n'
    )
    assert _detect_launch_command(tmp_path) is None


def test_detect_launch_picks_mcp_named_script_when_no_server_suffix(tmp_path):
    """Entry named 'mcp-foo' (contains 'mcp' but no -server suffix) is
    an acceptable fallback over a generic CLI."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "foo"\n'
        '\n'
        '[project.scripts]\n'
        'foo-cli = "foo.cli:main"\n'
        'mcp-foo = "foo.server:main"\n'
    )
    assert _detect_launch_command(tmp_path) == ["uvx", "mcp-foo"]


def test_detect_launch_from_readme_code_block(tmp_path):
    (tmp_path / "README.md").write_text(
        "# My Server\n\nInstall:\n\n```bash\n"
        "npx -y @foo/mcp-server --flag\n"
        "```\n"
    )
    got = _detect_launch_command(tmp_path)
    assert got is not None
    assert "npx" in got
    assert "@foo/mcp-server" in got


def test_detect_launch_falls_back_to_entrypoint_file(tmp_path):
    (tmp_path / "server.py").write_text("print('hi')")
    got = _detect_launch_command(tmp_path)
    assert got is not None
    assert got[0] == "python"
    assert got[1].endswith("server.py")


def test_detect_launch_returns_none_on_empty_repo(tmp_path):
    assert _detect_launch_command(tmp_path) is None


# ── Local path dispatch ──────────────────────────────────────────────────

def test_dispatch_local_python_file(tmp_path):
    script = tmp_path / "my_server.py"
    script.write_text("print(1)")
    d = dispatch(str(script))
    assert d.action == "engage"
    assert d.target.startswith("stdio-mcp://python")
    assert d.command == ["python", str(script)]


def test_dispatch_local_node_file(tmp_path):
    script = tmp_path / "index.js"
    script.write_text("console.log(1)")
    d = dispatch(str(script))
    assert d.action == "engage"
    assert d.command == ["node", str(script)]


def test_dispatch_unknown_file_extension(tmp_path):
    weird = tmp_path / "thing.wat"
    weird.write_text("")
    d = dispatch(str(weird))
    assert d.action == "fail"
    assert "don't know how to launch" in d.reason


# ── Engagement-dir detection ──────────────────────────────────────────────

def test_dispatch_engagement_dir_renders_report(tmp_path):
    (tmp_path / "chain.json").write_text(json.dumps({"chain_id": "x"}))
    d = dispatch(str(tmp_path))
    assert d.action == "report"
    assert d.target == str(tmp_path.resolve())


def test_dispatch_empty_dir_is_fail(tmp_path):
    d = dispatch(str(tmp_path))
    assert d.action == "fail"


# ── Fail-loud on empty / nonsense ────────────────────────────────────────

def test_dispatch_empty_input_fails():
    d = dispatch("")
    assert not d.ok()


def test_dispatch_whitespace_fails():
    d = dispatch("     ")
    assert not d.ok()


def test_dispatch_bare_name_dispatches_to_npm_even_when_unknown():
    """New policy: bare hyphenated strings get npx-wrapped. If the
    package doesn't exist on npm, runtime `npx -y` fails immediately
    and clearly — that's a better UX than a dispatch-time refusal."""
    d = dispatch("totally-random-string-that-is-not-a-package")
    assert d.action == "engage"
    assert d.target.startswith("stdio-mcp://npx+-y+")


def test_dispatch_nonsense_with_slashes_fails():
    """Strings with path separators that don't exist on disk have
    no npm dispatch path — fail loud."""
    d = dispatch("not/a/real/path/anywhere")
    assert not d.ok()
    assert "could not identify" in d.reason


# ── describe() string ────────────────────────────────────────────────────

def test_describe_engage_line():
    d = Dispatch(action="engage", target="mcp://x", reason="scheme")
    assert "engage mcp://x" in describe(d)


def test_describe_failure():
    d = Dispatch(action="fail", reason="because")
    assert describe(d).startswith("✗")
    assert "because" in describe(d)
