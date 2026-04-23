"""
tests/test_sandbox.py — docker-wrapped stdio adapter.

Tests verify the docker argv is built correctly WITHOUT actually
invoking docker. The SandboxedStdioAdapter only checks for
`docker` in PATH when constructing; we stub that via monkeypatch
so tests pass on any CI where docker may not be installed.
"""
from __future__ import annotations

import pytest

from argus.adapter import SandboxedStdioAdapter, SandboxPolicy
from argus.adapter.base import AdapterError


def _stub_docker(monkeypatch):
    import argus.adapter.sandboxed_stdio as mod
    monkeypatch.setattr(mod.shutil, "which",
                        lambda name: "/usr/local/bin/docker")


# ── Constructor guards ────────────────────────────────────────────────────

def test_refuses_empty_command():
    with pytest.raises(AdapterError):
        SandboxedStdioAdapter(command=[])


def test_refuses_when_docker_not_in_path(monkeypatch):
    import argus.adapter.sandboxed_stdio as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    with pytest.raises(AdapterError) as exc:
        SandboxedStdioAdapter(command=["npx", "-y", "pkg"])
    assert "docker" in str(exc.value).lower()


# ── Docker argv construction ─────────────────────────────────────────────

def test_build_docker_argv_applies_hardening_defaults(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(command=["npx", "-y", "some-pkg"])
    argv = a.command
    assert argv[0] == "docker"
    assert argv[1] == "run"
    assert "-i"            in argv
    assert "--rm"          in argv
    assert "--network"     in argv
    # Default network is none.
    i = argv.index("--network")
    assert argv[i + 1] == "none"
    # Read-only root + drop caps + nobody user.
    assert "--read-only"   in argv
    assert "--cap-drop"    in argv
    assert "--user"        in argv
    # Image defaults to node for npx.
    assert "node:22-alpine" in argv
    # Inner command appears AFTER the image.
    img_i = argv.index("node:22-alpine")
    assert argv[img_i + 1:] == ["npx", "-y", "some-pkg"]


def test_python_launcher_gets_python_image(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(command=["python", "/app/s.py"])
    assert "python:3.12-slim" in a.command


def test_uvx_launcher_gets_python_image(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(command=["uvx", "mcp-server-fetch"])
    assert "python:3.12-slim" in a.command


def test_policy_network_override(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(
        command=["npx", "-y", "pkg"],
        policy=SandboxPolicy(network="bridge"),
    )
    i = a.command.index("--network")
    assert a.command[i + 1] == "bridge"


def test_policy_image_override(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(
        command=["npx", "-y", "pkg"],
        policy=SandboxPolicy(image="custom-node:22"),
    )
    assert "custom-node:22"  in a.command
    assert "node:22-alpine"  not in a.command


def test_policy_disable_read_only(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(
        command=["npx", "-y", "pkg"],
        policy=SandboxPolicy(read_only_root=False),
    )
    assert "--read-only" not in a.command


def test_extra_docker_args_injected_before_image(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(
        command=["npx", "-y", "pkg"],
        policy=SandboxPolicy(
            extra_docker_args=["-v", "/host/ro:/app/ro:ro"],
        ),
    )
    img_i = a.command.index("node:22-alpine")
    assert a.command[img_i - 2:img_i] == ["-v", "/host/ro:/app/ro:ro"]


def test_target_id_reflects_inner_command_not_docker(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(command=["npx", "-y", "pkg"])
    assert a.target_id.startswith("sandboxed-stdio://")
    assert "npx" in a.target_id
    assert "docker" not in a.target_id


def test_describe_emits_readable_summary(monkeypatch):
    _stub_docker(monkeypatch)
    a = SandboxedStdioAdapter(command=["python", "/s.py"])
    d = a.describe()
    assert d["inner_command"] == ["python", "/s.py"]
    assert d["image"]   == "python:3.12-slim"
    assert d["network"] == "none"
    assert d["read_only"] is True
    assert "docker" in d["docker_args"]


# ── with_allow_network helper ─────────────────────────────────────────────

def test_policy_with_allow_network_opts_into_bridge():
    p = SandboxPolicy().with_allow_network()
    assert p.network == "bridge"
    # Other hardening preserved.
    assert p.read_only_root is True


# ── engagement runner wiring ─────────────────────────────────────────────

def test_set_sandbox_toggles_stdio_mcp_factory(monkeypatch):
    """When set_sandbox(enabled=True) is called, the stdio-mcp://
    factory must return a SandboxedStdioAdapter instead of a plain
    StdioAdapter."""
    _stub_docker(monkeypatch)
    from argus.engagement.builtin import (
        _stdio_mcp_factory, set_sandbox, _SANDBOX_CONFIG,
    )
    # Snapshot + restore so the test is self-contained.
    prior = dict(_SANDBOX_CONFIG)
    try:
        set_sandbox(enabled=True, network="none")
        a = _stdio_mcp_factory("stdio-mcp://labrat")
        from argus.adapter import SandboxedStdioAdapter as _S
        assert isinstance(a, _S)
    finally:
        set_sandbox(**prior)


def test_set_sandbox_default_off_uses_plain_stdio_adapter():
    from argus.engagement.builtin import _stdio_mcp_factory
    from argus.adapter import StdioAdapter, SandboxedStdioAdapter
    a = _stdio_mcp_factory("stdio-mcp://labrat")
    assert isinstance(a, StdioAdapter)
    assert not isinstance(a, SandboxedStdioAdapter)
