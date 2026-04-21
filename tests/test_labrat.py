"""
tests/test_labrat.py — Target Simulation Framework (Ticket 0.6).

Offline. We don't actually run docker in unit tests — the integration
test in Phase 0 acceptance handles that. Here we exercise:
  - LabConfig YAML round-trip
  - compose generation correctness (network isolation default,
    service blocks, port mappings)
  - Lab CLI smokes (writing compose, status without docker)
  - Validation errors when config is malformed
"""
from __future__ import annotations

from pathlib import Path

import pytest

from argus.labrat import (
    Lab, LabConfig, LabConfigError, LabError, NetworkSpec, ServiceSpec,
)


# ── ServiceSpec validation ───────────────────────────────────────────────────

def test_service_spec_requires_image_or_build():
    with pytest.raises(LabConfigError):
        ServiceSpec(name="x")  # neither image nor build_context


def test_service_spec_to_compose_includes_only_set_fields():
    s = ServiceSpec(name="api", image="python:3.12", ports=["8080:8080"])
    block = s.to_compose_block()
    assert block["image"] == "python:3.12"
    assert block["ports"] == ["8080:8080"]
    assert "command" not in block
    assert "environment" not in block


# ── LabConfig YAML loading ────────────────────────────────────────────────────

def test_lab_config_from_yaml(tmp_path):
    yaml_text = """\
name: t1
description: "test lab"
services:
  - name: api
    image: python:3.12
    ports: ["8080:8080"]
    env:
      X: "1"
"""
    p = tmp_path / "lab.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg = LabConfig.from_yaml(str(p))
    assert cfg.name == "t1"
    assert len(cfg.services) == 1
    assert cfg.services[0].name == "api"
    assert cfg.services[0].env == {"X": "1"}
    assert cfg.network.isolated is True   # default isolation


def test_lab_config_missing_required_field(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("description: no name", encoding="utf-8")
    with pytest.raises(LabConfigError):
        LabConfig.from_yaml(str(p))


def test_lab_config_missing_file():
    with pytest.raises(LabConfigError):
        LabConfig.from_yaml("/nonexistent/path/lab.yaml")


# ── Compose generation ───────────────────────────────────────────────────────

def test_to_compose_dict_attaches_network_to_every_service():
    cfg = LabConfig(
        name="t",
        services=[
            ServiceSpec(name="a", image="python:3.12"),
            ServiceSpec(name="b", image="python:3.12"),
        ],
    )
    compose = cfg.to_compose_dict()
    assert set(compose["services"]) == {"a", "b"}
    for svc in compose["services"].values():
        assert svc["networks"] == ["argus_t_net"]
    assert compose["networks"]["argus_t_net"]["internal"] is True


def test_isolation_can_be_disabled():
    cfg = LabConfig(
        name="t",
        services=[ServiceSpec(name="a", image="python:3.12")],
        network=NetworkSpec(isolated=False),
    )
    compose = cfg.to_compose_dict()
    assert compose["networks"]["argus_t_net"]["internal"] is False


def test_compose_yaml_round_trips_through_yaml():
    import yaml
    cfg = LabConfig(
        name="t",
        services=[ServiceSpec(name="a", image="python:3.12",
                              ports=["8080:8080"])],
    )
    text = cfg.to_compose_yaml()
    parsed = yaml.safe_load(text)
    assert parsed["services"]["a"]["image"] == "python:3.12"


# ── Lab CLI surface (no docker) ──────────────────────────────────────────────

def test_lab_writes_compose_file(tmp_path):
    cfg = LabConfig(
        name="t",
        services=[ServiceSpec(name="a", image="python:3.12")],
        project_dir=str(tmp_path),
    )
    lab = Lab(cfg)
    p = lab.write_compose()
    assert p.exists()
    text = p.read_text(encoding="utf-8")
    assert "image: python:3.12" in text
    assert "internal: true" in text


def test_lab_up_raises_loud_when_docker_missing(tmp_path):
    cfg = LabConfig(
        name="t",
        services=[ServiceSpec(name="a", image="python:3.12")],
        project_dir=str(tmp_path),
    )
    lab = Lab(cfg, docker_binary="docker-not-installed-anywhere-zzz")
    with pytest.raises(LabError) as exc:
        lab.up()
    assert "docker" in str(exc.value).lower()


def test_lab_status_returns_empty_when_compose_not_written(tmp_path, monkeypatch):
    cfg = LabConfig(
        name="t",
        services=[ServiceSpec(name="a", image="python:3.12")],
        project_dir=str(tmp_path),
    )
    # Pretend docker exists — but the file doesn't, so status() short-circuits.
    monkeypatch.setattr("shutil.which", lambda _binary: "/usr/bin/docker")
    lab = Lab(cfg)
    # Fresh compose dir; status before up() should report 0 services.
    s = lab.status()
    assert s.running == 0
    assert s.services == []


# ── Templates ────────────────────────────────────────────────────────────────

def test_ship_templates_load_cleanly():
    """The two reference YAMLs ship with the package; both must parse."""
    base = Path(__file__).resolve().parent.parent / "src" / "argus" / "labrat" / "templates"
    for tmpl in ("mcp_only.yaml", "multi_agent.yaml"):
        cfg = LabConfig.from_yaml(str(base / tmpl))
        assert cfg.name
        assert cfg.services, f"{tmpl}: zero services"
