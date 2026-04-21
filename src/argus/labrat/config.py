"""
argus/labrat/config.py — typed lab configuration loaded from YAML.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


class LabConfigError(Exception):
    """Raised on missing or invalid lab YAML."""


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class NetworkSpec:
    name:     str = ""
    isolated: bool = True       # internal: true on the docker network


@dataclass
class ServiceSpec:
    name:        str
    image:       str = ""           # if set, no build context required
    build_context: Optional[str] = None
    dockerfile:  Optional[str] = None
    command:     Optional[list[str]] = None
    ports:       list[str] = field(default_factory=list)   # "host:container"
    env:         dict[str, str] = field(default_factory=dict)
    volumes:     list[str] = field(default_factory=list)
    depends_on:  list[str] = field(default_factory=list)
    healthcheck: Optional[dict[str, Any]] = None
    restart:     str = "no"

    def __post_init__(self) -> None:
        if not self.name:
            raise LabConfigError("ServiceSpec.name is required")
        if not self.image and not self.build_context:
            raise LabConfigError(
                f"service {self.name!r}: must set either image or build_context"
            )

    def to_compose_block(self) -> dict[str, Any]:
        """Convert into the dict shape a docker-compose YAML expects."""
        block: dict[str, Any] = {}
        if self.image:
            block["image"] = self.image
        if self.build_context:
            build: dict[str, Any] = {"context": self.build_context}
            if self.dockerfile:
                build["dockerfile"] = self.dockerfile
            block["build"] = build
        if self.command is not None:
            block["command"] = list(self.command)
        if self.ports:
            block["ports"] = list(self.ports)
        if self.env:
            block["environment"] = dict(self.env)
        if self.volumes:
            block["volumes"] = list(self.volumes)
        if self.depends_on:
            block["depends_on"] = list(self.depends_on)
        if self.healthcheck:
            block["healthcheck"] = dict(self.healthcheck)
        if self.restart and self.restart != "no":
            block["restart"] = self.restart
        return block


@dataclass
class LabConfig:
    name:        str
    description: str = ""
    services:    list[ServiceSpec] = field(default_factory=list)
    network:     NetworkSpec = field(default_factory=NetworkSpec)
    project_dir: Optional[str] = None    # root for any relative build_context

    # ── Constructors ──────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str) -> "LabConfig":
        try:
            import yaml
        except ImportError as e:
            raise LabConfigError(
                "PyYAML not installed. Add `pyyaml` to the environment."
            ) from e
        p = Path(path)
        if not p.exists():
            raise LabConfigError(f"lab config not found: {path}")
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise LabConfigError(f"YAML parse failure: {e}") from e
        if not isinstance(raw, dict):
            raise LabConfigError(
                f"top-level YAML must be a mapping, got {type(raw).__name__}"
            )
        return cls.from_dict(raw, project_dir=str(p.resolve().parent))

    @classmethod
    def from_dict(cls, d: dict, *, project_dir: Optional[str] = None) -> "LabConfig":
        try:
            services_raw = d.get("services") or []
            services = []
            for s in services_raw:
                if not isinstance(s, dict):
                    raise LabConfigError("each service must be a mapping")
                services.append(ServiceSpec(
                    name=s["name"],
                    image=s.get("image", ""),
                    build_context=s.get("build_context"),
                    dockerfile=s.get("dockerfile"),
                    command=s.get("command"),
                    ports=list(s.get("ports", []) or []),
                    env=dict(s.get("env", {}) or {}),
                    volumes=list(s.get("volumes", []) or []),
                    depends_on=list(s.get("depends_on", []) or []),
                    healthcheck=(dict(s["healthcheck"]) if s.get("healthcheck") else None),
                    restart=s.get("restart", "no"),
                ))
            net_raw = d.get("network") or {}
            return cls(
                name=d["name"],
                description=d.get("description", ""),
                services=services,
                network=NetworkSpec(
                    name=net_raw.get("name", ""),
                    isolated=bool(net_raw.get("isolated", True)),
                ),
                project_dir=project_dir,
            )
        except KeyError as e:
            raise LabConfigError(f"missing required field: {e}") from e

    # ── Compose generator ────────────────────────────────────────────────

    def to_compose_dict(self) -> dict[str, Any]:
        """Produce the dict that serialises to docker-compose.yml."""
        net_name = self.network.name or f"argus_{self.name}_net"
        services: dict[str, Any] = {}
        for svc in self.services:
            block = svc.to_compose_block()
            block["networks"] = [net_name]
            services[svc.name] = block
        return {
            "name":     f"argus-{self.name}",
            "services": services,
            "networks": {
                net_name: {
                    "driver":   "bridge",
                    "internal": self.network.isolated,
                }
            },
        }

    def to_compose_yaml(self) -> str:
        try:
            import yaml
        except ImportError as e:
            raise LabConfigError("PyYAML not installed") from e
        return yaml.safe_dump(self.to_compose_dict(), sort_keys=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d
