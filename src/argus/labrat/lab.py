"""
argus/labrat/lab.py — Lab lifecycle (up / down / status) over docker compose.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from argus.labrat.config import LabConfig


class LabError(Exception):
    """Lab lifecycle failures (docker missing, compose error, etc.)."""


@dataclass
class LabStatus:
    name:     str
    project:  str
    services: list[dict] = field(default_factory=list)
    running:  int = 0


class Lab:
    """
    Owns the on-disk compose project for a LabConfig and shells out to
    ``docker compose`` for up / down / ps.

    Pure infrastructure — does not run attacks. Adapters (Phase 0.2)
    point at the lab's exposed ports.
    """

    def __init__(
        self,
        config:        LabConfig,
        compose_dir:   Optional[str] = None,
        docker_binary: str = "docker",
    ) -> None:
        self.config        = config
        self.docker_binary = docker_binary
        # Where to write the generated compose file. Default: a stable
        # path under the user's project_dir, falling back to a temp dir.
        if compose_dir:
            self.compose_dir = Path(compose_dir)
        elif config.project_dir:
            self.compose_dir = Path(config.project_dir) / ".argus" / "labrat" / config.name
        else:
            self.compose_dir = Path(tempfile.mkdtemp(prefix="argus-labrat-"))
        self.compose_dir.mkdir(parents=True, exist_ok=True)
        self.compose_file = self.compose_dir / "docker-compose.yml"

    # ── Public lifecycle ─────────────────────────────────────────────────

    def write_compose(self) -> Path:
        """Write generated YAML to disk. Useful for inspection + tests."""
        self.compose_file.write_text(
            self.config.to_compose_yaml(), encoding="utf-8"
        )
        return self.compose_file

    def up(self, *, build: bool = True, detach: bool = True) -> None:
        self._require_docker()
        self.write_compose()
        cmd = [self.docker_binary, "compose", "-f", str(self.compose_file), "up"]
        if detach:
            cmd.append("-d")
        if build:
            cmd.append("--build")
        self._run(cmd, "lab up")

    def down(self, *, volumes: bool = True) -> None:
        self._require_docker()
        if not self.compose_file.exists():
            return
        cmd = [self.docker_binary, "compose", "-f", str(self.compose_file), "down"]
        if volumes:
            cmd.append("-v")
        self._run(cmd, "lab down")

    def status(self) -> LabStatus:
        self._require_docker()
        if not self.compose_file.exists():
            return LabStatus(
                name=self.config.name,
                project=f"argus-{self.config.name}",
                services=[],
                running=0,
            )
        cmd = [
            self.docker_binary, "compose", "-f", str(self.compose_file),
            "ps", "--format", "json",
        ]
        out = self._run(cmd, "lab status", capture=True) or ""
        services: list[dict] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                services.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        running = sum(1 for s in services
                      if str(s.get("State", "")).lower() == "running")
        return LabStatus(
            name=self.config.name,
            project=f"argus-{self.config.name}",
            services=services,
            running=running,
        )

    # ── Internals ────────────────────────────────────────────────────────

    def _require_docker(self) -> None:
        if shutil.which(self.docker_binary) is None:
            raise LabError(
                f"docker binary {self.docker_binary!r} not on PATH; "
                "labrat requires a working Docker installation."
            )

    def _run(self, cmd: list[str], label: str, *,
             capture: bool = False) -> Optional[str]:
        try:
            if capture:
                proc = subprocess.run(
                    cmd, check=True, capture_output=True, text=True,
                )
                return proc.stdout
            subprocess.run(cmd, check=True)
            return None
        except subprocess.CalledProcessError as e:
            raise LabError(
                f"{label} failed (exit {e.returncode}): "
                f"{(e.stderr or e.stdout or '').strip()[:400]}"
            ) from e
        except FileNotFoundError as e:
            raise LabError(f"{label}: command not found: {e}") from e
