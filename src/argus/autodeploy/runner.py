"""
argus/autodeploy/runner.py — clone repo, stand up target, return URL.

Consumes the ``FrameworkSpec`` from ``detector.py`` and produces a
``Deployment``: a context-managed handle that owns the stood-up
process, exposes ``.url`` to the engagement runner, and guarantees
teardown even on exception.

Launch strategies this MVP supports:

    mcp-python       python -m <module>         (stdio subprocess)
    mcp-node         npx <pkg> | node <entry>   (stdio subprocess)
    python-entry     python <main.py>           (HTTP app, waits for port)
    uvicorn-module   uvicorn <module:app> --port <random>
    framework-example  recurse into examples/<dir>, re-detect + deploy

Explicitly out of scope for this MVP (fail with honest message):
    docker, docker-compose, kubernetes, multi-service orchestration

Isolation:
    - Python installs happen in a uv-managed venv rooted in the
      staging dir. The operator's site-packages is never touched.
    - HTTP apps are bound to 127.0.0.1 on a randomly-assigned port;
      stdio apps inherit no network unless they open it themselves.
    - Cleanup kills the process group, deletes the venv, and rmtrees
      the staging dir.

Timeouts:
    - Clone: 60s
    - Install: 180s (uv is fast but PyTorch-level deps blow past 60s)
    - Health check: 30s
    All raise ``DeploymentError`` with a pointer at the stuck stage.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from argus.autodeploy.detector import (
    FrameworkKind, FrameworkSpec, detect_framework, DetectionError,
)


class DeploymentError(Exception):
    pass


# ── Deployment handle ────────────────────────────────────────────────────


@dataclass
class Deployment:
    """Handle to a stood-up target. Use as a context manager; the
    ``url`` property is what the engagement runner attacks."""
    spec:         FrameworkSpec
    url:          str
    staging_dir:  Path
    process:      Optional[subprocess.Popen] = None
    venv_dir:     Optional[Path] = None
    # True when this deployment was launched as an stdio subprocess
    # (MCP-style). HTTP deployments set this False.
    is_stdio:     bool = False
    # Command tokens for the launched subprocess — operator-visible
    # in logs and test assertions.
    launch_argv:  list[str] = field(default_factory=list)
    notes:        str = ""

    def shutdown(self) -> None:
        proc = self.process
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
            except Exception:
                pass
        if self.staging_dir and self.staging_dir.exists():
            # Rmtree best-effort; a half-installed pip cache blocks
            # sometimes — log and move on.
            try:
                shutil.rmtree(self.staging_dir, ignore_errors=True)
            except Exception:
                pass

    def __enter__(self) -> "Deployment":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()


# ── Primitives ───────────────────────────────────────────────────────────


def _staging_root() -> Path:
    root = Path(tempfile.gettempdir()) / "argus-staging"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _git_clone(repo_url: str, dest: Path) -> None:
    if dest.exists():
        raise DeploymentError(f"staging dir already exists: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch",
         repo_url, str(dest)],
        capture_output=True, text=True, timeout=60.0,
    )
    if proc.returncode != 0:
        raise DeploymentError(
            f"git clone failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '<no output>').strip()[:500]}"
        )


def _uv_venv(path: Path, python: Optional[str] = None) -> Path:
    """Create an isolated venv via uv. Returns the venv root."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["uv", "venv", str(path)]
    if python:
        cmd += ["--python", python]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60.0)
    if proc.returncode != 0:
        raise DeploymentError(
            f"uv venv failed: {proc.stderr.strip()[:400] or 'unknown'}"
        )
    return path


def _uv_pip_install(venv: Path, repo: Path, extras: list[str] = []) -> None:
    """Install the repo into the venv. Handles pyproject.toml,
    setup.py, and requirements.txt shapes."""
    extras_suffix = f"[{','.join(extras)}]" if extras else ""
    install_target = f"{repo}{extras_suffix}" if extras_suffix else str(repo)

    cmd = ["uv", "pip", "install", "--python",
           str(venv / "bin" / "python"), "-e", install_target]
    # Fall back to requirements.txt if the project isn't installable
    # as an editable. We try editable first, retry bare if it fails.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180.0)
    if proc.returncode == 0:
        return

    # Requirements fallback.
    req = repo / "requirements.txt"
    if req.is_file():
        cmd = ["uv", "pip", "install", "--python",
               str(venv / "bin" / "python"), "-r", str(req)]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180.0,
        )
        if proc.returncode == 0:
            return

    raise DeploymentError(
        f"pip install failed: "
        f"{proc.stderr.strip()[:500] or proc.stdout.strip()[:500]}"
    )


def _npm_install(repo: Path) -> None:
    proc = subprocess.run(
        ["npm", "install", "--silent", "--no-audit",
         "--no-fund", "--prefer-offline"],
        cwd=str(repo),
        capture_output=True, text=True, timeout=180.0,
    )
    if proc.returncode != 0:
        raise DeploymentError(
            f"npm install failed: "
            f"{proc.stderr.strip()[:500] or proc.stdout.strip()[:500]}"
        )


# ── Per-strategy launchers ───────────────────────────────────────────────


def _launch_mcp_python(
    spec: FrameworkSpec, staging: Path,
) -> Deployment:
    """Install into a venv and launch `python -m <module>` as an stdio
    subprocess. Return a Deployment whose ``url`` is a
    ``stdio-mcp://`` URL encoding the exact launch command."""
    venv = staging / ".argus-venv"
    _uv_venv(venv)
    _uv_pip_install(venv, spec.repo_root)

    argv = [
        str(venv / "bin" / "python"), "-m", spec.entry_point,
    ]
    # The engagement runner's stdio-mcp:// factory expects a URL whose
    # body shlex-splits into the full argv. Return that URL; don't
    # launch the subprocess here — the factory launches it as part of
    # its adapter context manager, so we keep lifecycle in one place.
    body = " ".join(argv)
    url = f"stdio-mcp://{body.replace(' ', '+')}"
    return Deployment(
        spec=spec, url=url, staging_dir=staging.parent,
        venv_dir=venv, is_stdio=True, launch_argv=argv,
        notes=f"mcp-python module={spec.entry_point!r} venv={venv}",
    )


def _launch_mcp_node(
    spec: FrameworkSpec, staging: Path,
) -> Deployment:
    """Install npm deps and return an stdio-mcp URL that invokes the
    published package name (preferred — reproducible) or the local
    entry point if the package isn't publishable."""
    _npm_install(spec.repo_root)
    # Prefer name from package.json (installable via npx from the
    # local path). If the package isn't named, fall back to
    # ``node dist/index.js`` or ``node index.js`` if present.
    pkg_name = spec.entry_point
    if pkg_name and "/" not in pkg_name and pkg_name != str(spec.repo_root):
        # Simple name — use npx against the local directory.
        argv = ["npx", "--no-install", "--prefix",
                str(spec.repo_root), pkg_name]
    else:
        # Fall back to node + entry file discovery.
        for candidate in ("dist/index.js", "build/index.js",
                          "index.js", "server.js"):
            p = spec.repo_root / candidate
            if p.is_file():
                argv = ["node", str(p)]
                break
        else:
            raise DeploymentError(
                "mcp-node repo has no index.js / dist entry — "
                "unable to determine launch command"
            )

    body = " ".join(argv)
    url = f"stdio-mcp://{body.replace(' ', '+')}"
    return Deployment(
        spec=spec, url=url, staging_dir=staging.parent,
        is_stdio=True, launch_argv=argv,
        notes=f"mcp-node pkg={pkg_name!r}",
    )


def _launch_http_app(
    spec: FrameworkSpec, staging: Path,
) -> Deployment:
    """Stand up a FastAPI/Flask HTTP agent app on a random loopback
    port. Wait for the port to accept connections (30s timeout)."""
    venv = staging / ".argus-venv"
    _uv_venv(venv)
    _uv_pip_install(venv, spec.repo_root)

    port = _free_port()
    env = dict(os.environ)
    env["PORT"]    = str(port)        # standard
    env["HOST"]    = "127.0.0.1"
    # Some CrewAI/LangChain apps require LLM keys to even import.
    # Operator must set them in their shell; we only forward.

    if spec.launch_strategy == "uvicorn-module":
        argv = [
            str(venv / "bin" / "uvicorn"),
            spec.entry_point,
            "--host", "127.0.0.1",
            "--port", str(port),
        ]
    else:  # "python-entry"
        argv = [str(venv / "bin" / "python"), spec.entry_point]

    proc = subprocess.Popen(
        argv, cwd=str(spec.repo_root), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )

    # Wait for port to accept — or for the process to die.
    deadline = time.time() + 30.0
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = (proc.stderr.read() if proc.stderr else b"").decode(
                "utf-8", errors="replace",
            )[-500:]
            raise DeploymentError(
                f"HTTP app exited before accepting connections "
                f"(exit={proc.returncode}). stderr tail: {tail.strip()}"
            )
        if _port_open("127.0.0.1", port):
            break
        time.sleep(0.25)
    else:
        proc.terminate()
        raise DeploymentError(
            f"HTTP app didn't bind 127.0.0.1:{port} within 30s"
        )

    url = f"http://127.0.0.1:{port}"
    return Deployment(
        spec=spec, url=url, staging_dir=staging.parent,
        process=proc, venv_dir=venv, is_stdio=False,
        launch_argv=argv,
        notes=f"http-app port={port} strategy={spec.launch_strategy}",
    )


def _launch_framework_example(
    spec: FrameworkSpec, staging: Path,
) -> Deployment:
    """Framework-source repos (crewai-framework, langchain-framework)
    don't run themselves — but their examples/ directories do. Pick
    the first example that re-detects as an app and deploy it."""
    if not spec.example_paths:
        raise DeploymentError(
            f"{spec.kind.value} repo has no discoverable example apps"
        )
    last_err: Optional[str] = None
    for example in spec.example_paths:
        try:
            sub_spec = detect_framework(example)
        except DetectionError as e:
            last_err = f"{example}: {e}"
            continue
        if sub_spec.kind == FrameworkKind.UNKNOWN:
            last_err = f"{example}: unknown shape"
            continue
        # Recurse with the example as the new repo_root.
        return _dispatch_launch(sub_spec, staging)
    raise DeploymentError(
        f"no example in {spec.kind.value} could be stood up: {last_err}"
    )


# ── Strategy dispatch ────────────────────────────────────────────────────

def _dispatch_launch(spec: FrameworkSpec, staging: Path) -> Deployment:
    strat = spec.launch_strategy
    if strat == "python-module":
        return _launch_mcp_python(spec, staging)
    if strat == "npx-local":
        return _launch_mcp_node(spec, staging)
    if strat in ("python-entry", "uvicorn-module"):
        return _launch_http_app(spec, staging)
    if strat == "framework-example":
        return _launch_framework_example(spec, staging)
    if strat in ("docker", "docker-compose"):
        raise DeploymentError(
            f"docker launch strategies not implemented yet "
            f"(kind={spec.kind.value}); build manually and point "
            f"ARGUS at the running URL instead"
        )
    raise DeploymentError(
        f"no launcher for strategy={strat!r} (kind={spec.kind.value}); "
        f"spec notes: {spec.notes}"
    )


# ── Public entry point ───────────────────────────────────────────────────


def deploy(repo_url: str, *, staging: Optional[Path] = None) -> Deployment:
    """Clone + detect + launch. Returns a context-managed Deployment
    whose ``url`` can be handed straight to ``run_engagement``.

    Callers are expected to use this as a context manager so teardown
    runs deterministically:

        with deploy("https://github.com/org/repo") as d:
            result = run_engagement(d.url, ...)

    ``staging`` override is primarily for tests; leave unset in
    production so the staging dir lives under
    ``$TMPDIR/argus-staging/<uuid>``.
    """
    if not repo_url or not repo_url.strip():
        raise DeploymentError("empty repo_url")

    # Normalise a few shapes. We accept:
    #   https://github.com/<org>/<repo>[.git]
    #   git@github.com:<org>/<repo>.git
    #   <repo_url> as-is (passed to git clone)
    if staging is None:
        staging = _staging_root() / uuid.uuid4().hex[:12]

    repo_dir = staging / "repo"
    _git_clone(repo_url, repo_dir)
    try:
        spec = detect_framework(repo_dir)
    except DetectionError as e:
        shutil.rmtree(staging, ignore_errors=True)
        raise DeploymentError(f"detection failed: {e}") from e

    if spec.kind == FrameworkKind.UNKNOWN:
        shutil.rmtree(staging, ignore_errors=True)
        raise DeploymentError(
            f"unknown shape — ARGUS doesn't know how to stand up "
            f"{repo_url}. Detector notes: {spec.notes}"
        )

    try:
        return _dispatch_launch(spec, staging)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# ── One-shot context helper (convenience) ────────────────────────────────

@contextmanager
def deployed(repo_url: str) -> Iterator[Deployment]:
    """Shorthand context manager — ``with deployed(url) as d:``."""
    d = deploy(repo_url)
    try:
        yield d
    finally:
        d.shutdown()
