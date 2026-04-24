"""
argus/autodeploy/detector.py — look at a cloned repo, say what it is.

The job: given a local directory that may be an agentic-AI
deployment (or the framework source code for one), produce a
``FrameworkSpec`` that tells ``runner.py`` how to stand it up.

Signals checked (cheap → expensive):

  1. Python project metadata: pyproject.toml / setup.py / requirements.txt
     → deps: crewai, langchain, langgraph, autogen, llama-index, mcp
  2. Node project metadata: package.json → deps: @modelcontextprotocol/*,
     langchain, openai, ai
  3. Container definitions: Dockerfile, docker-compose.yml
  4. Entry-point probes: main.py / app.py / server.py / crew.py with
     fastapi / flask / uvicorn / mcp.server imports
  5. Example app discovery: examples/ or cookbook/ or samples/ when
     the repo is a framework source tree (not an app built on it)

The detector DOES NOT run anything — all signals come from file
content and AST-free string matches. Keep it fast.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class DetectionError(Exception):
    pass


class FrameworkKind(str, Enum):
    MCP_NODE       = "mcp-node"
    MCP_PYTHON     = "mcp-python"
    CREWAI_APP     = "crewai-app"         # an app built on CrewAI
    CREWAI_FRAMEWORK = "crewai-framework" # the CrewAI repo itself
    LANGCHAIN_APP  = "langchain-app"
    LANGCHAIN_FRAMEWORK = "langchain-framework"
    LANGGRAPH_APP  = "langgraph-app"
    AUTOGEN_APP    = "autogen-app"
    LLAMAINDEX_APP = "llamaindex-app"
    DOCKERIZED     = "dockerized"         # Dockerfile / compose; shape unknown
    HTTP_AGENT_APP = "http-agent-app"     # generic fastapi/flask agent app
    UNKNOWN        = "unknown"


@dataclass
class FrameworkSpec:
    kind:            FrameworkKind
    repo_root:       Path
    # Entry point the runner should launch. For MCP-Python it's the
    # module name; for MCP-Node it's the package name; for HTTP apps
    # it's the python file path or the ``fastapi_app:app`` spec.
    entry_point:     str = ""
    # For framework repos (crewai-framework / langchain-framework),
    # example apps discovered inside — runner picks one to stand up.
    example_paths:   list[Path] = field(default_factory=list)
    # Env vars the app is likely to need to actually run. "likely"
    # because we parse imports, not full config. Operators can add
    # their own before launch.
    required_env:    list[str] = field(default_factory=list)
    # Launch strategy the runner will use. Values: "python-module",
    # "python-entry", "npx", "uvx", "docker", "docker-compose".
    launch_strategy: str = ""
    # Human-readable note explaining the detection for logs.
    notes:           str = ""


# ── Dep markers per framework ─────────────────────────────────────────────

_PY_DEP_CREWAI     = re.compile(r"(?i)\bcrewai\b")
_PY_DEP_LANGCHAIN  = re.compile(r"(?i)\blangchain(?:-\w+)?\b")
_PY_DEP_LANGGRAPH  = re.compile(r"(?i)\blanggraph\b")
_PY_DEP_AUTOGEN    = re.compile(r"(?i)\b(autogen|pyautogen|ag2|autogen-agentchat)\b")
_PY_DEP_LLAMAINDEX = re.compile(r"(?i)\bllama[-_]?index\b")
_PY_DEP_MCP        = re.compile(r"(?i)\bmcp\b")
_PY_DEP_FASTAPI    = re.compile(r"(?i)\bfastapi\b")
_PY_DEP_UVICORN    = re.compile(r"(?i)\buvicorn\b")
_PY_DEP_FLASK      = re.compile(r"(?i)\bflask\b")

_NODE_DEP_MCP      = re.compile(r"@modelcontextprotocol/")
_NODE_DEP_LANGCHAIN = re.compile(r"(?i)\blangchain(?:js)?\b")


# ── Per-signal readers ────────────────────────────────────────────────────

def _read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _pyproject_deps(root: Path) -> str:
    """Concatenate every text source where python deps live. Avoids a
    TOML parser since we only need substring matches."""
    out = ""
    for name in ("pyproject.toml", "setup.py", "setup.cfg",
                 "requirements.txt", "requirements-dev.txt", "Pipfile",
                 "poetry.lock", "uv.lock"):
        p = root / name
        if p.is_file():
            out += "\n" + _read_text(p)
    return out


def _node_deps(root: Path) -> str:
    pkg = root / "package.json"
    if not pkg.is_file():
        return ""
    try:
        data = json.loads(_read_text(pkg) or "{}")
    except json.JSONDecodeError:
        return _read_text(pkg)
    # Flatten all dep keys we care about.
    parts: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies"):
        if isinstance(data.get(key), dict):
            parts.extend(data[key].keys())
    # main / bin — useful for launch strategy.
    parts.append(str(data.get("main", "")))
    parts.append(json.dumps(data.get("bin") or {}))
    parts.append(str(data.get("name", "")))
    return "\n".join(parts)


def _has_file(root: Path, *names: str) -> bool:
    return any((root / n).is_file() for n in names)


def _find_mcp_python_module(root: Path) -> str:
    """For a Python MCP server, find the module to launch via
    ``python -m <module>``. Returns the first match under src/ or the
    repo root that imports ``mcp.server``."""
    candidates: list[Path] = []
    for sub in ("src", "."):
        base = root / sub if sub != "." else root
        if not base.is_dir():
            continue
        for p in base.rglob("*.py"):
            # Skip venvs / test trees / examples.
            if any(seg in (".venv", "venv", "tests", "test",
                           "node_modules", "__pycache__", "examples")
                   for seg in p.parts):
                continue
            try:
                body = _read_text(p, limit=8_000)
            except OSError:
                continue
            if "mcp.server" in body or "from mcp." in body \
               or "import mcp" in body and "Server(" in body:
                candidates.append(p)
    if not candidates:
        return ""
    # Prefer __main__.py / server.py / __init__.py.
    def _rank(p: Path) -> int:
        name = p.name
        if name == "__main__.py":   return 0
        if name == "server.py":      return 1
        if name == "__init__.py":    return 2
        return 10
    candidates.sort(key=_rank)
    winner = candidates[0]
    # Convert path to a python module spec relative to the repo root.
    rel = winner.relative_to(root)
    parts = list(rel.parts)
    # Strip src/ prefix, __init__.py / __main__.py tail.
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] in ("__main__.py", "__init__.py"):
        parts = parts[:-1]
    elif parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(parts)


def _find_http_entry(root: Path) -> tuple[str, str]:
    """Return (strategy, entry) for a FastAPI/Flask HTTP agent app.
    strategy ∈ {"python-entry", "uvicorn-module"}; entry is the
    launch argument. ('', '') when nothing plausible found."""
    candidates = [
        root / "main.py", root / "app.py", root / "server.py",
        root / "crew.py", root / "agent.py",
        root / "src" / "main.py", root / "src" / "app.py",
    ]
    for p in candidates:
        if not p.is_file():
            continue
        body = _read_text(p, limit=8_000)
        # FastAPI app detection.
        if "FastAPI(" in body or "fastapi" in body.lower():
            # Does the file also call uvicorn.run()? If yes it's
            # self-launching — use python-entry. Otherwise module.
            if "uvicorn.run" in body or "__name__" in body:
                return "python-entry", str(p)
            return "uvicorn-module", f"{p.stem}:app"
        if "Flask(" in body:
            return "python-entry", str(p)
    return "", ""


def _discover_examples(root: Path) -> list[Path]:
    """For framework repos: enumerate example-app directories."""
    dirs: list[Path] = []
    for name in ("examples", "example", "cookbook", "samples",
                 "demos", "demo", "quickstart", "templates"):
        p = root / name
        if p.is_dir():
            # Collect direct subdirs that look like apps (have
            # their own pyproject / main.py / package.json).
            for sub in sorted(p.iterdir()):
                if not sub.is_dir():
                    continue
                if _has_file(sub, "pyproject.toml", "requirements.txt",
                             "main.py", "app.py", "server.py",
                             "crew.py", "package.json"):
                    dirs.append(sub)
            # Also include the parent itself if it has an app file
            # directly (e.g., examples/main.py).
            if _has_file(p, "main.py", "app.py", "crew.py"):
                dirs.append(p)
    return dirs


# ── Main detector ────────────────────────────────────────────────────────

def detect_framework(repo_root: Path) -> FrameworkSpec:
    """Classify ``repo_root`` and pick a launch strategy.

    Raises ``DetectionError`` on empty / missing paths; returns a
    ``FrameworkSpec`` with ``kind=UNKNOWN`` when the shape is
    recognisable but unsupported (runner will honestly bail instead
    of guessing)."""
    if not repo_root.is_dir():
        raise DetectionError(f"repo root not a directory: {repo_root}")

    py_deps   = _pyproject_deps(repo_root)
    node_deps = _node_deps(repo_root)

    # Combined corpus used by name-based detectors.
    top_readme = (_read_text(repo_root / "README.md", limit=4_000)
                  if (repo_root / "README.md").is_file() else "")

    has_dockerfile = _has_file(repo_root, "Dockerfile")
    has_compose    = _has_file(repo_root, "docker-compose.yml",
                               "compose.yml", "compose.yaml")

    # Framework-source detection: if the repo NAME matches the
    # framework and it contains examples/, treat it as a framework
    # repo whose example apps we'll stand up.
    repo_name = repo_root.name.lower()
    is_named_framework = any(
        k in repo_name for k in ("crewai", "langchain", "langgraph",
                                 "autogen", "llama_index", "llamaindex")
    )
    examples = _discover_examples(repo_root) if is_named_framework else []

    # ── 1) MCP (highest priority — narrowest shape) ──────────────
    if _NODE_DEP_MCP.search(node_deps):
        # package.json contains @modelcontextprotocol/* dep.
        pkg = (repo_root / "package.json")
        name = ""
        try:
            name = json.loads(_read_text(pkg) or "{}").get("name", "")
        except json.JSONDecodeError:
            pass
        return FrameworkSpec(
            kind=FrameworkKind.MCP_NODE, repo_root=repo_root,
            entry_point=name or str(repo_root),
            launch_strategy="npx-local",
            notes=f"package.json declares @modelcontextprotocol dep; name={name!r}",
        )

    if _PY_DEP_MCP.search(py_deps):
        module = _find_mcp_python_module(repo_root)
        if module:
            return FrameworkSpec(
                kind=FrameworkKind.MCP_PYTHON, repo_root=repo_root,
                entry_point=module,
                launch_strategy="python-module",
                notes=f"pyproject declares `mcp` dep; entry module={module}",
            )

    # ── 2) Framework-source repos (CrewAI, LangChain) ────────────
    if "crewai" in repo_name and examples:
        return FrameworkSpec(
            kind=FrameworkKind.CREWAI_FRAMEWORK, repo_root=repo_root,
            example_paths=examples,
            required_env=["OPENAI_API_KEY"],
            launch_strategy="framework-example",
            notes=f"CrewAI source tree with {len(examples)} example app(s)",
        )
    if ("langchain" in repo_name or "langgraph" in repo_name) and examples:
        return FrameworkSpec(
            kind=FrameworkKind.LANGCHAIN_FRAMEWORK, repo_root=repo_root,
            example_paths=examples,
            required_env=["OPENAI_API_KEY"],
            launch_strategy="framework-example",
            notes=f"LangChain source tree with {len(examples)} example app(s)",
        )

    # ── 3) Apps that import a known framework ────────────────────
    strat, entry = _find_http_entry(repo_root)
    if _PY_DEP_CREWAI.search(py_deps):
        return FrameworkSpec(
            kind=FrameworkKind.CREWAI_APP, repo_root=repo_root,
            entry_point=entry or "crew.py",
            launch_strategy=strat or "python-entry",
            required_env=["OPENAI_API_KEY"],
            notes="pyproject declares crewai dep",
        )
    if _PY_DEP_LANGGRAPH.search(py_deps):
        return FrameworkSpec(
            kind=FrameworkKind.LANGGRAPH_APP, repo_root=repo_root,
            entry_point=entry or "main.py",
            launch_strategy=strat or "python-entry",
            required_env=["OPENAI_API_KEY"],
            notes="pyproject declares langgraph dep",
        )
    if _PY_DEP_LANGCHAIN.search(py_deps):
        return FrameworkSpec(
            kind=FrameworkKind.LANGCHAIN_APP, repo_root=repo_root,
            entry_point=entry or "main.py",
            launch_strategy=strat or "python-entry",
            required_env=["OPENAI_API_KEY"],
            notes="pyproject declares langchain dep",
        )
    if _PY_DEP_AUTOGEN.search(py_deps):
        return FrameworkSpec(
            kind=FrameworkKind.AUTOGEN_APP, repo_root=repo_root,
            entry_point=entry or "main.py",
            launch_strategy=strat or "python-entry",
            required_env=["OPENAI_API_KEY"],
            notes="pyproject declares autogen dep",
        )
    if _PY_DEP_LLAMAINDEX.search(py_deps):
        return FrameworkSpec(
            kind=FrameworkKind.LLAMAINDEX_APP, repo_root=repo_root,
            entry_point=entry or "main.py",
            launch_strategy=strat or "python-entry",
            required_env=["OPENAI_API_KEY"],
            notes="pyproject declares llama-index dep",
        )

    # ── 4) Generic HTTP agent app (fastapi/flask, no declared framework) ──
    if strat and entry:
        return FrameworkSpec(
            kind=FrameworkKind.HTTP_AGENT_APP, repo_root=repo_root,
            entry_point=entry, launch_strategy=strat,
            notes="fastapi/flask HTTP entry detected; no framework declared",
        )

    # ── 5) Dockerized (fallback) ─────────────────────────────────
    if has_compose:
        return FrameworkSpec(
            kind=FrameworkKind.DOCKERIZED, repo_root=repo_root,
            entry_point="docker-compose.yml",
            launch_strategy="docker-compose",
            notes="docker-compose.yml present; launch shape unknown",
        )
    if has_dockerfile:
        return FrameworkSpec(
            kind=FrameworkKind.DOCKERIZED, repo_root=repo_root,
            entry_point="Dockerfile",
            launch_strategy="docker",
            notes="Dockerfile present; ARGUS can build + run",
        )

    # ── 6) Unknown ────────────────────────────────────────────────
    return FrameworkSpec(
        kind=FrameworkKind.UNKNOWN, repo_root=repo_root,
        notes=(
            "No recognized agentic-framework deps, MCP markers, "
            "fastapi/flask entry, or Dockerfile. Repo README "
            f"starts: {top_readme[:120].strip()!r}"
        ),
    )
