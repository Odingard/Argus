"""
argus.autodeploy — take a git URL, return a running target.

Mission-aligned: closes the gap between "client hands us a repo" and
"ARGUS attacks a running agentic system." The attack slate already
exists; this module produces the live URL it points at.

Pipeline:

    1. Clone repo (shallow, ephemeral /tmp root)
    2. Detect framework (CrewAI / LangChain / AutoGen / MCP / ...)
    3. Pick a launch strategy (python entry, docker, npx, uvx)
    4. Launch in an isolated env; health-check; bind loopback only
    5. Return a target URL the engagement runner can engage

On teardown the stood-up process is killed and the staging dir is
garbage-collected.

The detector + runner are deliberately modest: they handle the
ecosystem shapes tonight's targets actually take. Unknown shapes
raise ``DeploymentError`` with a clear pointer at what ARGUS would
need to stand them up — no silent half-success.
"""
from argus.autodeploy.detector import (
    FrameworkKind, FrameworkSpec, detect_framework, DetectionError,
)
from argus.autodeploy.runner import (
    Deployment, deploy, DeploymentError,
)

__all__ = [
    "FrameworkKind", "FrameworkSpec", "detect_framework", "DetectionError",
    "Deployment", "deploy", "DeploymentError",
]
