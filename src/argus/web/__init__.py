"""ARGUS Web Dashboard — FastAPI server with live SSE event streaming.

This is the production-grade web UI for ARGUS, designed for operators
who want a real security platform interface rather than a terminal.

Components:
- server.py — FastAPI app with REST endpoints + SSE event stream
- static/ — HTML/CSS/JS frontend (no build step)
"""

from argus.web.server import create_app

__all__ = ["create_app"]
