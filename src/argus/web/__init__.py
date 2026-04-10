"""ARGUS Web Dashboard — FastAPI server with live SSE event streaming.

This is the production-grade web UI for ARGUS, designed to look like a
real security platform (Aikido / Pentera-style) rather than a terminal.

Components:
- server.py — FastAPI app with REST endpoints + SSE event stream
- static/ — HTML/CSS/JS frontend (no build step)
"""

from argus.web.server import create_app

__all__ = ["create_app"]
