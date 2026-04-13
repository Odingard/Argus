"""ARGUS Live Terminal UI — Rich-powered streaming dashboards."""

from argus.ui.cinematic_dashboard import CinematicDashboard
from argus.ui.colors import AGENT_COLORS, agent_color, agent_color_by_value
from argus.ui.live_dashboard import LiveDashboard

__all__ = ["LiveDashboard", "CinematicDashboard", "AGENT_COLORS", "agent_color", "agent_color_by_value"]
