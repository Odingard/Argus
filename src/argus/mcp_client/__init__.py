"""MCP Client Library — connects to any MCP server as an attacker client."""

from argus.mcp_client.client import MCPAttackClient
from argus.mcp_client.models import MCPServerConfig, MCPTool, MCPToolParameter

__all__ = ["MCPAttackClient", "MCPServerConfig", "MCPTool", "MCPToolParameter"]
