"""MCP protocol models for ARGUS attack client."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class MCPToolParameter(BaseModel):
    """A parameter definition for an MCP tool."""
    name: str
    description: Optional[str] = None
    type: str = "string"
    required: bool = False
    enum: Optional[list[str]] = None
    default: Optional[Any] = None


class MCPTool(BaseModel):
    """An MCP tool definition as seen by the attacker client."""
    name: str
    description: Optional[str] = None
    parameters: list[MCPToolParameter] = Field(default_factory=list)
    input_schema: Optional[dict[str, Any]] = None

    # Attack-relevant metadata
    raw_definition: Optional[dict[str, Any]] = None
    hidden_content_detected: bool = False
    hidden_content: Optional[str] = None


class MCPServerConfig(BaseModel):
    """Configuration for connecting to an MCP server under test."""
    name: str
    transport: str = "stdio"  # stdio, sse, streamable-http

    # stdio transport
    command: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    # HTTP transports
    url: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)

    # Auth
    api_key: Optional[str] = None

    # Testing constraints
    timeout_seconds: int = 30
    max_concurrent_calls: int = 5


class MCPCallResult(BaseModel):
    """Result from calling an MCP tool."""
    tool_name: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    raw_response: Optional[dict[str, Any]] = None
    duration_ms: Optional[float] = None
