"""
argus/adapter/http_agent.py — Generic HTTP / chat-API adapter.

For targets that expose an agent via a plain HTTP endpoint rather than
MCP — the common pattern for custom production deployments (FastAPI
``/chat`` or ``/message`` with JSON bodies, internal OpenAPI services,
etc.).

The adapter is deliberately thin: callers supply the endpoint path, HTTP
method, header template, and a ``message_key`` that names the JSON field
the agent reads input from. Attack agents in Phase 1+ that need more
structure can subclass and override ``_shape_payload``.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


class HTTPAgentAdapter(BaseAdapter):
    """
    Talks to a plain HTTP agent API.

    Example:

        async with HTTPAgentAdapter(
            base_url="https://api.example.com",
            chat_path="/v1/chat",
            auth_header={"Authorization": "Bearer XYZ"},
            message_key="input",
        ) as h:
            obs = await h.interact(Request(surface="chat",
                                           payload="hello"))
    """

    DEFAULT_SURFACES = ("chat",)

    def __init__(
        self,
        *,
        base_url:       str,
        chat_path:      str = "/chat",
        method:         str = "POST",
        auth_header:    Optional[dict] = None,
        message_key:    str = "message",
        response_key:   Optional[str] = None,     # None → whole body
        connect_timeout: float = 10.0,
        request_timeout: float = 30.0,
        verify_tls:     bool = True,
    ) -> None:
        super().__init__(
            target_id=f"{base_url.rstrip('/')}{chat_path}",
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self.base_url     = base_url.rstrip("/")
        self.chat_path    = chat_path
        self.method       = method.upper()
        self.auth_header  = dict(auth_header or {})
        self.message_key  = message_key
        self.response_key = response_key
        self.verify_tls   = verify_tls
        self._client: Optional[httpx.AsyncClient] = None

    # ── Transport ─────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self.request_timeout,
            verify=self.verify_tls,
            headers=self.auth_header,
        )
        # Sanity ping: HEAD the chat path. Non-fatal if the server doesn't
        # support HEAD — we just want to prove TCP reachability here.
        try:
            await self._client.request(
                "HEAD", self.base_url + self.chat_path,
                timeout=self.connect_timeout,
            )
        except httpx.RequestError as e:
            await self._client.aclose()
            self._client = None
            raise AdapterError(f"HTTPAgentAdapter: {e}") from e

    async def _disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    # ── Enumeration ───────────────────────────────────────────────────────

    async def _enumerate(self) -> list[Surface]:
        return [
            Surface(
                kind="chat",
                name="chat",
                description=f"{self.method} {self.base_url}{self.chat_path}",
                meta={"message_key": self.message_key,
                      "response_key": self.response_key},
            )
        ]

    # ── Interaction ───────────────────────────────────────────────────────

    async def _interact(self, request: Request) -> AdapterObservation:
        if self._client is None:
            raise AdapterError("HTTPAgentAdapter._client is None")

        url = self.base_url + self.chat_path
        body = self._shape_payload(request)
        t0 = time.monotonic()
        try:
            resp = await self._client.request(self.method, url, json=body)
        except httpx.RequestError as e:
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="error",
                                  body=f"{type(e).__name__}: {e}",
                                  elapsed_ms=int((time.monotonic() - t0) * 1000)),
            )

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        try:
            parsed = resp.json()
        except (json.JSONDecodeError, ValueError):
            parsed = resp.text

        extracted = parsed
        if self.response_key and isinstance(parsed, dict):
            extracted = parsed.get(self.response_key, parsed)

        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(
                status=("ok" if resp.is_success else "error"),
                body=extracted,
                headers=dict(resp.headers),
                elapsed_ms=elapsed_ms,
                raw=parsed,
            ),
        )

    # ── Extension point ──────────────────────────────────────────────────

    def _shape_payload(self, request: Request) -> dict:
        """Default: put the payload under ``message_key``. Override as needed."""
        if isinstance(request.payload, dict):
            return request.payload
        return {self.message_key: request.payload}
