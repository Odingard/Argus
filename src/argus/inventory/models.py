"""
argus/inventory/models.py — probe provider APIs for available models + quotas.

Providers covered:

  Anthropic   GET https://api.anthropic.com/v1/models
              + minimal 1-token completion to capture rate-limit headers
              (anthropic-ratelimit-requests-remaining, tokens-remaining,
               tokens-reset, input-tokens-limit, output-tokens-limit).

  OpenAI      GET https://api.openai.com/v1/models
              + minimal 1-token completion for x-ratelimit-* headers.

  Google      GET https://generativelanguage.googleapis.com/v1beta/models
  (Gemini /   Returns the full list with supported methods. No standard
   DeepMind)  quota endpoint here — Cloud Quotas API is separate and
              requires gcloud auth; we surface supported generation
              methods and link to the billing console in the renderer.

Runs each probe in parallel with short timeouts. If a key isn't set,
that provider is cleanly skipped (not reported as an error).
"""
from __future__ import annotations

import concurrent.futures as cf
import os
from dataclasses import dataclass, field
from typing import Optional

import requests

from dotenv import load_dotenv
load_dotenv(override=True)


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class ModelInfo:
    id:            str
    display_name:  str = ""
    context_window: Optional[int] = None
    supports:      list[str] = field(default_factory=list)


@dataclass
class ProviderInventory:
    provider:     str
    ok:           bool
    key_set:      bool
    key_fp:       str = ""        # 8-char sha of key for sanity, never the key itself
    models:       list[ModelInfo] = field(default_factory=list)
    rate_limits:  dict = field(default_factory=dict)
    error:        str = ""


# ── Utility ───────────────────────────────────────────────────────────────────

def _fp(key: str) -> str:
    """Short fingerprint of a key; never the key itself."""
    import hashlib
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


# ── Anthropic ─────────────────────────────────────────────────────────────────

def probe_anthropic(key: Optional[str]) -> ProviderInventory:
    inv = ProviderInventory(provider="anthropic", ok=False, key_set=bool(key))
    if not key:
        return inv
    inv.key_fp = _fp(key)

    try:
        r = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            },
            timeout=10,
        )
        r.raise_for_status()
        body = r.json()
        for m in body.get("data", []):
            inv.models.append(ModelInfo(
                id=m.get("id", ""),
                display_name=m.get("display_name", ""),
            ))
        inv.ok = True
    except requests.RequestException as e:
        inv.error = f"list models: {e}"
        return inv

    # Minimal completion call to harvest rate-limit headers.
    try:
        probe = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            },
            timeout=15,
        )
        rl = {k: v for k, v in probe.headers.items()
              if k.lower().startswith(("anthropic-ratelimit-", "retry-after"))}
        if rl:
            inv.rate_limits = rl
    except requests.RequestException as e:
        inv.error = (inv.error + "; probe: " if inv.error else "probe: ") + str(e)

    return inv


# ── OpenAI ────────────────────────────────────────────────────────────────────

def probe_openai(key: Optional[str]) -> ProviderInventory:
    inv = ProviderInventory(provider="openai", ok=False, key_set=bool(key))
    if not key:
        return inv
    inv.key_fp = _fp(key)

    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        r.raise_for_status()
        body = r.json()
        for m in body.get("data", []):
            inv.models.append(ModelInfo(
                id=m.get("id", ""),
                display_name=m.get("owned_by", ""),
            ))
        inv.ok = True
    except requests.RequestException as e:
        inv.error = f"list models: {e}"
        return inv

    # Minimal probe to capture x-ratelimit headers.
    try:
        probe = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "content-type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            },
            timeout=15,
        )
        rl = {k: v for k, v in probe.headers.items()
              if k.lower().startswith("x-ratelimit")}
        if rl:
            inv.rate_limits = rl
    except requests.RequestException as e:
        inv.error = (inv.error + "; probe: " if inv.error else "probe: ") + str(e)

    return inv


# ── Gemini (DeepMind via Google AI Studio) ────────────────────────────────────

def probe_gemini(key: Optional[str]) -> ProviderInventory:
    inv = ProviderInventory(provider="google-gemini", ok=False, key_set=bool(key))
    if not key:
        return inv
    inv.key_fp = _fp(key)

    try:
        r = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": key},
            timeout=10,
        )
        r.raise_for_status()
        body = r.json()
        for m in body.get("models", []):
            inv.models.append(ModelInfo(
                id=m.get("name", "").replace("models/", ""),
                display_name=m.get("displayName", ""),
                context_window=m.get("inputTokenLimit"),
                supports=list(m.get("supportedGenerationMethods", []) or []),
            ))
        inv.ok = True
    except requests.RequestException as e:
        inv.error = f"list models: {e}"
        return inv
    return inv


# ── Orchestration ─────────────────────────────────────────────────────────────

def inventory_all() -> list[ProviderInventory]:
    """Probe every provider we have a key for. Missing keys are skipped."""
    anth = os.environ.get("ANTHROPIC_API_KEY")
    oai  = os.environ.get("OPENAI_API_KEY")
    gem  = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    with cf.ThreadPoolExecutor(max_workers=3) as pool:
        futs = {
            pool.submit(probe_anthropic, anth): "anthropic",
            pool.submit(probe_openai,    oai):  "openai",
            pool.submit(probe_gemini,    gem):  "google-gemini",
        }
        out: list[ProviderInventory] = []
        for fut in cf.as_completed(futs):
            try:
                out.append(fut.result())
            except Exception as e:
                out.append(ProviderInventory(
                    provider=futs[fut], ok=False, key_set=True,
                    error=f"probe crashed: {type(e).__name__}: {e}",
                ))
    return sorted(out, key=lambda x: x.provider)


# ── Rendering ─────────────────────────────────────────────────────────────────

def render_inventory_text(results: list[ProviderInventory]) -> str:
    lines: list[str] = []
    for inv in results:
        header = f"[{inv.provider}]"
        if not inv.key_set:
            lines.append(f"{header} (no API key configured — skipped)")
            continue
        if not inv.ok:
            lines.append(f"{header} KEY={inv.key_fp}  FAILED: {inv.error}")
            continue

        lines.append(f"{header} KEY={inv.key_fp}  {len(inv.models)} model(s) available")

        # Summarize models. For providers that return 50+ models
        # (OpenAI especially) we group by family-prefix to keep output
        # readable.
        if inv.provider == "openai":
            families: dict[str, int] = {}
            for m in inv.models:
                fam = m.id.split("-")[0]
                families[fam] = families.get(fam, 0) + 1
            for fam, count in sorted(families.items(), key=lambda x: -x[1])[:12]:
                lines.append(f"    {fam:<20s} ({count})")
        else:
            for m in inv.models[:30]:
                label = m.id
                extras = []
                if m.context_window:
                    extras.append(f"ctx={m.context_window}")
                if m.supports:
                    extras.append("methods=" + ",".join(m.supports[:3]))
                tail = ("  " + "  ".join(extras)) if extras else ""
                lines.append(f"    {label}{tail}")
            if len(inv.models) > 30:
                lines.append(f"    ... {len(inv.models) - 30} more")

        if inv.rate_limits:
            lines.append("  rate_limits:")
            for k, v in sorted(inv.rate_limits.items()):
                lines.append(f"    {k}: {v}")
        else:
            lines.append("  rate_limits: (not returned by provider)")

        lines.append("")

    if not lines:
        lines.append("No providers configured (check ANTHROPIC_API_KEY / "
                     "OPENAI_API_KEY / GEMINI_API_KEY in .env).")
    return "\n".join(lines)
