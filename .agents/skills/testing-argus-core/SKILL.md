# Testing ARGUS Core Detection Engine

## Overview
ARGUS Core detection engine includes the transport layer (prober, session), attack agents, and evaluation pillars (ResponseDivergence, DataCategoryMatcher, CanaryPropagator). This skill covers how to test changes to these components.

## Devin Secrets Needed
- `OPENAI_API_KEY` — needed only if testing BehaviorEvaluator (LLM-based evaluation). Not needed for transport layer tests.

## Quick Start
```bash
# Activate venv
source .venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run specific test suites
python -m pytest tests/test_phase_a_transport.py -v   # Transport layer (T1/T2/T5/T6)
python -m pytest tests/test_conductor.py -v            # ConversationSession + ResponseMatcher
python -m pytest tests/test_core_detection_harness.py -v  # Core detection pillars
```

## Transport Layer Testing

### Key Architecture
- **Prober** (`src/argus/survey/prober.py`): Discovers endpoints via HTTP probing. `EndpointProber.probe_all()` probes a seed set of paths + autonomous discovery from response bodies.
- **Session** (`src/argus/conductor/session.py`): Stateful multi-turn HTTP transport. `ConversationSession.turn()` executes requests and applies filters.
- **Agents** (`src/argus/agents/*.py`): Attack agents that use session turns to probe targets.

### Testing with Custom HTTP Servers
The prober and session make real HTTP requests. To test transport features (HTML filtering, SSE parsing, etc.), spin up a `http.server.HTTPServer` with custom handlers:

```python
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            # Return HTML SPA shell (T1 should filter this)
            body = b'<!DOCTYPE html><html><body></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

server = HTTPServer(("127.0.0.1", 18765), TestHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()
```

### EndpointProber API
- Constructor: `EndpointProber(base_url=url)` — NO `extra_paths` parameter
- The prober always probes `/` first, then a hardcoded seed set from `_PROBE_PATHS`
- It also does autonomous discovery from response bodies
- To test specific paths, set up your test server to serve them, and the prober will find them through its seed set or discovery

### Key Transport Layer Functions
- `_is_html_catchall(content_type, body)` — detects SPA shells
- `is_ai_response(content_type, body)` — True for JSON/SSE/text, False for HTML/binary
- `_parse_sse_to_text(raw)` — reassembles SSE `data:` frames into text
- `build_body_for_format(payload, fmt)` — constructs openai/prompt/input/message bodies

### Critical Gotchas
1. **TurnResult.ok() checks error field**: `ok()` returns False when `error is not None`, even for HTTP 200. This is how T1 HTML filtering works — HTML 200s get `error="html_response"` and `ok()=False`.
2. **Circular import avoidance**: `session.py` imports from `prober.py` inside function bodies to avoid circular imports at module load time.
3. **T6 format not fully wired**: `_fire_via_agent_endpoint()` reads `self._endpoint_format` via `getattr` (defaults to `"message"`). The orchestrator→agent propagation is Phase B scope.
4. **Pre-existing test failure**: `test_identity_spoof_detects_baseline_403_to_spoofed_200` may fail on Python 3.11 — this is unrelated to transport layer changes.

## Mock Target Testing
ARGUS includes a built-in mock vulnerable AI target:
```bash
# Start mock target (returns JSON, not HTML/SSE)
argus test-target start --host 127.0.0.1 --port 9999

# Scan against it
ARGUS_WEB_ALLOW_PRIVATE=1 argus scan mock-target --agent-endpoint http://localhost:9999/chat
```
Note: The mock target returns JSON only — it won't exercise T1 (HTML filter) or T2 (SSE parser). Use a custom HTTP server for those.

## Lint & Format
```bash
ruff check src/ tests/
ruff format --check src/ tests/
# Auto-fix formatting:
ruff format src/ tests/
```
