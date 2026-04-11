# Testing ARGUS

## Running Tests

```bash
source .venv/bin/activate

# Full test suite
pytest tests/ -x -q

# Specific module
pytest tests/test_tiering.py -x -q

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

## Testing CLI Commands

ARGUS CLI is invoked via `argus` after activating the venv.

```bash
source .venv/bin/activate

# System status (shows tier, agents, corpus)
argus status

# Tier info and feature matrix
argus tier

# Switch to enterprise tier for testing
ARGUS_TIER=enterprise argus tier

# Test tier resolution precedence (ARGUS_TIER > ARGUS_LICENSE_KEY > default)
ARGUS_TIER=core ARGUS_LICENSE_KEY=test-key argus tier  # Should show Core

# Test ALEC export gate (should fail on Core tier)
argus alec-export test-target -o /tmp/test.json  # Exit code 1, "Enterprise Feature" error
```

## Testing Web API

```bash
# Start server with known token
ARGUS_WEB_TOKEN=test-token argus serve &
sleep 3

# Health check (no auth required)
curl http://localhost:8765/api/health

# Tier endpoint (auth required)
curl -H "Authorization: Bearer test-token" http://localhost:8765/api/system/tier

# Dashboard stats
curl -H "Authorization: Bearer test-token" http://localhost:8765/api/dashboard/stats

# Agents status
curl -H "Authorization: Bearer test-token" http://localhost:8765/api/agents/status
```

## Testing React Frontend

```bash
# Start backend first
ARGUS_WEB_TOKEN=test-token argus serve &

# Start frontend dev server
cd argus-frontend && VITE_API_URL=http://localhost:8765 npm run dev &

# Frontend at http://localhost:5173
# Login with token: test-token
```

## Auth

- Backend API uses Bearer token auth on all `/api/*` routes except `/api/health`
- Token is set via `ARGUS_WEB_TOKEN` env var or auto-generated on startup
- Create API keys: `argus auth create-key --name test --role admin`
- Frontend login accepts the same Bearer token

## Arena Testing

```bash
# Start all 12 Arena scenarios (ports 9001-9012)
PYTHONPATH=. argus arena start

# Check status
argus arena status

# Scan specific scenarios
ARGUS_WEB_ALLOW_PRIVATE=1 argus arena scan --only 1,2,3

# Score findings
argus arena score
```

## Environment Variables for Testing

| Variable | Purpose | Default |
|----------|---------|--------|
| `ARGUS_TIER` | Active tier: `core` or `enterprise` | `core` |
| `ARGUS_LICENSE_KEY` | Enterprise licence key (presence activates enterprise) | — |
| `ARGUS_WEB_TOKEN` | Bearer token for API auth | auto-generated |
| `ARGUS_WEB_ALLOW_PRIVATE` | Allow scanning private/localhost targets | — |
| `VITE_API_URL` | Backend URL for React frontend | `http://localhost:8765` |
