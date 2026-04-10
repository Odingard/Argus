# Changelog

All notable changes to ARGUS will be documented in this file.

## [0.1.0] — 2026-04-09

### Phase 0 — Orchestration Foundation

#### Added
- **Agent Orchestrator** (`src/argus/orchestrator/engine.py`) — Core engine that deploys N attack agents simultaneously at T=0, manages parallel execution with asyncio, handles timeouts, collects findings, and coordinates the full scan lifecycle.
- **Inter-Agent Signal Bus** (`src/argus/orchestrator/signal_bus.py`) — Async pub/sub bus enabling real-time communication between attack agents and the Correlation Agent. Supports targeted and broadcast signals.
- **Finding Schema** (`src/argus/models/findings.py`) — Complete data model for ARGUS findings including attack chains, reproduction steps, OWASP Agentic AI Top 10 mapping, OWASP LLM Top 10 mapping, validation results, and remediation guidance.
- **Agent Models** (`src/argus/models/agents.py`) — Configuration and result models for all 10 attack agent types plus Correlation Agent. Includes target configuration with MCP server support.
- **Validation Engine** (`src/argus/validation/engine.py`) — Deterministic proof-of-exploitation framework. Replays attacks N times and confirms reproducible behavior change. Technique-specific validators for each attack domain. Only validated findings ship.
- **MCP Attack Client** (`src/argus/mcp_client/client.py`) — Full MCP protocol client from the attacker's perspective. Connects via stdio or HTTP transports, enumerates tools, scans for hidden content (zero-width chars, HTML comments, instruction tags), and supports adversarial tool calling.
- **Agent Sandbox** (`src/argus/sandbox/environment.py`) — Isolated execution environments with resource limits (request count, rate, data volume), network controls (host allow/block lists), workspace isolation, and full audit logging.
- **Attack Corpus v0.1** (`src/argus/corpus/manager.py`) — Initial database of 15+ AI-specific attack patterns covering prompt injection (direct, indirect, encoded), tool poisoning (description, unicode, shadow), memory poisoning, identity spoofing, supply chain, cross-agent exfiltration, privilege escalation, and model extraction. Tracks effectiveness over time.
- **Report Renderer** (`src/argus/reporting/renderer.py`) — Generates JSON and human-readable summary reports with findings grouped by severity, compound attack paths, and OWASP mappings.
- **CLI** (`src/argus/cli.py`) — Command-line interface with `status`, `scan`, `corpus`, `probe`, and `banner` commands.
- **Test Suite** — 20 tests covering models, orchestrator (parallel execution, timeouts, signal bus), validation engine (replay, timeout, technique-specific), and corpus (seed, query, persistence).
- **CI/CD** — GitHub Actions pipeline with lint, test (Python 3.11-3.13), and build stages.
- **Docker** — Multi-stage Dockerfile (dev + production) and docker-compose for containerized development.
- **Developer Tooling** — Makefile, pre-commit hooks (ruff lint + format), .env.example, CLAUDE.md conventions.
