# ARGUS XBOW Challenge — Public Leaderboard

Scores from all tools that have been validated against the ARGUS AI Agent Security Benchmark.

## Current Scores

| Rank | Tool | Version | Total Score | Phase 1 Score | Date |
|------|------|---------|-------------|---------------|------|
| 1 | **ARGUS** | 0.1.0 (Phase 1) | **18/42 (42.86%)** | **18/18 (100%)** | 2026-04-09 |

> **Phase 1 Score** measures performance on the 3 scenarios that ARGUS Phase 1 has agents for. The remaining scenarios require Phase 2+ agents.

## ARGUS Per-Scenario Breakdown

| Scenario | Difficulty | Detection | Validation | Chaining | Total |
|----------|-----------|-----------|------------|----------|-------|
| 01 — Poisoned MCP Server | Easy | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 02 — Injection Gauntlet | Easy | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 03 — Supply Chain Trap | Medium | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 04 — Leaky Memory Agent | Medium | — | — | — | 0/6 *(Phase 2 agent)* |
| 05 — Trusting Orchestrator | Hard | — | — | — | 0/6 *(Phase 2 agent)* |
| 06 — Privilege Chain | Hard | — | — | — | 0/6 *(Phase 3 agent)* |
| 07 — Race Window | Expert | — | — | — | 0/6 *(Phase 3 agent)* |

## Run Stats

- **Scan duration:** 0.7 seconds
- **Findings emitted:** 30 total, 27 validated (90%)
- **Agents deployed:** 3 in parallel (Prompt Injection Hunter, Tool Poisoning Agent, Supply Chain Agent)
- **Vulnerabilities detected per scenario:**
  - Scenario 01: 13 findings matched
  - Scenario 02: 29 findings matched
  - Scenario 03: 10 findings matched

## How to Reproduce

```bash
# Clone the repo
git clone https://github.com/Odingard/Argus.git
cd Argus

# Install ARGUS
pip install -e ".[dev]"

# Spin up the benchmark scenarios
docker compose -f benchmark/docker-compose.yml up -d

# Run the baseline
python benchmark/run_baseline.py
```

The score will be written to `benchmark/baseline-score.json` and printed to the console.

## How to Submit Your Score

See [README.md](README.md) for submission instructions. All scores are independently verified by re-running the tool against the same Docker containers.
