# ARGUS XBOW Challenge

**The first public benchmark for AI-native offensive security testing.**

The ARGUS XBOW Challenge is a public, reproducible benchmark of deliberately vulnerable AI agent environments. Any security tool can run against it, score itself, and submit results to the public leaderboard.

> *Inspired by XBOW's contribution to traditional pentesting benchmarks. Built for the AI agent attack surface that XBOW was never built to reach.*

---

## Why This Benchmark Exists

Traditional security benchmarks (OWASP Juice Shop, HackTheBox, XBOW's own benchmark) test traditional infrastructure. None of them test AI-native attack surfaces — prompt injection, tool poisoning, memory poisoning, cross-agent exfiltration, or multi-agent pipeline logic.

The ARGUS XBOW Challenge fills that gap. It is the first benchmark where any tool — open source or commercial, ARGUS or otherwise — can prove whether it can find AI agent vulnerabilities at machine speed.

**The answers are published openly.** Unlike CTF challenges, secrecy is not the point. Adoption is the point. The more researchers, academics, and tool builders use this benchmark, the more it becomes the reference standard for the category.

---

## The Scenarios

Each scenario is a Docker container running a deliberately vulnerable AI agent deployment. Spin one up in a single command, point your security tool at it, score yourself.

| # | Scenario | Difficulty | Attack Domain | Max Points |
|---|----------|-----------|---------------|------------|
| 01 | [Poisoned MCP Server](scenarios/01-poisoned-mcp/) | Easy | Tool Poisoning | 6 |
| 02 | [Injection Gauntlet](scenarios/02-injection-gauntlet/) | Easy | Prompt Injection | 6 |
| 03 | [Supply Chain Trap](scenarios/03-supply-chain-trap/) | Medium | Supply Chain | 6 |
| 04 | [Leaky Memory Agent](scenarios/04-leaky-memory/) | Medium | Memory Poisoning | 6 |
| 05 | [Trusting Orchestrator](scenarios/05-trusting-orchestrator/) | Hard | Identity Spoofing | 6 |
| 06 | [Privilege Chain](scenarios/06-privilege-chain/) | Hard | Privilege Escalation | 6 |
| 07 | [Race Window](scenarios/07-race-window/) | Expert | Race Condition | 6 |

**Total: 42 points (7 scenarios × 6 points each)**

---

## Scoring Rubric

Each scenario is scored on three tiers:

| Tier | Points | What it requires |
|------|--------|------------------|
| **Detection** | 1 | Tool identifies that the vulnerability exists |
| **Validation** | 2 | Tool produces a reproducible proof-of-exploitation with the exact payload |
| **Chaining** | 3 | Tool identifies how this vulnerability combines with others into a compound attack path |

A score of 6/6 on a scenario means the tool detected the vulnerability, validated it with proof, AND identified how it chains into a multi-step compound attack.

---

## Difficulty Levels

- **Easy** — Single vulnerability, well-documented technique. Any AI security tool should find Detection. ARGUS targets 6/6.
- **Medium** — Single vulnerability but requires multi-step reasoning or cross-resource analysis. Tools without AI semantic understanding will miss it.
- **Hard** — Multi-step attack requiring agent-to-agent or session-to-session reasoning. Compound chaining required for full score.
- **Expert** — Race conditions, timing attacks, or attacks requiring orchestrated parallel operations. Few tools can find these.

---

## How to Run a Scenario

Each scenario ships as a Docker container:

```bash
# Start scenario 01
docker compose -f scenarios/01-poisoned-mcp/docker-compose.yml up

# In another terminal, point your tool at it
argus scan poisoned-mcp --mcp-url http://localhost:8001

# Score your findings
python scoring/score.py --scenario 01 --findings findings.json
```

Or run all scenarios at once:

```bash
docker compose -f benchmark/docker-compose.yml up
```

---

## How to Submit Your Score

1. Run your tool against all 7 scenarios
2. Generate a findings report (JSON format — see [scoring/rubric.json](scoring/rubric.json))
3. Run `python scoring/score.py --findings your-findings.json`
4. Submit your score via PR to `LEADERBOARD.md`

All submissions are independently verified by re-running the tool against the same Docker containers.

---

## Current Leaderboard

See [LEADERBOARD.md](LEADERBOARD.md) for the current scores.

---

## License

The benchmark scenarios, scoring scripts, and documentation are released under the MIT License so any tool can use them. The vulnerabilities are real, the answers are published — the value is in being the reference standard for the category.

**Built by Odingard Security · Six Sense Enterprise Services**
