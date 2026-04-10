# ARGUS — Autonomous AI Red Team Platform

**Odingard Security · Six Sense Enterprise Services**

ARGUS is an autonomous AI red team platform that deploys a swarm of specialized offensive agents simultaneously against AI systems, MCP servers, and multi-agent workflows. Every agent attacks a different AI-specific attack domain in parallel. A Correlation Agent chains individual findings into multi-step attack paths. Every finding is validated with proof of exploitation before it is surfaced.

> *"Every organization deploying AI agents into production is asking the same question their security team cannot answer: 'Has this been red-teamed?' ARGUS answers that question autonomously, at machine speed, before the agent touches production data."*

---

## The Problem

Traditional security testing tools cannot test AI agent vulnerabilities. They were built for a different attack surface. A SQL injection scanner does not know what tool poisoning is. A network vulnerability scanner cannot detect cross-agent exfiltration.

**ARGUS tests the layer above** — the AI systems, agent workflows, and tool connections that sit on top of traditional infrastructure and are becoming the primary attack surface in the enterprise.

---

## The 10 Attack Agents

| # | Agent | Primary Attack Surface |
|---|-------|----------------------|
| 1 | **Prompt Injection Hunter** | All input surfaces — system prompt, user input, tool descriptions, memory, retrieved context |
| 2 | **Tool Poisoning Agent** | MCP tool definitions and metadata |
| 3 | **Memory Poisoning Agent** | Agent persistent memory and session state |
| 4 | **Identity Spoof Agent** | Agent-to-agent authentication channels |
| 5 | **Context Window Agent** | Multi-turn conversation state |
| 6 | **Cross-Agent Exfiltration Agent** | Multi-agent data flow boundaries |
| 7 | **Privilege Escalation Agent** | Tool call chains and permission boundaries |
| 8 | **Race Condition Agent** | Parallel agent execution timing |
| 9 | **Supply Chain Agent** | External MCP servers and tool packages |
| 10 | **Model Extraction Agent** | Agent API and output interface |
| 11 | **Correlation Agent** | All agent outputs — chains findings into compound attack paths |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  ATTACK LAYER                         │
│                                                       │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐           │
│  │ PI  │ │ TP  │ │ MP  │ │ IS  │ │ CW  │           │
│  │Agent│ │Agent│ │Agent│ │Agent│ │Agent│   ...×10   │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘           │
│     │       │       │       │       │                │
│     └───────┴───────┴───┬───┴───────┘                │
│                         │                             │
│              ┌──────────▼──────────┐                  │
│              │    Signal Bus       │                  │
│              └──────────┬──────────┘                  │
├─────────────────────────┼────────────────────────────┤
│                CORRELATION LAYER                      │
│              ┌──────────▼──────────┐                  │
│              │  Correlation Agent  │                  │
│              │  Compound Chains    │                  │
│              └──────────┬──────────┘                  │
├─────────────────────────┼────────────────────────────┤
│                 REPORTING LAYER                       │
│              ┌──────────▼──────────┐                  │
│              │  Validation Engine  │                  │
│              │  Proof of Exploit   │                  │
│              └──────────┬──────────┘                  │
│              ┌──────────▼──────────┐                  │
│              │   Report Renderer   │                  │
│              │   OWASP Mapping     │                  │
│              └─────────────────────┘                  │
└──────────────────────────────────────────────────────┘
```

---

## Attack Surfaces Tested

1. **MCP Tool Chains** — Tool poisoning, confused deputy, cross-server shadowing, prompt injection in tool definitions
2. **Agent-to-Agent Communication** — Identity spoofing, orchestrator impersonation, trust chain exploitation
3. **Agent Memory and Context** — Cross-session memory poisoning, context window manipulation, memory summary attacks
4. **Multi-Agent Pipeline Logic** — Race conditions, privilege escalation through chaining, business logic abuse

---

## Quick Start

### Installation

```bash
git clone https://github.com/Odingard/Argus.git
cd Argus
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### CLI Commands

```bash
# Show system status and corpus stats
argus status

# Show the ARGUS banner
argus banner

# View attack corpus statistics
argus corpus

# Probe an MCP server for hidden content
argus probe https://mcp-server.example.com

# Run a full scan against a target
argus scan "My AI Agent" --mcp-url https://mcp.example.com --output report.json
```

### Run Tests

```bash
pytest tests/ -v
```

---

## Build Roadmap

| Phase | Duration | Milestone |
|-------|----------|-----------|
| **Phase 0 — Orchestration** | Weeks 1-3 | Parallel agent framework operational |
| **Phase 1 — First 3 Agents** | Weeks 4-8 | Shippable product — first customer test |
| **Phase 2 — Memory + Identity** | Weeks 9-13 | Compound attack chains surfacing |
| **Phase 3 — Pipeline Agents** | Weeks 14-18 | Full multi-agent pipeline testing |
| **Phase 4 — Complete Swarm** | Weeks 19-22 | 10 agents + CERBERUS integration |
| **Phase 5 — Pilots** | Weeks 23-28 | First paying enterprise customer |

**Current Status: Phase 0 Complete** — Orchestration framework, validation engine, MCP client, sandbox, attack corpus v0.1, and CLI operational.

---

## Portfolio Position

| Product | Function | When |
|---------|----------|------|
| **ARGUS** | Autonomous AI Red Team — finds vulnerabilities before deployment | Before production |
| **CERBERUS** | Runtime AI Agent Security — detects attacks in production | In production |
| **ALEC** | Autonomous Legal Evidence Chain — seals evidence after incidents | After incident |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Agent Orchestrator | Python — parallel agent coordination, signal bus, execution management |
| Attack Agent Runtime | LLM-powered reasoning (Claude / GPT) + tool access |
| Validation Engine | Deterministic Python — reproducible proof-of-exploitation |
| Attack Corpus | Custom AI-specific attack pattern database |
| MCP Client | Full MCP protocol client — attacker perspective |
| Reporting | Structured output with OWASP Agentic AI mapping |
| API | ASP.NET Core (Phase 4+) |

---

## Project Structure

```
src/argus/
├── __init__.py              # Package root
├── cli.py                   # CLI entry point
├── models/
│   ├── findings.py          # Finding schema, OWASP mappings, validation results
│   └── agents.py            # Agent config, results, target definitions
├── orchestrator/
│   ├── engine.py            # Core orchestrator — parallel agent deployment
│   └── signal_bus.py        # Inter-agent real-time signal bus
├── validation/
│   └── engine.py            # Deterministic proof-of-exploitation validation
├── mcp_client/
│   ├── client.py            # MCP attack client — tool enum, hidden content scan
│   └── models.py            # MCP protocol models
├── sandbox/
│   └── environment.py       # Isolated execution environments
├── corpus/
│   └── manager.py           # Attack pattern corpus — the moat
├── reporting/
│   └── renderer.py          # Report generation — JSON and summary
└── agents/                  # Attack agents (Phase 1+)
```

---

**CONFIDENTIAL — Odingard Security · Six Sense Enterprise Services · Houston, TX**
