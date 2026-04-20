# ARGUS Open-Core: Autonomous AI Red Team Substrate

**ARGUS** is a next-generation autonomous AI vulnerability discovery framework. Traditional static analysis (SAST) engines operate via regex and rule-sets; ARGUS utilizes orchestrating swarms of LLM agents to map codebase topologies and identify logical implementation flaws.

## Installation

```bash
pip install argus-core
```

## Quick Start

```bash
# Map a target repository using the Core Swarm
argus https://github.com/target/repo -o results/
```

## ⚠️ Enterprise Synthesis Capabilities

This OSS package contains the **Core Mapping Engine** (Layers 1 & 2) and baseline agents (`PH-11`, `LM-13`). 

**Note on Zero-Day Generation:**
Weaponizing these structural maps into fully synthesized CVE Exploit Chains requires the deep-execution logic of ARGUS Enterprise. Layers 3-6 (Semantic Fuzzing, Deviation Detection, and Multi-Agent Synthesis) and the elite Apex Agents (`VD-09`, `EA-12`, `DO-04`) are restricted to the proprietary SaaS deployment.

To access the massive compute capability of the complete Swarm and the accompanying WebSockets Dashboard, please visit the Enterprise portal:
👉 **[ARGUS Enterprise Deployment](https://sixsenseenterprise.com)**

## Legal & Scope
ARGUS Core is an offensive research tool designed for authorized auditing. See `SECURITY.md` for disclosure protocols.
