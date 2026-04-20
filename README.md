<div align="center">
  <h1>ARGUS</h1>
  <p><b>Autonomous AI Red Team Substrate</b></p>
  <p><i>Odingard Security · Six Sense Enterprise Services</i></p>
</div>

---

## 1. The Positioning Statement
ARGUS does not compete with traditional pentesting tools. It does something they inherently cannot do — test the AI-specific attack surface that none of them were built to find. If you run XBOW or traditional SAST to test your raw infrastructure, you still need ARGUS to test the AI agents running on top of that infrastructure. They are complementary, not competing.

## 2. The Architecture (Open-Core)
ARGUS is uniquely built as an 11-Agent Swarm. 

This Open-Source core implements the basic scaffolding of the **Attack Layer**. It provides the entry-point logic to spawn short-lived, narrowly scoped agents designed to hunt AI logic flaws without accumulated bias or context collapse. 

```bash
pip install argus-core
```

```bash
# Map a target repository using the Core Swarm
argus https://github.com/target/repo -o results/
```

## 3. ⚠️ ARGUS Enterprise 
This OSS package contains the **Core Execution Engine**. It fundamentally lacks the Correlation Synthesis and Reporting Validation engines built into the proprietary SaaS product.

**The Full 11-Agent Swarm:**
ARGUS Enterprise deploys 10 simultaneous specialized agents (Prompt Injection Hunter, Tool Poisoner, Memory Poisoner, Identity Spoofer, etc.) and routes all intelligence to a single **Correlation Agent**. This Correlation Agent chains individual, seemingly benign findings into compound, multi-step zero-day attack paths. 

To access the complete Swarm logic and generate verifiable CVEs, please visit the Enterprise portal:
👉 **[ARGUS Enterprise Deployment](https://sixsenseenterprise.com)**
