# ARGUS Production Readiness — Phase A Inventory

**Date:** 2026-04-27 · **Scope:** ARGUS as the engagement-tool driving 4
upcoming red-team engagements. Per Directives 1, 2, 3.

This is the honest current state. No fixes in this document — fixes
follow in Phase B with explicit linkbacks to the items below.

---

## 1. Repo at a glance

- **41 subpackages** under `src/argus/`, ~40,000 LOC of production code.
- **Top-5 by size:** `agents/` (8997), `engagement/` (2993), `adapter/`
  (2654), `shared/` (2068), `swarm/` (1890).
- **Test gate (offline):** 798 pass · 44 skip · 1 xfail · 7 stale-fail
  (all 7 documented in `KNOWN_REDS.md`, source-drift, not regressions).
- **Deferred work markers:** 7 total in 40k LOC (all are legitimate
  `NotImplementedError` in abstract base classes — zero TODO/FIXME).
- **Branch:** `feat/resilient-llm-gateway` · **6 commits ahead of v0.4.0**.

---

## 2. legacy/ vs src/argus/ — verified

- `legacy/` (564KB, 7 directories) contains pre-2026-04-21 source-scanner
  code archived per the spec-reconciliation pivot.
- **Zero Python imports** from `legacy/` anywhere in `src/argus/` or
  `tests/`. Three references in `src/argus/cli.py` and `tests/`
  documentation strings only.
- **Verdict:** True archive. Recommended action: **keep as-is** —
  documents the 2026-04-21 reconciliation, doesn't ship to PyPI
  (`pyproject.toml` only packages `src/argus/`), doesn't slow tests,
  doesn't confuse imports.

---

## 3. PyPI alignment

| Package | Version | Role |
|---|---|---|
| `argus-core` | **0.7.0rc1** | Real package. Ships `src/argus/`. |
| `argus-redteam` | 0.4.1 | Compat shim. Pulls in `argus-core`. Marked deprecated. |

### Findings

**[F-PyPI-1] Public-PyPI listing vs engagement-tool positioning (Directive 2 conflict)**

The README and PyPI page position ARGUS as `pip install argus-core`
software for the public. Per Directive 2, ARGUS is OdinGard's
internal engagement tool — customers buy engagements, not software.
**This is your decision, not mine.** Three coherent options:

  - (a) **Pull from public PyPI.** Strictest read of Directive 2.
  - (b) **Keep on PyPI but reposition the README.** Reframe as
    "if you want to red-team your own AI deployment, here's the
    same tool we use" — keeps install-flow, restates engagement
    as the primary delivery.
  - (c) **Keep on PyPI as-is.** Accept the inconsistency for
    now, revisit when an engagement reveals an actual problem.

I recommend (b) — it preserves the option of customer-installed-product
later (Directive 2 explicitly leaves that door open) without the
costs of reversing a PyPI delisting.

**[F-PyPI-2] Version drift between pyproject.toml and git tags**

`pyproject.toml` says `0.7.0rc1`. Latest git tag visible in this branch
is `6167f85 feat: ARGUS v0.4.0`. Version bumps have happened in
`pyproject.toml` without corresponding git tags or release commits.
Resolve by tagging the next release-worthy commit and aligning the
version string to it.

**[F-PyPI-3] argus-redteam shim version range OK**

`argus-redteam==0.4.1` declares `argus-core>=0.5.0,<1.0`. Compatible
with current `0.7.0rc1`. No action needed.

---

## 4. Sandbox — where exploits actually run

### Where it lives

`src/argus/adapter/sandboxed_stdio.py` (213 LOC). Wraps subprocess
launches in `docker run` with strict hardening:

```
--rm --network none --read-only --cap-drop ALL
--security-opt no-new-privileges --user 65534:65534
--memory 512m --cpus 1.0 --pids-limit 64
--tmpfs /tmp:rw,size=64m,mode=1777
```

CLI: `--sandbox` flag plus `--sandbox-network` and `--sandbox-image`
overrides. CLI → `set_sandbox()` → `engagement/builtin.py` factory
returns `SandboxedStdioAdapter` instead of plain `StdioAdapter`.

**Coverage today:**
- npx-launched MCP servers: ✅ (`@modelcontextprotocol/server-filesystem` etc.)
- uvx-launched Python MCP servers: ✅
- `python my_server.py` MCP servers: ✅
- Any stdio JSON-RPC subprocess: ✅
- Multipurpose use as you described — tricking MCP tools, isolating
  hostile community servers — works today.

### [F-SANDBOX-1] Capability gap: in-process Python target adapters

The `SandboxedStdioAdapter` only wraps subprocess launchers. The
following adapter types run in-process today and **don't get sandbox
isolation:**

  - `RealCrewAIAdapter` — imports `crewai` package, runs in ARGUS process
  - `HttpAgent` — talks to HTTP target, no subprocess
  - `A2AAdapter` — agent-to-agent handoff, in-process
  - `GenericAgentAdapter` — fake-target labrat, in-process

For the CrewAI re-test you specified: today's `--sandbox` flag does
NOT isolate the CrewAI target. If a malicious CrewAI config uses
`tools=[some_dangerous_tool]`, that tool runs in ARGUS's process with
ARGUS's permissions.

**Impact for upcoming engagements:** if any of the 4 engagements
involve attacking a customer-supplied agent framework (CrewAI,
LangChain, Agno) AND the operator wants the same isolation guarantees
as the stdio path, **the sandbox needs to grow.**

**Resolution path** (Directive 1 universal-fit):

  - Generalize to `SandboxedSubprocessAdapter` taking any launcher
    (Python script, Node script, binary)
  - Spawn the in-process target as a sandboxed Python subprocess via
    a thin RPC bridge (stdin/stdout JSON, identical to MCP's pattern)
  - `RealCrewAIAdapter` becomes one consumer of this generalized
    adapter, no special case
  - Estimated cost: ~6-10 hours, depending on RPC bridge complexity

**This is real Phase B work.** Don't run the CrewAI re-test until
this is built — running an in-process CrewAI exploit re-creates
exactly the trust boundary that motivated the sandbox in the first
place.

---

## 5. Agents — completion inventory

11 MAAC agents. Per `SWARM_SPRINT_STATE.md`:

| Agent | Status | Swarm-migrated |
|---|---|---|
| PI-01 (prompt injection) | functional | ✅ |
| TP-02 (tool poisoning) | functional | ❌ legacy |
| ME-03 (memory poisoning) | functional | ❌ legacy |
| IS-04 (identity spoof) | functional, 1 xfail on a2a | ❌ legacy |
| CW-05 (context window) | functional | ❌ legacy |
| XE-06 (cross-agent exfil) | functional | ❌ legacy |
| PE-07 (privilege escalation) | functional | ❌ legacy |
| RC-08 (race condition) | functional | ❌ legacy |
| SC-09 (supply chain) | functional | ❌ legacy |
| ME-10 (model extraction) | functional | ❌ legacy |
| EP-11 (environment pivot) | functional | ✅ |

**[F-AGENTS-1] 9 of 11 agents not swarm-migrated**

Bench shows 101.5x speedup on swarm-migrated agents (per
`benchmark/swarm_vs_legacy.py`). For 4 upcoming engagements, **legacy
agents will run noticeably slower against the same target**. Real
engagement scope ~50 surfaces × 9 legacy agents × ~50 probes each =
~22,500 sequential probes vs ~220 swarm probes.

Migration is mechanical (the contract is defined in
`swarm/agent_mixin.py`), but it's 9 agents × ~30-60 min each = 5-9
hours of focused work. **Phase B priority decision needed.**

**[F-AGENTS-2] No 12th agent**

Earlier I had memory of "12 MAAC agents" — that's wrong. Roster is 11.
Either the 12th is on roadmap and unbuilt, or my memory was off.
Doesn't affect engagements but noting for accuracy.

---

## 6. Production-grade subsystem review

The bar I committed to:

1. No silent failures — errors surface with operator-actionable context
2. No infinite hangs — every external call has a timeout
3. Findings are reproducible from artifacts saved to disk
4. Operator can stop and resume an engagement
5. Each subsystem has at least one happy-path test
6. Plus: ready-to-run-against-the-4-upcoming-engagements (your bar)

### What I can confirm from this pass (verified)

- **(2) timeouts**: `argus.shared.client._LLM_TIMEOUT_S = 45s` enforced
  via threading on every LLM call. ✅
- **(2) timeouts** dynamic-mutator infinite-retry hang: fixed last
  session via offline-gate (commit `8c2f4d8`). ✅
- **(1) silent failures** judge unavailability: degrades to
  UNAVAILABLE verdict, doesn't crash, surfaces in logs. ✅
- **(5) tests exist** for: judge failover (40 tests), swarm engine
  (72 tests), corpus mutators, finding schema, contracts, harness.

### What I can NOT confirm from this pass (Phase B work)

- **(1) silent failures** in the 9 legacy agents — need per-agent
  audit of error paths
- **(2) timeouts** in adapter network calls (HTTP, A2A) — need audit
- **(3) reproducibility** from saved artifacts — need to actually
  re-execute a finding from a saved engagement and confirm
- **(4) stop/resume** — does `engagement/runner.py` support resuming
  a partial engagement, or only restart? Not yet verified.
- **(6) end-to-end against community target** — has not been run
  successfully through the sandbox since the 2026-04-18 hallucinated
  Bugcrowd submission. **The whole point of Phase B is changing this.**

---

## 7. Suspicious-low-import subpackages — Phase B audit list

Subpackages with very low import counts from elsewhere in the codebase
need closer review for "dead code or just underused?":

- `autodeploy/` (3 files, 1 ext-import) — investigate
- `integrations/` (3 files, 1 ext-import) — investigate
- `personas/` (1 file, 1 ext-import) — investigate
- `r2r/` (4 files, 2 ext-imports) — investigate
- `audit/` (2 files, 2 ext-imports) — investigate

Total: 13 files. Phase B will verify each is alive or dead and act.

---

## 8. CLI surface

33 long flags (`--engage`, `--demo`, `--report`, `--sandbox`, etc.).
**Zero short-form aliases** beyond `-o` (`--output`) and `-h` (help).

### [F-CLI-1] Add short-form aliases for high-frequency flags

Operator-typed-from-memory flags during engagement runs benefit from
short forms:

  - `-e` / `--engage`
  - `-d` / `--demo`
  - `-r` / `--report`
  - `-a` / `--agents`
  - `-s` / `--sandbox`
  - `-l` / `--live`
  - `-v` / `--verbose`
  - `-V` / `--version`

Backwards-compatible — long forms keep working. ~15 min change.

### [F-CLI-2] Memorize: positional target, not subcommand

Per `SWARM_SPRINT_STATE.md`:
> `argus <target>` (positional target, NEVER `argus engage <target>`,
> NEVER `--engage`)

This is documented but `--engage` is still a flag. Either:
- (a) Remove `--engage` flag entirely (breaking)
- (b) Keep `--engage` as alias for positional, document positional as canonical
- (c) Status quo

I'd pick (b) — least friction, documented, no breaking change.

---

## 9. Ranked backlog for Phase B

In execution order, with cost estimates:

| # | Item | Cost | Blocks |
|---|------|------|--------|
| 1 | F-CLI-1 short aliases | 15 min | nothing — quality of life |
| 2 | F-PyPI-2 version/tag alignment | 10 min | release hygiene |
| 3 | F-SANDBOX-1 generalize sandbox to in-process Python | 6-10 hr | CrewAI re-test |
| 4 | Suspicious-subpackage audit (5 dirs, 13 files) | 1-2 hr | repo cleanliness |
| 5 | Production-grade audit (9 legacy agents error paths) | 4-6 hr | engagement reliability |
| 6 | Adapter timeout audit (HTTP, A2A) | 1 hr | engagement reliability |
| 7 | Reproducibility test (re-execute saved finding) | 1-2 hr | engagement claim |
| 8 | Stop/resume audit | 1 hr | engagement UX |
| 9 | F-AGENTS-1 swarm-migrate 9 legacy agents | 5-9 hr | engagement speed |
| 10 | CrewAI re-test through sandbox | 1-2 hr | proof-point — depends on #3 |
| 11 | F-PyPI-1 README repositioning | 30 min | Your decision required |

Total ballpark for production-readiness pass: **~25-35 hours** of
focused work. Distributable across multiple sessions.

---

## 10. What this document does NOT cover

- **The 4 upcoming engagements** — what targets, what scope, what
  agents matter most. Phase B priorities will sharpen once you tell
  me what those engagements look like (target type, size, what success
  looks like, what timeline).
- **UI roadmap** (Directive 3) — explicitly out of tonight's scope.
- **OdinGard portfolio products** (Cerberus, Wraith, Nemesis, Aegis,
  OdinForgeAI) — ARGUS is one tool in the portfolio; this doc is
  ARGUS-only.

---

*Phase A complete. Findings inventoried. Ready to discuss Phase B
priority and execute fixes you've signed off on.*
