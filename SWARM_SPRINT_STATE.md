# Swarm Sprint — Resume State

**Last updated:** 2026-04-26 (before computer restart)

## What's done

### Day 1 — SwarmProbeEngine + concurrency/kill/results/types
- `src/argus/swarm/engine.py`, `concurrency.py`, `kill.py`, `results.py`, `types.py`
- 20 tests green

### Day 2 — WaveController
- `src/argus/swarm/waves.py` — fingerprint → saturation → exploitation, heat carryover
- 4 tests green

### Day 3a — SwarmAgentMixin abstraction
- `src/argus/swarm/agent_mixin.py` — defines `run_swarm()`, contract: `list_techniques()`, `list_surfaces()`, `swarm_config()`, `run_probe()`
- `swarm_mode_enabled()` reads `ARGUS_SWARM_MODE=1`
- 4 tests green

### Day 3b — Agent migrations to swarm contract
- **Migrated (2/11):** PI-01, EP-11
- **Legacy (9/11):** TP-02, ME-03, IS-04, CW-05, XE-06, PE-07, RC-08, SC-09, ME-10
- Both migrated agents have: `_run_async_swarm`, `swarm_mode_enabled()` gate, `swarm_config()`, `run_probe()`, `list_techniques()`. Legacy fall-through preserved.

### Day 3c — Simulated bench
- `benchmark/swarm_vs_legacy.py` — complete
- `results/swarm_smoke/bench_swarm_vs_legacy.json` — written
- **Result: 101.5x speedup, identical findings, 1.89x request reduction** on 3,120-pair simulation

## What's NOT done (next steps in order)

### Step A — Confirm baseline test suite is green
Run in terminal (NOT through DC — DC hangs on long pytest):
```
cd /Users/dre/dev/ARGUS && source .venv/bin/activate && \
  python -m pytest tests/ --tb=short -q -x \
    --ignore=argus-targets \
    --ignore=tests/test_real_mcp.py 2>&1 | tail -30
```
Paste tail to Claude. Need green baseline before further changes.

### Step B — Stage real-target bench script (TODO)
Write `scripts/bench_ep11_real_targets.sh` — runs EP-11 in legacy + swarm modes against:
- `npx://-y @nathanclevenger/node-code-sandbox-mcp@1.2.0`
- `npx://-y @cyanheads/git-mcp-server@2.1.4`

**CLI invocation form:** `argus <target> -o <out> --agents EP-11`
(positional target, NEVER `argus engage <target>`, NEVER `--engage`)

Script should:
- be idempotent (clean output dirs each run)
- capture wall-clock + finding count + irrefutable-proof count per run
- emit a summary table at the end
- support `ARGUS_BENCH_SKIP_LEGACY=1` and `ARGUS_BENCH_SKIP_SWARM=1`

### Step C — Three-part audit
1. **Migration audit** — for each of 9 legacy agents, locate inner sequential loop, estimate migration LOC. One-line-per-agent output.
2. **Dead code audit** — `vulture src/argus --min-confidence 80`, cross-reference agent registry / CLI / `__all__`. Flag-only, no deletes without sign-off.
3. **Test/script staleness** — find tests/scripts that reference symbols no longer exported.

### Step D — Migrate agents 02-10 to SwarmAgentMixin
Mechanical refactor following PI-01 / EP-11 template. ~50 LOC per agent. Keep legacy fall-through.

### Step E — Run real-target bench
Execute `scripts/bench_ep11_real_targets.sh`. Capture before/after for v0.5.0 release notes and LinkedIn post.

## Known issues
- Desktop Commander hangs on long-running operations (full pytest, broad recursive content searches). Use small targeted reads only via DC; run pytest in your own terminal.
- `tests/test_real_mcp.py` spawns real MCP servers via subprocess — exclude with `--ignore=tests/test_real_mcp.py` for unit-test runs.
- `pytest-timeout` is NOT installed. Either `pip install pytest-timeout` or just use `-x` to bail on first failure.

## Discarded ideas (do not revive)
- The "Raptor Swarm Engine" pitch's SwarmProbeEngine blueprint code (strictly worse than what shipped — fixed semaphore, no streaming, no kill, no exception isolation)
- T-MAP's prompt-mutation machinery (wrong domain — natural-language LLM jailbreaks vs. ARGUS's structured payload fuzzing)
- The "Day 4 dismantles 10+ MCP servers in <15s" roadmap claim (fantasy timeline)
- Marketing claims without sources: "asyncio outscales threading 2.4x", "Shadow AI 120% annually"

## Deferred to v0.6.0 (after wiring sprint)
- MAP-Elites archive over technique catalog, binned by `(vuln_class × payload_style × surface_type)`
- Tool Call Graph for inter-engagement learning
- Bayesian posterior update for `hot_surfaces()` scoring
- Cite T-MAP (arXiv 2603.22341) in VERDICT WEIGHT arXiv submission

## CLI rule (memorized)
ARGUS CLI is **always** `argus <target>` (positional). NEVER `argus engage <target>`, NEVER `--engage TARGET_URL`. Use short agent IDs (EP-11, PI-01) not long class names.
