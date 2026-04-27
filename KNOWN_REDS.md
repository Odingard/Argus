# Known Red Tests — Tracking

Tests marked `xfail` or known-red, deferred from the swarm sprint.
Each entry needs an owner, reason, and resolution path.

Run gate with `ARGUS_OFFLINE=1` to suppress live LLM mutator calls.

## Active

### IS-04 silent on a2a://labrat
- Test: tests/test_a2a_labrat_engagement.py::test_a2a_labrat_engagement_produces_is04_and_xe06_findings
- Status: pytest.mark.xfail(strict=False)
- Symptom: IS-04 fires 18 spoofs, 0 deltas; runtime tags "(silent — surface class absent or hardened)". XE-06 lands 40 findings on same target.
- Resolution: Re-evaluate after Step D (IS-04 swarm migration).

### Per-agent tests requiring ARGUS_JUDGE (~19 tests)
- Tests: tests/test_agent_{01,04,05,10}_*.py::*, plus test_agent_11_findings_have_full_provenance, test_agent_11_persists_findings, test_agent_11_imds_probe_lands_through_ssrf
- Status: Unmarked, fail in offline mode
- Symptom: "[AGENT] judge UNAVAILABLE (ARGUS_JUDGE not set or no provider key) — semantic findings skipped". Tests assert >=1 finding which never appears without the judge.
- Resolution: Either (a) add pytest.mark.requires_judge + skip-condition for offline, or (b) inject a fake judge fixture. Not blocking swarm sprint.

### Acceptance / e2e tests requiring runtime deps (~8 tests)
- Tests: test_phase1_acceptance, test_phase4_acceptance, test_pillar_oauth_supply_chain_acceptance, test_framework_labrats[autogen|langgraph|llamaindex|parlant|hermes]
- Status: Unmarked
- Symptom: Mix of judge unavailability and framework runtime adapters that need npx subprocesses.
- Resolution: Same as above — opt-in marker for full-fat runs.

### EP-11 family-D coverage
- Test: tests/test_agent_11_environment_pivot.py::test_agent_11_lands_on_oauth_supply_chain_pattern
- Status: Unmarked
- Symptom: EP-11 surgical-stops at 9 confirmed findings before family-D techniques (T9/T10) get probed. Test asserts at least one finding from each of 4 families.
- Resolution: Either disable surgical stop in this test or relax assertion to ">=3 of 4 families".

### Stale tests (pre-existing source drift)
- tests/test_dynamic_corpus.py::test_llm_mutator_bulk_creates_n_distinct_variants — stub matches "VARIANT INDEX (use as a phrasing seed): {i}" but actual _prompt() emits "SEED: {self.seed_index}". Update test stub.
- tests/test_sentry_mutators.py::test_sentry_mutators_not_in_default_bundle — crescendo was promoted into default_mutators(). Update test or move crescendo back to opt-in.
- tests/test_sentry_mutators.py::test_sentry_mutators_integrate_with_corpus — same root cause.
- tests/test_cerberus_alec_stubs.py::test_write_rules_persists_payload — not yet inspected.
- tests/test_report.py::test_render_html_from_dir_end_to_end — not yet inspected.
- tests/test_demo_generic_agent.py::test_demo_emits_full_artifact_package — not yet inspected.

## Resolved (this session)

### EP-11 _judge_findings signature regression
- Bug: def _judge_findings() had empty parameter list after a botched refactor. Body still referenced 9 kwargs the caller passes. Raised TypeError on every probe.
- Fix: Restored signature with self + 9 keyword-only params (technique_id, tech, surface, target_id, payload, sess, response_text, baseline, had_regex_hit).
- File: src/argus/agents/agent_11_environment_pivot.py:2042
- Recovered: ~8 tests across test_agent_11_*, test_generic_agent_pillar, test_demo_generic_agent.

### Dynamic mutator infinite-retry hang
- Bug: LLMMutator.apply() invoked _route_call() => live Gemini API. On network failure, Google's retry_target looped forever. With bulk(n=5) x hundreds of seeds, accumulated 30+ stuck CLOSE_WAIT sockets and deadlocked the test suite at ~8% completion.
- Fix: Added offline gate. When self.responder is None and ARGUS_OFFLINE=1, return seed text unchanged. Mock-responder tests are unaffected.
- File: src/argus/corpus_attacks/dynamic.py:80
- Recovered: 2 dynamic_corpus tests + suite no longer hangs.

## Required gate flags

All future test runs must include ARGUS_OFFLINE=1 and --timeout=120. Without ARGUS_OFFLINE=1, the dynamic mutator may attempt live Gemini calls. Without --timeout=120, a hung test can block the entire suite indefinitely.

Standard gate command:
    ARGUS_OFFLINE=1 python -m pytest tests/ --tb=short -q --timeout=120 --ignore=argus-targets --ignore=tests/test_real_mcp.py
