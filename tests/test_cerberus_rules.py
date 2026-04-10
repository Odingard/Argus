"""Tests for CERBERUS detection rule generation."""

from argus.models.findings import (
    AttackChainStep,
    CerberusRule,
    Finding,
    FindingSeverity,
    OWASPAgenticCategory,
    ReproductionStep,
)
from argus.reporting.cerberus_rules import CerberusRuleGenerator


def _make_finding(
    agent_type: str = "prompt_injection_hunter",
    technique: str = "role_hijack",
    target_surface: str = "user_input",
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    owasp: OWASPAgenticCategory | None = OWASPAgenticCategory.PROMPT_INJECTION,
    attack_chain: list[AttackChainStep] | None = None,
    title: str = "Test finding",
    description: str = "Test description",
) -> Finding:
    """Helper to build a minimal Finding for testing."""
    return Finding(
        agent_type=agent_type,
        agent_instance_id="test-inst-001",
        scan_id="scan-test-001",
        title=title,
        description=description,
        severity=severity,
        target_surface=target_surface,
        technique=technique,
        attack_chain=attack_chain or [],
        reproduction_steps=[
            ReproductionStep(
                step_number=1,
                action="Send payload",
                expected_result="Rejected",
                actual_result="Accepted",
            )
        ],
        owasp_agentic=owasp,
    )


# ---------- CerberusRule model tests ----------


def test_cerberus_rule_creation():
    rule = CerberusRule(
        rule_id="CERB-PI-001",
        title="Detect prompt injection via role hijack",
        description="Monitors for role hijack injection patterns",
        severity="CRITICAL",
        agent_source="prompt_injection_hunter",
        detection_logic="Monitor user inputs for role override phrases",
        indicators=["Role override phrases", "System prompt extraction"],
        owasp_mapping="AA01:2025 — Agentic Prompt Injection",
        finding_id="finding-001",
        recommended_action="Block the input and alert security team",
    )
    assert rule.rule_id == "CERB-PI-001"
    assert rule.severity == "CRITICAL"
    assert len(rule.indicators) == 2
    assert rule.finding_id == "finding-001"


def test_cerberus_rule_defaults():
    rule = CerberusRule(
        rule_id="CERB-GN-001",
        title="Generic rule",
        description="A rule",
        severity="LOW",
        agent_source="unknown_agent",
        detection_logic="Monitor something",
        finding_id="finding-002",
    )
    assert rule.indicators == []
    assert rule.owasp_mapping == ""
    assert rule.recommended_action == ""


def test_cerberus_rule_serialization():
    rule = CerberusRule(
        rule_id="CERB-TP-001",
        title="Detect tool poisoning",
        description="Monitors tool descriptions for hidden instructions",
        severity="HIGH",
        agent_source="tool_poisoning",
        detection_logic="Scan tool metadata",
        indicators=["Hidden Unicode characters"],
        owasp_mapping="AA02:2025 — Tool Misuse and Manipulation",
        finding_id="finding-003",
        recommended_action="Quarantine affected tool",
    )
    data = rule.model_dump()
    assert data["rule_id"] == "CERB-TP-001"
    assert data["severity"] == "HIGH"
    assert "Hidden Unicode characters" in data["indicators"]

    # Round-trip
    rebuilt = CerberusRule.model_validate(data)
    assert rebuilt.rule_id == rule.rule_id
    assert rebuilt.indicators == rule.indicators


# ---------- CerberusRuleGenerator tests ----------


def test_generate_rules_empty():
    gen = CerberusRuleGenerator()
    rules = gen.generate_rules([])
    assert rules == []


def test_generate_single_finding():
    gen = CerberusRuleGenerator()
    finding = _make_finding()
    rules = gen.generate_rules([finding])

    assert len(rules) == 1
    rule = rules[0]
    assert rule.rule_id == "CERB-PI-001"
    assert rule.severity == "CRITICAL"
    assert rule.agent_source == "prompt_injection_hunter"
    assert rule.finding_id == finding.id
    assert "Detect" in rule.title
    assert rule.owasp_mapping == OWASPAgenticCategory.PROMPT_INJECTION.value


def test_generate_rules_all_agent_types():
    """Every agent type should produce at least one rule."""
    gen = CerberusRuleGenerator()
    agent_types = [
        ("prompt_injection_hunter", OWASPAgenticCategory.PROMPT_INJECTION),
        ("tool_poisoning", OWASPAgenticCategory.TOOL_MISUSE),
        ("supply_chain", OWASPAgenticCategory.SUPPLY_CHAIN),
        ("memory_poisoning", OWASPAgenticCategory.MEMORY_POISONING),
        ("identity_spoof", OWASPAgenticCategory.IDENTITY_SPOOFING),
        ("context_window", OWASPAgenticCategory.MEMORY_POISONING),
        ("cross_agent_exfiltration", OWASPAgenticCategory.CROSS_AGENT_EXFIL),
        ("privilege_escalation", OWASPAgenticCategory.PRIVILEGE_ESCALATION),
        ("race_condition", OWASPAgenticCategory.RACE_CONDITIONS),
        ("model_extraction", OWASPAgenticCategory.MODEL_EXTRACTION),
    ]
    findings = [_make_finding(agent_type=at, owasp=owasp) for at, owasp in agent_types]
    rules = gen.generate_rules(findings)
    assert len(rules) >= len(agent_types)

    # Check that each agent produced rules
    agents_with_rules = {r.agent_source for r in rules}
    for at, _ in agent_types:
        assert at in agents_with_rules


def test_generate_rules_multi_step_chain():
    """A finding with a multi-step attack chain should produce an extra rule."""
    gen = CerberusRuleGenerator()
    chain = [
        AttackChainStep(
            step_number=1,
            agent_type="prompt_injection_hunter",
            technique="indirect_injection",
            description="Inject via tool output",
            target_surface="tool_output",
        ),
        AttackChainStep(
            step_number=2,
            agent_type="prompt_injection_hunter",
            technique="role_hijack",
            description="Override agent role",
            target_surface="user_input",
        ),
    ]
    finding = _make_finding(attack_chain=chain)
    rules = gen.generate_rules([finding])

    # Should get primary + chain rule
    assert len(rules) == 2
    chain_rule = rules[1]
    assert "attack chain" in chain_rule.title.lower()
    assert len(chain_rule.indicators) == 2
    assert "indirect_injection" in chain_rule.detection_logic
    assert "role_hijack" in chain_rule.detection_logic


def test_rule_id_sequential():
    """Rule IDs should increment sequentially per agent prefix."""
    gen = CerberusRuleGenerator()
    findings = [_make_finding() for _ in range(3)]
    rules = gen.generate_rules(findings)

    assert rules[0].rule_id == "CERB-PI-001"
    assert rules[1].rule_id == "CERB-PI-002"
    assert rules[2].rule_id == "CERB-PI-003"


def test_rule_id_different_agents():
    """Different agents get different prefixes."""
    gen = CerberusRuleGenerator()
    findings = [
        _make_finding(agent_type="prompt_injection_hunter"),
        _make_finding(agent_type="tool_poisoning"),
        _make_finding(agent_type="supply_chain"),
    ]
    rules = gen.generate_rules(findings)

    assert rules[0].rule_id == "CERB-PI-001"
    assert rules[1].rule_id == "CERB-TP-001"
    assert rules[2].rule_id == "CERB-SC-001"


def test_unknown_agent_type_gets_generic_prefix():
    """An unknown agent type should get the GN (generic) prefix."""
    gen = CerberusRuleGenerator()
    finding = _make_finding(agent_type="totally_unknown_agent", owasp=None)
    rules = gen.generate_rules([finding])

    assert len(rules) == 1
    assert rules[0].rule_id == "CERB-GN-001"
    assert "totally_unknown_agent" in rules[0].agent_source


def test_finding_without_owasp():
    """Findings without OWASP mapping should still generate rules."""
    gen = CerberusRuleGenerator()
    finding = _make_finding(owasp=None)
    rules = gen.generate_rules([finding])

    assert len(rules) == 1
    assert rules[0].owasp_mapping == ""


def test_indicators_include_technique_and_surface():
    """Generated indicators should include the finding's technique and surface."""
    gen = CerberusRuleGenerator()
    finding = _make_finding(technique="role_hijack", target_surface="user_input")
    rules = gen.generate_rules([finding])

    indicator_text = " ".join(rules[0].indicators)
    assert "role_hijack" in indicator_text
    assert "user_input" in indicator_text


# ---------- export_ruleset tests ----------


def test_export_ruleset_empty():
    gen = CerberusRuleGenerator()
    ruleset = gen.export_ruleset([])
    assert ruleset["total_rules"] == 0
    assert ruleset["rules"] == []
    assert ruleset["generator"] == "ARGUS-CERBERUS-Bridge"
    assert ruleset["ruleset_version"] == "1.0.0"


def test_export_ruleset_structure():
    gen = CerberusRuleGenerator()
    findings = [
        _make_finding(agent_type="prompt_injection_hunter", severity=FindingSeverity.CRITICAL),
        _make_finding(agent_type="tool_poisoning", severity=FindingSeverity.HIGH),
    ]
    rules = gen.generate_rules(findings)
    ruleset = gen.export_ruleset(rules)

    assert ruleset["total_rules"] == 2
    assert ruleset["severity_summary"]["CRITICAL"] == 1
    assert ruleset["severity_summary"]["HIGH"] == 1
    assert ruleset["agent_summary"]["prompt_injection_hunter"] == 1
    assert ruleset["agent_summary"]["tool_poisoning"] == 1
    assert len(ruleset["rules"]) == 2

    # Rules should be dicts (JSON-serializable)
    for r in ruleset["rules"]:
        assert isinstance(r, dict)
        assert "rule_id" in r
        assert "indicators" in r


def test_export_ruleset_severity_aggregation():
    gen = CerberusRuleGenerator()
    findings = [
        _make_finding(severity=FindingSeverity.CRITICAL),
        _make_finding(severity=FindingSeverity.CRITICAL),
        _make_finding(severity=FindingSeverity.LOW),
    ]
    rules = gen.generate_rules(findings)
    ruleset = gen.export_ruleset(rules)

    assert ruleset["severity_summary"]["CRITICAL"] == 2
    assert ruleset["severity_summary"]["LOW"] == 1
