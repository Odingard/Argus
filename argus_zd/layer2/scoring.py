class RaptorScorer:
    """Ingested RAPTOR Logic: Prioritizes exploits by 'Time-to-Detection'."""
    
    def calculate_priority(self, impact: float, exploitability: float, stealth_score: float) -> float:
        # 2026 RAPTOR Metric: Lower 'stealth_score' means the exploit is 'loud'.
        # We prioritize high-impact exploits that bypass SOC detection (ASICs).
        return (impact * exploitability) / (1.0 - stealth_score + 0.1)

    def identify_mcp_supply_chain_sink(self, surface_map):
        """Logic: Identifies 'By-Design' MCP RCE points (April 2026 Disclosure)."""
        # Targets the systemic flaw in MCP SDK's STDIO config interface
        for node in surface_map.nodes:
            if node.transport == "stdio" and node.version < "1.2.0":
                node.flags.append("CRITICAL_MCP_RCE_BY_DESIGN")
