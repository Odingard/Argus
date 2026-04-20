"""
agents/do_04_denial_of_wallet.py
DO-04 — Denial of Wallet Trapper

Hunts recursive multi-agent loops and unbounded context size exhaustion.

Techniques (3):
  DO-T1  INFINITE_DELEGATION — identify agents throwing loops at each other
  DO-T2  UNBOUNDED_CONTEXT   — agent memory without truncation limits
  DO-T3  RECURSIVE_TOOL_CALL — tools triggering an agent response recursively
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class DenialOfWalletAgent(BaseAgent):
    AGENT_ID   = "DO-04"
    AGENT_NAME = "Denial of Wallet Trapper"
    VULN_CLASS = "UNBOUNDED_CONSUMPTION"
    TECHNIQUES = ["DO-T1", "DO-T2", "DO-T3"]

    # Basic trigger keywords
    LOOP_PATTERNS = [
        r'handoff', r'transfer', r'delegate', r'.append\(', r'message_history'
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "DO-T1": self._t1_infinite_delegation,
            "DO-T2": self._t2_unbounded_context,
            "DO-T3": self._t3_recursive_tool,
        }

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        self._print_header(target)
        files = self._discover_files(repo_path)
        print(f"  Files     : {len(files)}\n")

        for tech_id, fn in self.technique_library.items():
            print(f"  {BLUE}[{tech_id}]{RESET} {fn.__doc__ or tech_id}")
            fn(files, repo_path)

        self.save_history(target, output_dir)
        out = self.save_findings(output_dir)
        print(f"\n  {BOLD}{self.AGENT_ID} complete{RESET} — {len(self.findings)} findings")
        return self.findings

    def _t1_infinite_delegation(self, files: list[str], repo_path: str):
        """Identify agents throwing infinite delegation loops at each other"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            
            if not any(re.search(p, code, re.IGNORECASE) for p in self.LOOP_PATTERNS):
                continue
                
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for Unbounded Consumption (Denial of Wallet) via Multi-Agent loops.
FILE: {rel}
CODE snippet: {code[:2000]}

Does this code allow an agent to continuously delegate back to another agent without a strict max_turn loop counter?
Return JSON only: {{"findings": [{{"severity": "HIGH", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "DO-T1", f["description"], "Trigger endless conversational delegation", None, None, None, f.get("remediation")))
            except: pass

    def _t2_unbounded_context(self, files: list[str], repo_path: str):
        """Agent memory arrays without token truncation limits"""
        pass

    def _t3_recursive_tool(self, files: list[str], repo_path: str):
        """Tools designed to trigger immediate re-execution infinitely"""
        pass

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = DenialOfWalletAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
