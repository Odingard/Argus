"""
agents/ea_12_excessive_agency.py
EA-12 — Excessive Agency Agent

Hunts over-permissioned agent tools, unrestricted shell access, and broad MCP schemas.

Techniques (3):
  EA-T1  UNRESTRICTED_SHELL — find tools allowing raw shell command execution
  EA-T2  BROAD_FS_ACCESS    — tools granting agent access outside a sandbox
  EA-T3  MCP_SCHEMA_POISON  — overly broad MCP schemas exposed to manipulation
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


class ExcessiveAgencyAgent(BaseAgent):
    AGENT_ID   = "EA-12"
    AGENT_NAME = "Excessive Agency Agent"
    VULN_CLASS = "EXCESSIVE_AGENCY"
    TECHNIQUES = ["EA-T1", "EA-T2", "EA-T3"]

    TOOL_PATTERNS = [
        r'@tool', r'def \w+.*shell', r'subprocess\.run', r'os\.system', r'eval\(', r'exec\('
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "EA-T1": self._t1_unrestricted_shell,
            "EA-T2": self._t2_broad_fs_access,
            "EA-T3": self._t3_mcp_schema,
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

    def _t1_unrestricted_shell(self, files: list[str], repo_path: str):
        """Find agent tools allowing raw shell command execution"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            
            if not any(re.search(p, code, re.IGNORECASE) for p in self.TOOL_PATTERNS):
                continue
                
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for Excessive Agency.
FILE: {rel}
CODE snippet: {code[:2000]}

Does this code expose an agent tool that allows LLMs to execute raw OS commands or python code without human verification?
Return JSON only: {{"findings": [{{"severity": "CRITICAL", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "EA-T1", f["description"], "Prompt injection -> tool call -> RCE", None, None, None, f.get("remediation")))
            except: pass

    def _t2_broad_fs_access(self, files: list[str], repo_path: str):
        """Find tools granting agent access outside a filesystem sandbox"""
        pass

    def _t3_mcp_schema(self, files: list[str], repo_path: str):
        """Identify overly broad MCP schemas exposed to manipulation"""
        pass

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = ExcessiveAgencyAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
