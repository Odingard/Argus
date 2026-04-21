"""
layer7/sandbox.py
Execution Sandbox Module

Dynamically validates synthesized exploit chains against a live sandbox.
Prevents hallucinated exploits from reaching the final disclosure package.

Validation contract:
    A chain is marked validated ONLY when the PoC, when run inside an
    isolated container with the target code mounted read-only, produces
    observable evidence that the exploit landed. Exit code 0 alone is not
    sufficient — a benign `print()` also exits 0. We require one of:
      - stdout/stderr contains a recognised proof marker (OOB callback ID,
        sensitive-file content shape, RCE evidence), or
      - the PoC explicitly emits the line ``ARGUS_POC_LANDED:<chain_id>``.
    Everything else is reported as unvalidated with the observed output
    for human triage.
"""
import os
import re
import tempfile
import asyncio
from pathlib import Path

from argus.shared.models import L5Chains, ExploitChain

VALIDATION_TIMEOUT_SECONDS = 15

# Evidence patterns that suggest a PoC actually touched the target.
# These are deliberately narrow — we would rather under-validate than
# falsely crown a print() statement as a "weaponised exploit".
_EVIDENCE_PATTERNS = [
    re.compile(r"ARGUS_POC_LANDED:\S+"),
    re.compile(r"root:[^:]*:0:0:"),                # /etc/passwd row
    re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*[:=]"),
    re.compile(r"sk-(?:ant-|proj-|svcacct-)[A-Za-z0-9_\-]{16,}"),
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+"),     # `id` output
]


def _has_evidence(output: str) -> bool:
    return any(p.search(output) for p in _EVIDENCE_PATTERNS)


async def _validate_chain_via_docker(chain: ExploitChain, repo_path: str) -> tuple[bool, str]:
    if not chain.poc_code:
        return False, "No PoC code available for validation."

    with tempfile.TemporaryDirectory() as tmpdir:
        poc_path = os.path.join(tmpdir, "poc.py")
        payload = chain.poc_code

        if payload.startswith("```python"):
            payload = payload[9:]
        elif payload.startswith("```"):
            payload = payload[3:]
        if payload.endswith("```"):
            payload = payload[:-3]

        with open(poc_path, "w") as f:
            f.write(payload.strip())

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(repo_path)}:/target:ro",
            "-v", f"{poc_path}:/poc/poc.py:ro",
            "-w", "/target",
            "-e", "PYTHONPATH=/target:/target/src",
            "python:3.10-slim",
            "bash", "-c",
            "pip install -q requests websocket-client aiohttp && python /poc/poc.py",
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(), timeout=VALIDATION_TIMEOUT_SECONDS
                )
                output = stdout.decode("utf-8", errors="replace")

                if process.returncode != 0:
                    return False, f"Crash/Error (Code {process.returncode}):\n{output}"

                if _has_evidence(output):
                    return True, output

                return False, (
                    "Exit code 0 but no exploit evidence in output. "
                    "PoC must emit an ARGUS_POC_LANDED:<id> marker or leak "
                    "recognisable sensitive data to be considered validated.\n"
                    f"Output:\n{output}"
                )

            except asyncio.TimeoutError:
                process.kill()
                return False, f"Validation Timeout ({VALIDATION_TIMEOUT_SECONDS}s): Exploit hung or failed to complete."

        except Exception as e:
            return False, f"Docker Execution Error: {str(e)}"

def validate_l5_chains(l5_chains: L5Chains, repo_path: str, verbose: bool = False) -> None:
    """
    Mutates the L5Chains objects in place, setting the is_validated flag
    by executing the PoCs in Docker.
    """
    print(f"\n[L7] Execution Sandbox Validation")
    print(f"     Target repo: {repo_path}")
    print(f"     Validating {len(l5_chains.chains)} chains...")

    # We run the async validations synchronously sequentially for clean logging
    async def run_all():
        for i, chain in enumerate(l5_chains.chains):
            if not chain.poc_code:
                if verbose:
                    print(f"  [{i+1}/{len(l5_chains.chains)}] {chain.chain_id} - SKIP (No PoC)")
                continue

            print(f"  [{i+1}/{len(l5_chains.chains)}] Executing {chain.chain_id} in Sandbox...")
            is_valid, out = await _validate_chain_via_docker(chain, repo_path)
            
            chain.is_validated = is_valid
            chain.validation_output = out[:1000] # store summary
            
            if is_valid:
                print(f"         ✓ Exploit evidence detected — chain validated")
            else:
                reason = out.strip().replace('\n', ' ')[:100]
                print(f"         ✗ Not validated: {reason}")
                if verbose:
                    for line in out.splitlines():
                        print(f"             | {line}")
                
    asyncio.run(run_all())
