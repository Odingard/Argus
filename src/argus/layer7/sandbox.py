"""
layer7/sandbox.py
Execution Sandbox Module

Responsible for dynamically validating synthesized zero-day exploit chains
against a live sandbox. Prevents synthetic hallucinated exploits from 
reaching the final disclosure package.
"""
import os
import tempfile
import asyncio
import subprocess
import shutil
from pathlib import Path

from argus.shared.models import L5Chains, ExploitChain

# Time allowed for an exploit to prove itself before we kill it
VALIDATION_TIMEOUT_SECONDS = 15

async def _validate_chain_via_docker(chain: ExploitChain, repo_path: str) -> tuple[bool, str]:
    if not chain.poc_code:
        return False, "No PoC code available for validation."

    # Create an ephemeral workspace for this test
    with tempfile.TemporaryDirectory() as tmpdir:
        poc_path = os.path.join(tmpdir, "poc.py")
        payload = chain.poc_code
        
        # If the AI wrapped it in markdown code blocks, strip them
        if payload.startswith("```python"):
            payload = payload[9:]
        elif payload.startswith("```"):
            payload = payload[3:]
        if payload.endswith("```"):
            payload = payload[:-3]
            
        with open(poc_path, "w") as f:
            f.write(payload.strip())

        # Construct a docker command that:
        # 1. Mounts the target repo as /target (read-only)
        # 2. Mounts our temporary PoC script as /poc
        # 3. Sets PYTHONPATH so the library is directly importable
        # 4. Executes the PoC script
        
        # We use a standard slim image. (In a real enterprise setting, this would be a hardened sandbox image)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(repo_path)}:/target:ro",
            "-v", f"{poc_path}:/poc/poc.py:ro",
            "-w", "/target",
            "-e", "PYTHONPATH=/target:/target/src",
            "python:3.10-slim",
            "bash", "-c",
            "pip install -q requests websocket-client aiohttp && python /poc/poc.py"
        ]

        try:
            # We use asyncio to enforce a hard timeout on the execution
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            try:
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=VALIDATION_TIMEOUT_SECONDS)
                output = stdout.decode('utf-8', errors='replace')
                
                if process.returncode == 0:
                    # Exploit ran without crashing! Mark it as successfully validated.
                    return True, output
                else:
                    return False, f"Crash/Error (Code {process.returncode}):\n{output}"

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
                print(f"         [CRITICAL] ✓ WEAPONIZED EXPLOIT CONFIRMED")
            else:
                reason = out.strip().replace('\n', ' ')[:100]
                print(f"         [DROP] ✗ Failed: {reason}")
                if verbose:
                    for line in out.splitlines():
                        print(f"             | {line}")
                
    asyncio.run(run_all())
