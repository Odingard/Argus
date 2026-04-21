"""
argus/integrations/webhook.py — FastAPI MVP for webhook-triggered scans.

Two endpoints:

    POST /scan         {target, mode, client_id, swarm}  -> {scan_id}
    GET  /scan/{id}    -> {status, findings_summary, ars_max, report_path}
    GET  /health       -> {ok: true, version: ...}

Scans run in a background thread. The receiver is intentionally minimal
— one process, in-memory job table, no persistence. Appropriate for a
single-operator / single-engagement reverse-proxy setup. For fleet
deployments, back it with a queue (Redis / SQS) + worker pool.

Security note: this endpoint must be behind auth. The default is no
auth so the operator has to choose (bearer token, mTLS, IP allowlist).
"""
from __future__ import annotations

import os
import subprocess
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# We import FastAPI lazily so the rest of the package stays usable
# without the webserver dependency tree installed.
def build_app():
    try:
        from fastapi import FastAPI, HTTPException, Header
        from pydantic import BaseModel, Field
    except ImportError as e:
        raise RuntimeError(
            "FastAPI / pydantic not installed. "
            "Install with: pip install 'argus-redteam[webhook]' "
            "or `pip install fastapi pydantic 'uvicorn[standard]'`"
        ) from e

    app = FastAPI(
        title="ARGUS webhook",
        description="Trigger ARGUS scans via HTTP.",
        version=_argus_version(),
    )

    jobs: dict[str, "Job"] = {}
    jobs_lock = threading.Lock()
    required_token = os.environ.get("ARGUS_WEBHOOK_BEARER", "")

    class ScanRequest(BaseModel):
        target:     str
        mode:       str = Field("static", pattern="^(static|live|harness)$")
        client_id:  Optional[str] = None
        swarm:      bool = True
        output_dir: Optional[str] = None

    def _auth(authorization: Optional[str]) -> None:
        if not required_token:
            return
        if not authorization or authorization != f"Bearer {required_token}":
            raise HTTPException(status_code=401, detail="invalid or missing bearer")

    @app.get("/health")
    def health():
        return {"ok": True, "version": _argus_version(),
                "auth_required": bool(required_token)}

    @app.post("/scan")
    def scan(req: ScanRequest, authorization: Optional[str] = Header(None)):
        _auth(authorization)
        scan_id = uuid.uuid4().hex[:12]
        out_dir = req.output_dir or f"results/webhook/{scan_id}"
        job = Job(scan_id=scan_id, target=req.target, mode=req.mode,
                  output_dir=out_dir, status="queued",
                  started_at=datetime.utcnow().isoformat())
        with jobs_lock:
            jobs[scan_id] = job
        t = threading.Thread(
            target=_run_scan_job, args=(job, req), name=f"argus-scan-{scan_id}",
            daemon=True,
        )
        t.start()
        return {"scan_id": scan_id, "status": "queued", "output_dir": out_dir}

    @app.get("/scan/{scan_id}")
    def scan_status(scan_id: str, authorization: Optional[str] = Header(None)):
        _auth(authorization)
        with jobs_lock:
            job = jobs.get(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        return asdict(job)

    return app


def run_server(host: str = "0.0.0.0", port: int = 8787) -> None:
    try:
        import uvicorn
    except ImportError as e:
        raise RuntimeError(
            "uvicorn not installed. Install with: "
            "pip install 'argus-redteam[webhook]' "
            "or `pip install fastapi pydantic 'uvicorn[standard]'`"
        ) from e
    app = build_app()
    uvicorn.run(app, host=host, port=port)


# ── Internals ─────────────────────────────────────────────────────────────────

@dataclass
class Job:
    scan_id:        str
    target:         str
    mode:           str
    output_dir:     str
    status:         str
    started_at:     str
    finished_at:    str = ""
    findings_total: int = 0
    chains_total:   int = 0
    ars_max:        int = 0
    error:          str = ""


def _run_scan_job(job: Job, req) -> None:
    import json
    job.status = "running"
    Path(job.output_dir).mkdir(parents=True, exist_ok=True)

    cmd = ["argus", job.target, "-o", job.output_dir]
    if req.mode == "live":
        cmd.append("--live")
    if req.mode == "harness":
        cmd.append("--harness")
    if req.swarm and req.mode == "static":
        cmd.append("--swarm")

    env = dict(os.environ)
    if req.client_id:
        env["ARGUS_CLIENT_ID"] = req.client_id

    try:
        subprocess.check_call(cmd, env=env, timeout=60 * 60)   # 1h hard cap
    except subprocess.CalledProcessError as e:
        job.status = "failed"
        job.error = f"exit {e.returncode}"
        job.finished_at = datetime.utcnow().isoformat()
        return
    except subprocess.TimeoutExpired:
        job.status = "failed"
        job.error = "timeout: scan exceeded 1h"
        job.finished_at = datetime.utcnow().isoformat()
        return
    except FileNotFoundError:
        job.status = "failed"
        job.error = "argus CLI not on PATH"
        job.finished_at = datetime.utcnow().isoformat()
        return

    # Summarize.
    l5 = Path(job.output_dir) / "layer5.json"
    if l5.exists():
        try:
            data = json.loads(l5.read_text())
            job.chains_total = int(data.get("chain_count", 0) or 0)
            from argus.shared.ars import score_chain
            for c in data.get("chains", []):
                b = score_chain(
                    blast_radius=c.get("blast_radius", "MEDIUM"),
                    is_validated=bool(c.get("is_validated", False)),
                    combined_score=float(c.get("combined_score", 0.5)),
                    entry_point=c.get("entry_point", "unknown"),
                    preconditions_count=len(c.get("preconditions", []) or []),
                )
                job.ars_max = max(job.ars_max, b.score)
        except (json.JSONDecodeError, ImportError):
            pass

    l1 = Path(job.output_dir) / "layer1.json"
    if l1.exists():
        try:
            job.findings_total = int(
                json.loads(l1.read_text()).get("total_findings", 0) or 0
            )
        except json.JSONDecodeError:
            pass

    job.status = "complete"
    job.finished_at = datetime.utcnow().isoformat()


def _argus_version() -> str:
    try:
        from importlib.metadata import version
        return version("argus-redteam")
    except Exception:
        return "dev"
