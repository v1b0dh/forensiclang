"""
CARVE Management Server
server/main.py

FastAPI application that:
  - Accepts agent WebSocket connections
  - Accepts authenticated REST API requests from the dashboard
  - Dispatches CARVE scripts to agents
  - Stores results and artifacts in SQLite (dev) / PostgreSQL (prod)

Run:
    uvicorn server.main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    Depends, HTTPException, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text

# ── Database setup ────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./carve.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("carve.server")

# ── FastAPI app ───────────────────────────────────────────────────
app = FastAPI(
    title="CARVE Management Server",
    version="1.0.0",
    description="CARVE Forensic Script Deployment & Artifact Management API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

from server.api.forensics import router as forensics_router
app.include_router(forensics_router)

# ── In-memory state ───────────────────────────────────────────────
connected_agents: dict[str, WebSocket]        = {}
job_queues:       dict[str, asyncio.Queue]    = {}
job_results:      dict[str, dict]             = {}

# ── Auth ─────────────────────────────────────────────────────────
security = HTTPBearer()
SECRET_TOKEN = os.environ.get("JOCKY_API_TOKEN", "dev-secret-change-me")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SECRET_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
        )
    return credentials.credentials


# ══════════════════════════════════════════════════════════════════
# Database helpers
# ══════════════════════════════════════════════════════════════════
def init_db():
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                script TEXT NOT NULL,
                targets TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                data TEXT,
                created_at TEXT NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                ts TEXT NOT NULL,
                source TEXT NOT NULL,
                event TEXT NOT NULL,
                details TEXT
            )
        """))
        conn.commit()

@app.on_event("startup")
async def startup():
    init_db()
    log.info("CARVE Management Server started — DB initialised")


def save_job(job_id: str, script: str, targets: list[str]):
    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO jobs (job_id, script, targets, status, created_at) "
            "VALUES (:jid, :script, :targets, 'queued', :ts)"
        ), {"jid": job_id, "script": script,
            "targets": json.dumps(targets),
            "ts": datetime.now(timezone.utc).isoformat()})
        conn.commit()

def save_artifacts(job_id: str, agent_id: str, artifacts: list[dict]):
    with engine.connect() as conn:
        for art in artifacts:
            conn.execute(text(
                "INSERT INTO artifacts (job_id, agent_id, name, size, data, created_at) "
                "VALUES (:jid, :aid, :name, :size, :data, :ts)"
            ), {"jid": job_id, "aid": agent_id,
                "name": art.get("name", "unknown"),
                "size": art.get("size", 0),
                "data": art.get("data", ""),
                "ts":   datetime.now(timezone.utc).isoformat()})
        conn.commit()

def get_artifacts_for_job(job_id: str) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT agent_id, name, size, created_at FROM artifacts WHERE job_id=:jid"
        ), {"jid": job_id}).fetchall()
    return [{"agent_id": r[0], "name": r[1], "size": r[2], "created_at": r[3]}
            for r in rows]


# ══════════════════════════════════════════════════════════════════
# WebSocket — Agent endpoint
# ══════════════════════════════════════════════════════════════════
@app.websocket("/agent/{agent_id}")
async def agent_endpoint(ws: WebSocket, agent_id: str):
    await ws.accept()
    connected_agents[agent_id] = ws
    job_queues[agent_id] = asyncio.Queue()
    log.info(f"Agent connected: {agent_id}")

    try:
        while True:
            # ── Push pending jobs ─────────────────────────────────
            try:
                job = job_queues[agent_id].get_nowait()
                await ws.send_text(json.dumps(job))
            except asyncio.QueueEmpty:
                pass

            # ── Receive results (1 s timeout to keep pushing jobs) ─
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=1.0)
                data = json.loads(raw)
                await _handle_agent_message(agent_id, data)
            except asyncio.TimeoutError:
                pass

    except WebSocketDisconnect:
        log.info(f"Agent disconnected: {agent_id}")
    finally:
        connected_agents.pop(agent_id, None)
        job_queues.pop(agent_id, None)


async def _handle_agent_message(agent_id: str, data: dict):
    msg_type = data.get("type")
    if msg_type == "script_result":
        job_id = data.get("job_id")
        job_results[job_id] = data
        artifacts = data.get("artifacts", [])
        if artifacts:
            save_artifacts(job_id, agent_id, artifacts)
        log.info(f"Result for job {job_id} from agent {agent_id}: {data.get('status')}")
    elif msg_type == "alive":
        log.debug(f"Heartbeat from {agent_id}")


# ══════════════════════════════════════════════════════════════════
# REST API — Job management
# ══════════════════════════════════════════════════════════════════
class JobRequest(BaseModel):
    script_code: str = Field(..., description="JOCKY script source code")
    targets: list[str] = Field(default_factory=list, description="Agent IDs to target")


@app.post("/api/jobs", summary="Deploy a JOCKY script to agents")
async def create_job(job: JobRequest, _=Depends(verify_token)):
    job_id = str(uuid.uuid4())
    save_job(job_id, job.script_code, job.targets)

    dispatched = []
    for agent_id in job.targets:
        if agent_id in job_queues:
            await job_queues[agent_id].put({
                "type":       "execute_script",
                "job_id":     job_id,
                "script":     job.script_code,
            })
            dispatched.append(agent_id)

    log.info(f"Job {job_id} dispatched to {dispatched}")
    return {
        "job_id":     job_id,
        "status":     "queued",
        "dispatched": dispatched,
        "missed":     [a for a in job.targets if a not in dispatched],
    }


@app.get("/api/jobs/{job_id}/status", summary="Poll job status")
async def job_status(job_id: str, _=Depends(verify_token)):
    result = job_results.get(job_id)
    if result:
        return {"job_id": job_id, "status": result.get("status"), "result": result}
    return {"job_id": job_id, "status": "pending"}


@app.get("/api/agents", summary="List connected agents")
async def list_agents(_=Depends(verify_token)):
    return {"agents": list(connected_agents.keys()), "count": len(connected_agents)}


@app.get("/api/artifacts/{job_id}", summary="Get artifacts for a job")
async def get_artifacts(job_id: str, _=Depends(verify_token)):
    arts = get_artifacts_for_job(job_id)
    return {"job_id": job_id, "artifacts": arts}


@app.get("/api/timeline/{host}", summary="Get timeline events for a host")
async def get_timeline(host: str, _=Depends(verify_token)):
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT ts, source, event, details FROM timeline_events "
            "WHERE host=:host ORDER BY ts"
        ), {"host": host}).fetchall()
    events = [{"ts": r[0], "source": r[1], "event": r[2], "details": r[3]}
              for r in rows]
    return {"host": host, "events": events}


# ── Health check (no auth) ────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "agents_connected": len(connected_agents),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
