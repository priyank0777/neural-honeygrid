import os
import time
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse

from backend.config import config, BASE_DIR
from backend.core.session_manager import session_manager
from backend.canary.honeytokens import honeytoken_manager
from backend.intelligence.threat_profiler import threat_profiler
from backend.intelligence.report_generator import report_generator
from backend.simulator.attack_bot import attack_simulator
from backend.emulation.web_decoy import web_decoy_router
from backend.emulation.llm_driver import llm_driver

app = FastAPI(
    title="Neural HoneyGrid API",
    description="AI-Driven Adaptive Deception Honeypot & Cyber Threat Intelligence Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Decoy Routes
app.include_router(web_decoy_router)

start_time = time.time()

# --- Request Models ---
class ExecCommandRequest(BaseModel):
    session_id: str
    command: str

class LaunchSimulationRequest(BaseModel):
    scenario_id: str
    session_id: Optional[str] = None

class LLMConfigRequest(BaseModel):
    provider: str
    gemini_key: Optional[str] = None
    groq_key: Optional[str] = None
    openai_key: Optional[str] = None

# --- API Endpoints ---

@app.get("/api/status")
async def get_system_status():
    sessions = session_manager.get_all_sessions_summary()
    total_commands = sum(s["command_count"] for s in sessions)
    critical_sessions = sum(1 for s in sessions if s["risk_score"] >= 75)
    honeytoken_alerts = honeytoken_manager.get_alerts()

    return {
        "status": "ONLINE",
        "uptime_seconds": int(time.time() - start_time),
        "persona": {
            "hostname": config.HOSTNAME,
            "os": config.OS_NAME,
            "ip": config.IP_ADDRESS,
            "kernel": config.KERNEL_VERSION,
            "default_user": config.DEFAULT_USER
        },
        "stats": {
            "total_sessions": len(sessions),
            "active_sessions": sum(1 for s in sessions if s["is_active"]),
            "total_commands_intercepted": total_commands,
            "critical_threats": critical_sessions,
            "canary_breaches": len(honeytoken_alerts),
            "llm_provider": config.LLM_PROVIDER
        }
    }

@app.get("/api/sessions")
async def list_sessions():
    return session_manager.get_all_sessions_summary()

@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    detail = session_manager.get_session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Session not found")
    return detail

@app.post("/api/shell/exec")
async def execute_shell_command(req: ExecCommandRequest):
    result = await session_manager.execute_command(req.session_id, req.command)
    return result

@app.get("/api/canary/tokens")
async def list_canary_tokens():
    return honeytoken_manager.get_all_tokens()

@app.get("/api/canary/alerts")
async def list_canary_alerts():
    return honeytoken_manager.get_alerts()

@app.get("/api/mitre/matrix")
async def get_mitre_matrix():
    # Aggregate all observed techniques
    technique_map = {}
    for s_id, session in session_manager.sessions.items():
        for event in session.mitre_events:
            tid = event.get("technique_id")
            if tid not in technique_map:
                technique_map[tid] = {
                    "technique_id": tid,
                    "name": event.get("name"),
                    "tactic": event.get("tactic"),
                    "severity": event.get("severity"),
                    "hit_count": 0,
                    "sessions": set()
                }
            technique_map[tid]["hit_count"] += 1
            technique_map[tid]["sessions"].add(s_id)

    # Convert sets to lists
    result = []
    for k, v in technique_map.items():
        v_copy = dict(v)
        v_copy["sessions"] = list(v_copy["sessions"])
        result.append(v_copy)
    return sorted(result, key=lambda x: x["hit_count"], reverse=True)

@app.get("/api/reports/{session_id}/markdown")
async def get_report_markdown(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    profile = threat_profiler.evaluate_session(
        session_id=session.session_id,
        commands=session.command_records,
        mitre_events=session.mitre_events,
        canaries_triggered=session.canaries_triggered,
        start_time=session.start_time
    )
    detail = session_manager.get_session_detail(session_id)
    report_md = report_generator.generate_incident_report_md(detail, profile)
    return PlainTextResponse(report_md, media_type="text/markdown")

@app.get("/api/reports/{session_id}/stix")
async def get_report_stix(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    profile = threat_profiler.evaluate_session(
        session_id=session.session_id,
        commands=session.command_records,
        mitre_events=session.mitre_events,
        canaries_triggered=session.canaries_triggered,
        start_time=session.start_time
    )
    detail = session_manager.get_session_detail(session_id)
    bundle = report_generator.generate_stix_bundle(detail, profile)
    return JSONResponse(bundle)

@app.get("/api/simulator/scenarios")
async def get_simulator_scenarios():
    return attack_simulator.get_available_scenarios()

@app.post("/api/simulator/launch")
async def launch_simulation(req: LaunchSimulationRequest):
    try:
        session_id = await attack_simulator.run_scenario(req.scenario_id, req.session_id)
        return {"status": "SUCCESS", "session_id": session_id, "message": f"Simulation scenario '{req.scenario_id}' launched successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/config/llm")
async def update_llm_config(req: LLMConfigRequest):
    config.LLM_PROVIDER = req.provider
    if req.gemini_key:
        config.GEMINI_API_KEY = req.gemini_key
        llm_driver.gemini_key = req.gemini_key
    if req.groq_key:
        config.GROQ_API_KEY = req.groq_key
        llm_driver.groq_key = req.groq_key
    if req.openai_key:
        config.OPENAI_API_KEY = req.openai_key
        llm_driver.openai_key = req.openai_key
    return {"status": "SUCCESS", "provider": config.LLM_PROVIDER}

# --- WebSocket Channel for Real-Time Telemetry ---
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    session_manager.register_websocket(websocket)
    try:
        # Send initial welcome state
        await websocket.send_json({
            "type": "INIT_CONNECTED",
            "message": "Connected to Neural HoneyGrid Real-Time Cyber Stream"
        })
        while True:
            # Keep socket open and listen for any client pings
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        session_manager.unregister_websocket(websocket)
    except Exception:
        session_manager.unregister_websocket(websocket)

# Mount Frontend static files
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

@app.get("/")
async def serve_index():
    index_file = BASE_DIR / "frontend" / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Neural HoneyGrid API is running. Frontend not found."}
