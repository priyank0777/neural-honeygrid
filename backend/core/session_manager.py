import time
import json
from typing import Dict, List, Optional, Any
from fastapi import WebSocket

from backend.core.virtual_kernel import VirtualShellSession, virtual_kernel
from backend.intelligence.threat_profiler import threat_profiler, AttackerProfile
from backend.intelligence.report_generator import report_generator
from backend.canary.honeytokens import honeytoken_manager
from backend.config import config

class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, VirtualShellSession] = {}
        self.websocket_clients: List[WebSocket] = []

    def get_or_create_session(self, session_id: str, remote_ip: str = "127.0.0.1", user_agent: str = "Unknown") -> VirtualShellSession:
        if session_id not in self.sessions:
            session = VirtualShellSession(session_id=session_id, remote_ip=remote_ip, user_agent=user_agent)
            self.sessions[session_id] = session
        return self.sessions[session_id]

    def get_session(self, session_id: str) -> Optional[VirtualShellSession]:
        return self.sessions.get(session_id)

    def get_all_sessions_summary(self) -> List[Dict[str, Any]]:
        summaries = []
        for s_id, s in self.sessions.items():
            profile = threat_profiler.evaluate_session(
                session_id=s.session_id,
                commands=s.command_records,
                mitre_events=s.mitre_events,
                canaries_triggered=s.canaries_triggered,
                start_time=s.start_time
            )
            summaries.append({
                "session_id": s.session_id,
                "remote_ip": s.remote_ip,
                "user_agent": s.user_agent,
                "start_time": s.start_time,
                "last_active": s.last_active,
                "is_active": s.is_active,
                "command_count": len(s.command_records),
                "risk_score": profile.risk_score,
                "classification": profile.classification,
                "primary_intent": profile.primary_intent,
                "canary_count": len(s.canaries_triggered),
                "mitre_count": len(s.mitre_events)
            })
        return sorted(summaries, key=lambda x: x["last_active"], reverse=True)

    def get_session_detail(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.sessions.get(session_id)
        if not session:
            return None
        profile = threat_profiler.evaluate_session(
            session_id=session.session_id,
            commands=session.command_records,
            mitre_events=session.mitre_events,
            canaries_triggered=session.canaries_triggered,
            start_time=session.start_time
        )
        return {
            "session_id": session.session_id,
            "remote_ip": session.remote_ip,
            "user_agent": session.user_agent,
            "user": session.user,
            "cwd": session.cwd,
            "start_time": session.start_time,
            "last_active": session.last_active,
            "is_active": session.is_active,
            "profile": profile.model_dump(),
            "commands": session.command_records,
            "mitre_events": session.mitre_events,
            "canaries_triggered": session.canaries_triggered
        }

    async def execute_command(self, session_id: str, command: str) -> Dict[str, Any]:
        session = self.get_or_create_session(session_id)
        result = await virtual_kernel.execute_command(session, command)
        
        # Evaluate updated profile
        profile = threat_profiler.evaluate_session(
            session_id=session.session_id,
            commands=session.command_records,
            mitre_events=session.mitre_events,
            canaries_triggered=session.canaries_triggered,
            start_time=session.start_time
        )

        # Broadcast live event to connected WebSockets
        broadcast_payload = {
            "type": "COMMAND_EXEC",
            "session_id": session.session_id,
            "remote_ip": session.remote_ip,
            "command": command,
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "exit_code": result["exit_code"],
            "prompt": result["prompt"],
            "mitre_matches": result["mitre_matches"],
            "canary_triggered": result["canary_triggered"],
            "risk_score": profile.risk_score,
            "classification": profile.classification,
            "primary_intent": profile.primary_intent,
            "timestamp": time.time()
        }
        await self.broadcast(broadcast_payload)
        return result

    def register_websocket(self, ws: WebSocket):
        if ws not in self.websocket_clients:
            self.websocket_clients.append(ws)

    def unregister_websocket(self, ws: WebSocket):
        if ws in self.websocket_clients:
            self.websocket_clients.remove(ws)

    async def broadcast(self, data: Dict[str, Any]):
        dead_sockets = []
        for ws in self.websocket_clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead_sockets.append(ws)
        for ws in dead_sockets:
            self.unregister_websocket(ws)

session_manager = SessionManager()
