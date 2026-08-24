import time
from typing import List, Dict, Set
from pydantic import BaseModel

class AttackerProfile(BaseModel):
    session_id: str
    risk_score: int # 0 to 100
    classification: str # "Automated Scanner", "Script Kiddie", "Targeted Operator", "Advanced Persistent Threat (APT)"
    confidence: float
    primary_intent: str
    techniques_used: List[str]
    tactics_observed: List[str]
    canaries_triggered_count: int
    command_count: int
    start_time: float
    last_active: float

class ThreatProfiler:
    def __init__(self):
        pass

    def evaluate_session(
        self,
        session_id: str,
        commands: List[Dict],
        mitre_events: List[Dict],
        canaries_triggered: List[Dict],
        start_time: float
    ) -> AttackerProfile:
        cmd_count = len(commands)
        unique_techniques: Set[str] = set()
        tactics: Set[str] = set()
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        for event in mitre_events:
            unique_techniques.add(event.get("technique_id", ""))
            tactics.add(event.get("tactic", ""))
            sev = event.get("severity", "LOW")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate base score
        score = 0
        score += severity_counts["LOW"] * 4
        score += severity_counts["MEDIUM"] * 10
        score += severity_counts["HIGH"] * 22
        score += severity_counts["CRITICAL"] * 35
        score += len(canaries_triggered) * 25

        # Cap score at 100
        risk_score = min(100, max(5 if cmd_count > 0 else 0, score))

        # Classification logic
        if len(canaries_triggered) >= 2 or severity_counts["CRITICAL"] >= 2 or ("Defense Evasion" in tactics and "Exfiltration" in tactics):
            classification = "Advanced Persistent Threat (APT)"
            confidence = 0.94
        elif severity_counts["CRITICAL"] >= 1 or severity_counts["HIGH"] >= 2 or len(canaries_triggered) >= 1:
            classification = "Targeted Operator"
            confidence = 0.88
        elif severity_counts["MEDIUM"] >= 2 or severity_counts["HIGH"] >= 1:
            classification = "Script Kiddie"
            confidence = 0.82
        elif cmd_count > 0:
            classification = "Automated Scanner"
            confidence = 0.78
        else:
            classification = "Unclassified / Inactive"
            confidence = 0.50

        # Intent assessment
        intents = []
        if any("T1496" in t for t in unique_techniques):
            intents.append("Resource Hijacking (Cryptomining)")
        if len(canaries_triggered) > 0 or any("T1003" in t or "T1552" in t for t in unique_techniques):
            intents.append("Credential Theft & Secret Exfiltration")
        if any("T1548" in t or "T1068" in t for t in unique_techniques):
            intents.append("Privilege Escalation")
        if any("T1098" in t or "T1136" in t or "T1053" in t for t in unique_techniques):
            intents.append("Backdoor & Persistence Setup")
        if any("T1562" in t or "T1070" in t for t in unique_techniques):
            intents.append("Defense Impairment & Forensics Evasion")
        if any("T1046" in t or "T1016" in t or "T1049" in t for t in unique_techniques):
            intents.append("Internal Network Reconnaissance")

        primary_intent = " & ".join(intents[:2]) if intents else "Initial Environment Discovery"

        return AttackerProfile(
            session_id=session_id,
            risk_score=risk_score,
            classification=classification,
            confidence=confidence,
            primary_intent=primary_intent,
            techniques_used=sorted(list(unique_techniques)),
            tactics_observed=sorted(list(tactics)),
            canaries_triggered_count=len(canaries_triggered),
            command_count=cmd_count,
            start_time=start_time,
            last_active=time.time()
        )

threat_profiler = ThreatProfiler()
