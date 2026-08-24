import json
import time
import uuid
from typing import Dict, List, Any
from backend.intelligence.threat_profiler import AttackerProfile

class ReportGenerator:
    def __init__(self):
        pass

    def generate_incident_report_md(self, session_data: Dict[str, Any], profile: AttackerProfile) -> str:
        session_id = session_data.get("session_id", "Unknown")
        remote_ip = session_data.get("remote_ip", "Unknown")
        user_agent = session_data.get("user_agent", "Unknown")
        commands = session_data.get("commands", [])
        canaries = session_data.get("canaries_triggered", [])
        mitre_events = session_data.get("mitre_events", [])

        duration = max(1, int(profile.last_active - profile.start_time))
        start_date = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(profile.start_time))

        md = f"""# 🛡️ NEURAL HONEYGRID - THREAT INTELLIGENCE & INCIDENT REPORT

**Report ID:** `NHG-INC-{session_id[:8].upper()}`  
**Generated At:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`  
**Classification:** `CONFIDENTIAL // TLP:AMBER`  

---

## 1. Executive Summary

| Attribute | Assessment |
| :--- | :--- |
| **Attacker Origin IP** | `{remote_ip}` |
| **Assigned Threat Level** | **{profile.risk_score} / 100** |
| **Actor Classification** | **{profile.classification}** (Confidence: {int(profile.confidence * 100)}%) |
| **Identified Intent** | **{profile.primary_intent}** |
| **Session Duration** | {duration} seconds |
| **Commands Executed** | {profile.command_count} commands |
| **Canary Traps Tripped** | {profile.canaries_triggered_count} Honeytokens breached |

### Incident Overview
On **{start_date}**, the Neural HoneyGrid Deception engine intercepted an unauthorized entity connecting from `{remote_ip}`. 
The actor conducted multi-stage adversarial operations against the emulated environment. The actor's primary operational goal was identified as **{profile.primary_intent}**. 
{"⚠️ **CRITICAL BREACH WARNING:** The attacker discovered and attempted to exfiltrate planted honeytokens." if profile.canaries_triggered_count > 0 else "No canary tokens were successfully exfiltrated."}

---

## 2. MITRE ATT&CK Matrix Alignment

Observed Tactics: {", ".join([f"`{t}`" for t in profile.tactics_observed]) if profile.tactics_observed else "None"}

| Technique ID | Technique Name | Tactic | Severity |
| :--- | :--- | :--- | :--- |
"""
        for event in mitre_events:
            md += f"| `{event.get('technique_id')}` | {event.get('name')} | {event.get('tactic')} | **{event.get('severity')}** |\n"

        if not mitre_events:
            md += "| None | No explicit MITRE patterns matched | - | - |\n"

        md += """
---

## 3. Honeytoken & Deception Canary Interceptions

"""
        if canaries:
            for c in canaries:
                c_time = time.strftime('%H:%M:%S UTC', time.gmtime(c.get('triggered_at', time.time())))
                md += f"""- **🚨 [{c_time}] {c.get('token_type', '').upper()}**: `{c.get('description')}`
  - **Planted Location:** `{c.get('location_planted')}`
  - **Trigger Context:** `{c.get('trigger_context')}`
"""
        else:
            md += "*No honeytokens were accessed during this session.*\n"

        md += """
---

## 4. Chronological Command Forensics Timeline

```bash
"""
        for cmd in commands:
            ts = time.strftime('%H:%M:%S', time.gmtime(cmd.get('timestamp', time.time())))
            user = cmd.get('user', 'admin')
            cwd = cmd.get('cwd', '~')
            md += f"[{ts}] {user}@prod-corp-sec-srv01:{cwd}$ {cmd.get('command')}\n"

        md += """```

---

## 5. Automated Blue Team Defense Rules

### Sigma Detection Rule (SIEM Ingestion)
```yaml
title: NeuralHoneyGrid Detected Attacker Activity from """ + remote_ip + """
id: """ + str(uuid.uuid4()) + """
status: experimental
description: Auto-generated detection rule from Neural HoneyGrid honeypot engagement.
author: Neural HoneyGrid AI Autonomous Engine
date: """ + time.strftime('%Y/%m/%d') + """
references:
    - https://attack.mitre.org/
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
"""
        sample_cmds = [c.get('command') for c in commands if len(c.get('command', '')) > 2][:5]
        if sample_cmds:
            for sc in sample_cmds:
                clean_sc = sc.replace('"', '\\"').replace("'", "''")
                md += f"            - '{clean_sc}'\n"
        else:
            md += "            - 'whoami'\n"

        md += """    condition: selection
fields:
    - CommandLine
    - User
    - Image
falsepositives:
    - Authorized administrative maintenance
level: high
```

---
*Report generated autonomously by Neural HoneyGrid AI Core.*
"""
        return md

    def generate_stix_bundle(self, session_data: Dict[str, Any], profile: AttackerProfile) -> Dict[str, Any]:
        bundle_id = f"bundle--{uuid.uuid4()}"
        remote_ip = session_data.get("remote_ip", "127.0.0.1")
        
        objects = [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{uuid.uuid4()}",
                "created": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "name": f"Honeypot Intercepted Actor [{profile.classification}]",
                "threat_actor_types": [profile.classification.lower().replace(" ", "-")],
                "description": f"Automated profile generated by Neural HoneyGrid. Primary intent: {profile.primary_intent}"
            },
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": f"ipv4-addr--{uuid.uuid4()}",
                "value": remote_ip
            }
        ]

        for tech in profile.techniques_used:
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "name": tech,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech
                    }
                ]
            })

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects
        }

report_generator = ReportGenerator()
