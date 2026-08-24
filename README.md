# 🛡️ Neural HoneyGrid: AI-Driven Adaptive Deception & Threat Intelligence Platform

**Neural HoneyGrid** is a state-of-the-art cyber deception platform combining an AI-powered interactive Linux shell, dynamic canary baiting, real-time MITRE ATT&CK telemetry, attacker sophistication profiling, and an automated blue-team Sigma & YARA rule synthesizer.

---

## 🚀 Quick Start

### 1. Launch the Deception SOC Server
```bash
python run.py
```

### 2. Access the Cyber SOC War Room
Open your browser and navigate to:
```text
http://localhost:8000
```

---

## 🌟 Key Features

1. **AI Generative Virtual Shell (`backend/core/virtual_kernel.py` & `llm_driver.py`)**
   - Emulates an authentic **Ubuntu 22.04 LTS** server (`prod-corp-sec-srv01`).
   - Stateful Linux filesystem (`/etc/passwd`, `/etc/shadow`, `/opt/api_gateway/.env`, `/root/.ssh/id_rsa`).
   - Built-in **High-Fidelity Cyber Neural Emulator** (works instantly offline out-of-the-box, with optional Google Gemini / Groq / OpenAI API hooks).

2. **Canary Honeytoken Traps (`backend/canary/honeytokens.py`)**
   - High-value fake AWS keys, Stripe secrets, PostgreSQL passwords, and SSH keys.
   - When an attacker accesses or exfiltrates them (e.g. `cat /opt/api_gateway/.env` or `cat ~/.aws/credentials`), high-priority SOC alarms are tripped immediately.

3. **Real-Time MITRE ATT&CK Classification (`backend/intelligence/mitre_mapper.py`)**
   - Maps attacker commands and tools in real-time across 40+ techniques (Discovery, Credential Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Collection, Exfiltration, Impact).
   - Live visual MITRE matrix radar on the web UI.

4. **Threat Actor Profiling & AI Incident Reports (`backend/intelligence/`)**
   - Real-time sophistication scoring (0–100) and actor classification (*Automated Scanner, Script Kiddie, Targeted Operator, APT*).
   - Generates executive forensic reports in Markdown, exportable STIX 2.1 JSON bundles, and auto-generated **Sigma & YARA rules** ready to deploy into SIEMs.

5. **Adversary Attack Simulator (`backend/simulator/attack_bot.py`)**
   - Built-in multi-stage adversary scenarios:
     - 🔍 *Automated Recon & Subnet Discovery (Shodan Bot)*
     - 🔑 *Targeted Cloud Credential & Secret Harvester*
     - 💀 *Full-Chain APT: Sudo Exploitation & SSH Backdoor*
     - ⛏️ *Malware Dropper & Cryptojacker Infiltration*

6. **Decoy Web & API Routes (`backend/emulation/web_decoy.py`)**
   - `/.env` — Leaks canary secrets and fingerprints crawlers.
   - `/admin` & `/login` — Decoy authentication portal.
   - `/api/v1/debug` & `/actuator/env` — Fake Spring/NodeJS debug endpoints.

---

## 📁 Project Architecture

```text
NeuralHoneyGrid/
├── backend/
│   ├── app.py                 # FastAPI application & WebSocket server
│   ├── config.py              # System configuration & OS persona
│   ├── core/
│   │   ├── session_manager.py # Manages active sessions & WebSocket broadcast
│   │   ├── virtual_fs.py      # Stateful virtual Linux filesystem
│   │   └── virtual_kernel.py  # Shell logic & command pipeline processor
│   ├── emulation/
│   │   ├── llm_driver.py      # Multi-provider LLM connector & Neural Emulator
│   │   └── web_decoy.py       # Decoy web portal & bait routes
│   ├── intelligence/
│   │   ├── mitre_mapper.py    # MITRE ATT&CK classifier (40+ rules)
│   │   ├── threat_profiler.py # Risk scoring & actor classification
│   │   └── report_generator.py# Incident reports & Sigma/STIX generator
│   ├── canary/
│   │   └── honeytokens.py     # Honeytoken traps & canary alarm monitor
│   └── simulator/
│       └── attack_bot.py      # Automated multi-stage attack scenarios
├── frontend/
│   ├── index.html             # Cyber SOC War Room UI
│   ├── css/
│   │   └── style.css          # Dark futuristic Cyberpunk theme
│   └── js/
│       ├── app.js             # Real-time WebSocket & state management
│       ├── terminal_view.js   # Interactive terminal & keystroke stream
│       ├── mitre_view.js      # MITRE ATT&CK Matrix heatmap
│       └── simulator_view.js  # Adversary attack simulator controller
├── tests/
│   ├── test_honeygrid.py      # Core integration test suite
│   └── test_api_endpoints.py  # REST & WebSocket endpoint tests
├── run.py                     # One-click startup script
└── requirements.txt           # Python dependencies
```
