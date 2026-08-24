import os
import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


BANNER = r"""
  _   _                      _   _   _                             ____      _     _ 
 | \ | | ___ _   _ _ __ __ _| | | | | | ___  _ __   ___ _   _     / ___|_ __(_) __| |
 |  \| |/ _ \ | | | '__/ _` | | | |_| |/ _ \| '_ \ / _ \ | | |   | |  _| '__| |/ _` |
 | |\  |  __/ |_| | | | (_| | | |  _  | (_) | | | |  __/ |_| |   | |_| | |  | | (_| |
 |_| \_|\___|\__,_|_|  \__,_|_| |_| |_|\___/|_| |_|\___|\__, |    \____|_|  |_|\__,_|
                                                          |___/                       
                     [ AI ADAPTIVE CYBER DECEPTION PLATFORM ]
"""

def main():
    print(BANNER)
    print(" [✓] Initializing Virtual Linux Kernel & Decoy Shell...")
    print(" [✓] Planting High-Value Canary Honeytokens (.env, AWS, RSA keys)...")
    print(" [✓] Calibrating Real-Time MITRE ATT&CK Telemetry Engine...")
    print(" [✓] Starting Cyber SOC War Room Dashboard on http://localhost:8000")
    print("\n -> Open your browser at http://localhost:8000 to access the War Room UI.\n")

    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=False, log_level="info")

if __name__ == "__main__":
    main()
