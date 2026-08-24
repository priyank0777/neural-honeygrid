import os
import re
import json
import time
import random
from typing import Optional, Dict, Any
import httpx

from backend.config import config

class LLMDriver:
    def __init__(self):
        self.provider = config.LLM_PROVIDER
        self.gemini_key = config.GEMINI_API_KEY
        self.groq_key = config.GROQ_API_KEY
        self.openai_key = config.OPENAI_API_KEY

    async def generate_shell_output(
        self,
        command: str,
        cwd: str,
        user: str,
        environment_context: Dict[str, Any]
    ) -> str:
        """Generates realistic shell output for commands that are not handled by local built-ins."""
        
        # 1. Try Gemini API if key is present
        if self.gemini_key and (self.provider in ["auto", "gemini"]):
            try:
                res = await self._query_gemini(command, cwd, user, environment_context)
                if res is not None:
                    return res
            except Exception as e:
                pass # fallback to neural cyber heuristic emulator

        # 2. Try Groq API if key is present
        if self.groq_key and (self.provider in ["auto", "groq"]):
            try:
                res = await self._query_groq(command, cwd, user, environment_context)
                if res is not None:
                    return res
            except Exception as e:
                pass

        # 3. Try OpenAI API if key is present
        if self.openai_key and (self.provider in ["auto", "openai"]):
            try:
                res = await self._query_openai(command, cwd, user, environment_context)
                if res is not None:
                    return res
            except Exception as e:
                pass

        # 4. Fallback to High-Fidelity Neural Cyber Emulator
        return self._heuristic_cyber_emulator(command, cwd, user, environment_context)

    async def _query_gemini(self, command: str, cwd: str, user: str, context: Dict[str, Any]) -> Optional[str]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
        prompt = self._build_system_prompt(command, cwd, user, context)
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800}
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return self._clean_llm_output(text)
        return None

    async def _query_groq(self, command: str, cwd: str, user: str, context: Dict[str, Any]) -> Optional[str]:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.groq_key}"}
        prompt = self._build_system_prompt(command, cwd, user, context)
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                return self._clean_llm_output(text)
        return None

    async def _query_openai(self, command: str, cwd: str, user: str, context: Dict[str, Any]) -> Optional[str]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.openai_key}"}
        prompt = self._build_system_prompt(command, cwd, user, context)
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                return self._clean_llm_output(text)
        return None

    def _build_system_prompt(self, command: str, cwd: str, user: str, context: Dict[str, Any]) -> str:
        return f"""You are a low-level Linux kernel terminal emulator for an Ubuntu 22.04 LTS honeypot system named '{config.HOSTNAME}'.
Current User: {user}
Current Directory: {cwd}
Command executed by attacker: {command}

STRICT RULES:
1. Output ONLY the exact raw STDOUT and STDERR that a real Ubuntu 22.04 terminal would print.
2. DO NOT include markdown code blocks, backticks (```), explanations, or notes.
3. Be completely realistic. If the command succeeds, return its standard output. If it fails or is invalid, return standard bash error formatting (e.g., `bash: command: command not found`).
4. If downloading a payload (curl/wget), pretend the connection succeeds or times out realistically.
5. If the attacker tries privilege escalation exploits or reverse shells, simulate standard output that keeps them engaged.
"""

    def _clean_llm_output(self, text: str) -> str:
        # Strip markdown fences if LLM accidentally included them
        clean = text.strip()
        if clean.startswith("```bash") or clean.startswith("```sh") or clean.startswith("```"):
            clean = re.sub(r"^```[a-zA-Z]*\n?", "", clean)
            clean = re.sub(r"\n?```$", "", clean)
        return clean.strip()

    def _heuristic_cyber_emulator(self, command: str, cwd: str, user: str, context: Dict[str, Any]) -> str:
        cmd = command.strip()

        # curl / wget payload download
        if cmd.startswith("curl") or cmd.startswith("wget"):
            if "pastebin" in cmd or "evil" in cmd or "sh" in cmd or "py" in cmd:
                return "[*] Connecting to remote host...\n[+] 200 OK (3.4 KB downloaded)\n[+] Executing payload stage 1 in memory..."
            elif "-I" in cmd or "--head" in cmd:
                return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nDate: " + time.strftime('%a, %d %b %Y %H:%M:%S GMT') + "\nContent-Type: text/html\nConnection: keep-alive"
            else:
                return "<!DOCTYPE html>\n<html>\n<head><title>Internal Gateway Service</title></head>\n<body>\n<h1>API Service Online</h1>\n</body>\n</html>"

        # Docker / Containers
        if cmd.startswith("docker ps") or cmd.startswith("docker container ls"):
            return "CONTAINER ID   IMAGE                 COMMAND                  CREATED        STATUS        PORTS                    NAMES\n" \
                   "4c82b017f8a1   redis:7-alpine        \"docker-entrypoint.s…\"   4 days ago     Up 4 days     0.0.0.0:6379->6379/tcp   redis-cache\n" \
                   "9a18f402c31e   postgres:14-alpine    \"docker-entrypoint.s…\"   2 weeks ago    Up 2 weeks    0.0.0.0:5432->5432/tcp   prod-postgres-db\n" \
                   "f028da9109bc   node:18-bullseye      \"docker-entrypoint.s…\"   2 weeks ago    Up 2 weeks    0.0.0.0:3000->3000/tcp   api-gateway-service"

        if cmd.startswith("docker"):
            return "Emulated Docker engine daemon v24.0.7 (API version 1.43)"

        # Git
        if cmd.startswith("git status"):
            return "On branch main\nYour branch is up to date with 'origin/main'.\n\nnothing to commit, working tree clean"
        if cmd.startswith("git log"):
            return "commit a8f9c1023812739812749817234918239012 (HEAD -> main, origin/main)\nAuthor: devops <devops@corp.internal>\nDate:   Fri Aug 21 14:12:00 2024 -0400\n\n    Update production DB pool size and Canary environment secrets\n\ncommit 31b8f4102938120398123091823091823091\nAuthor: admin <admin@corp.internal>\nDate:   Tue Aug 18 09:30:15 2024 -0400\n\n    Initial API gateway cluster configuration"

        # Systemctl & Services
        if cmd.startswith("systemctl status") or cmd.startswith("service"):
            srv = cmd.split()[-1] if len(cmd.split()) > 1 else "service"
            return f"● {srv}.service - Production Internal Microservice\n     Loaded: loaded (/lib/systemd/system/{srv}.service; enabled; vendor preset: enabled)\n     Active: active (running) since Sun 2024-08-20 02:11:04 UTC; 4 days ago\n   Main PID: 842 ({srv})\n      Tasks: 4 (limit: 9482)\n     Memory: 48.2M\n        CPU: 1.204s"

        if cmd.startswith("systemctl") or cmd.startswith("service"):
            return ""

        # Nmap / Port scanning
        if cmd.startswith("nmap"):
            return "Starting Nmap 7.80 ( https://nmap.org ) at " + time.strftime('%Y-%m-%d %H:%M') + "\n" \
                   "Nmap scan report for localhost (127.0.0.1)\n" \
                   "Host is up (0.00012s latency).\n" \
                   "Not shown: 995 closed ports\n" \
                   "PORT     STATE SERVICE     VERSION\n" \
                   "22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6\n" \
                   "80/tcp   open  http        nginx 1.18.0\n" \
                   "443/tcp  open  ssl/http    nginx 1.18.0\n" \
                   "3000/tcp open  ppp?        NodeJS API Gateway\n" \
                   "5432/tcp open  postgresql  PostgreSQL 14.9\n" \
                   "6379/tcp open  redis       Redis key-value store 7.0.12\n\n" \
                   "Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds"

        # LinPEAS / LinEnum privilege escalation enumerator
        if "linpeas" in cmd or "linenum" in cmd:
            return "  ╔══════════╣ Basic System Information\n" \
                   "  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation\n" \
                   f"  Linux prod-corp-sec-srv01 5.15.0-105-generic #115-Ubuntu SMP x86_64\n" \
                   f"  Current User: {user} (uid={1000 if user=='admin' else 0})\n" \
                   "  [+] SUID Binaries found:\n" \
                   "  /usr/bin/sudo\n" \
                   "  /usr/bin/pkexec (CVE-2021-4034 PwnKit candidate)\n" \
                   "  /usr/bin/passwd\n" \
                   "  [+] Writable configuration files:\n" \
                   "  /opt/api_gateway/.env\n" \
                   "  /opt/backup_scripts/sync_db.sh\n"

        # Reverse shell attempts
        if "bash -i" in cmd or "/dev/tcp" in cmd or "nc -e" in cmd or "mkfifo" in cmd:
            return "[+] Reverse connection initiated to target listener on standard stream. Session established in background..."

        # Cryptominer / XMRig
        if "xmrig" in cmd or "minerd" in cmd:
            return "[2024-08-24 15:10:02.124] [net] connect to pool.minexmr.com:4444 ...\n[2024-08-24 15:10:02.340] [net] connected (diff 100000)\n[2024-08-24 15:10:02.341] [cpu] READY cpu #0, #1 (2 threads active)\n[2024-08-24 15:10:05.100] [cpu] speed 10s/60s/15m 482.4 H/s max 512.0 H/s"

        # Python inline execution
        if cmd.startswith("python") or cmd.startswith("python3"):
            if "-c" in cmd:
                return ""
            return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> "

        # Default fallback
        first_token = cmd.split()[0] if cmd.split() else "command"
        if first_token in ["apt", "apt-get", "yum", "dnf"]:
            return f"Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nE: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock, are you root?"
        
        # Realistic command not found or silent success
        if len(cmd.split()) == 1 and cmd not in ["clear", "exit", "logout"]:
            return f"bash: {first_token}: command not found"

        return ""

llm_driver = LLMDriver()
