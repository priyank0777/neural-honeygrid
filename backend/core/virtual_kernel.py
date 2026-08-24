import re
import time
import asyncio
import random
from typing import Dict, Any, Tuple, List, Optional

from backend.config import config
from backend.core.virtual_fs import VirtualFileSystem, FSNode
from backend.canary.honeytokens import honeytoken_manager, CanaryToken
from backend.intelligence.mitre_mapper import mitre_mapper, MitreTechnique
from backend.emulation.llm_driver import llm_driver

class VirtualShellSession:
    def __init__(self, session_id: str, remote_ip: str = "127.0.0.1", user_agent: str = "curl/7.81.0"):
        self.session_id = session_id
        self.remote_ip = remote_ip
        self.user_agent = user_agent
        self.user = config.DEFAULT_USER
        self.uid = config.DEFAULT_UID
        self.gid = config.DEFAULT_GID
        self.cwd = f"/home/{self.user}"
        self.env: Dict[str, str] = {
            "USER": self.user,
            "LOGNAME": self.user,
            "HOME": f"/home/{self.user}",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": f"/home/{self.user}",
            "HOSTNAME": config.HOSTNAME
        }
        self.history: List[str] = [
            "ls -la",
            "cd /opt/api_gateway",
            "docker ps",
            "git status",
            "sudo systemctl status nginx"
        ]
        self.fs = VirtualFileSystem()
        self.start_time = time.time()
        self.last_active = time.time()
        self.command_records: List[Dict[str, Any]] = []
        self.mitre_events: List[Dict[str, Any]] = []
        self.canaries_triggered: List[Dict[str, Any]] = []
        self.is_active = True

    def get_prompt(self) -> str:
        symbol = "#" if self.user == "root" else "$"
        short_cwd = "~" if self.cwd == f"/home/{self.user}" else self.cwd
        return f"{self.user}@{config.HOSTNAME}:{short_cwd}{symbol} "

class VirtualKernel:
    def __init__(self):
        pass

    async def execute_command(self, session: VirtualShellSession, raw_command: str) -> Dict[str, Any]:
        """Executes an attacker command, logs MITRE TTPs, checks canaries, and returns output."""
        session.last_active = time.time()
        clean_cmd = raw_command.strip()

        # Simulated latency for realism
        if config.SIMULATE_LATENCY:
            latency = random.uniform(config.MIN_LATENCY_MS, config.MAX_LATENCY_MS) / 1000.0
            await asyncio.sleep(latency)

        if not clean_cmd:
            return {
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "prompt": session.get_prompt(),
                "mitre_matches": [],
                "canary_triggered": None
            }

        # 1. MITRE ATT&CK Classification
        mitre_matches: List[MitreTechnique] = mitre_mapper.analyze_command(clean_cmd)
        for m in mitre_matches:
            match_dict = m.model_dump()
            match_dict["timestamp"] = time.time()
            match_dict["command"] = clean_cmd
            session.mitre_events.append(match_dict)

        # 2. Canary & Honeytoken Check
        canary_hit: Optional[CanaryToken] = honeytoken_manager.check_for_canary_access(
            session_id=session.session_id,
            target_path_or_content=clean_cmd,
            command=clean_cmd
        )
        if canary_hit:
            session.canaries_triggered.append(canary_hit.model_dump())

        # 3. Add to history
        session.history.append(clean_cmd)

        # 4. Handle Redirection / Appends (e.g. echo "..." >> /tmp/file)
        redirect_out = self._handle_redirection(session, clean_cmd)
        if redirect_out is not None:
            stdout, stderr, code = redirect_out
        else:
            stdout, stderr, code = await self._run_command_pipeline(session, clean_cmd)

        # 5. Check if output itself contained canaries (e.g. cat .env printed honeytoken)
        output_canary_hit = honeytoken_manager.check_for_canary_access(
            session_id=session.session_id,
            target_path_or_content=stdout,
            command=clean_cmd
        )
        if output_canary_hit and not canary_hit:
            canary_hit = output_canary_hit
            session.canaries_triggered.append(output_canary_hit.model_dump())

        # Record command entry
        cmd_record = {
            "timestamp": time.time(),
            "command": clean_cmd,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": code,
            "user": session.user,
            "cwd": session.cwd,
            "mitre_matches": [m.model_dump() for m in mitre_matches],
            "canary_triggered": canary_hit.model_dump() if canary_hit else None
        }
        session.command_records.append(cmd_record)

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": code,
            "prompt": session.get_prompt(),
            "mitre_matches": [m.model_dump() for m in mitre_matches],
            "canary_triggered": canary_hit.model_dump() if canary_hit else None,
            "cwd": session.cwd,
            "user": session.user
        }

    def _handle_redirection(self, session: VirtualShellSession, command: str) -> Optional[Tuple[str, str, int]]:
        # Check for >> or >
        if ">>" in command:
            parts = command.split(">>", 1)
            target_cmd = parts[0].strip()
            target_file = parts[1].strip()
            # Extract content from echo
            if target_cmd.startswith("echo"):
                content = target_cmd[4:].strip().strip('"\'') + "\n"
                session.fs.append_file(target_file, content, cwd=session.cwd)
                return ("", "", 0)
        elif ">" in command and not "dev/tcp" in command and not "2>&1" in command:
            parts = command.split(">", 1)
            target_cmd = parts[0].strip()
            target_file = parts[1].strip()
            if target_cmd.startswith("echo"):
                content = target_cmd[4:].strip().strip('"\'') + "\n"
                session.fs.write_file(target_file, content, cwd=session.cwd, owner=session.user)
                return ("", "", 0)
        return None

    async def _run_command_pipeline(self, session: VirtualShellSession, command: str) -> Tuple[str, str, int]:
        # Split chained commands (e.g. cd /tmp && ls)
        if "&&" in command:
            subcmds = command.split("&&")
            full_out = []
            for sc in subcmds:
                out, err, code = await self._run_single_command(session, sc.strip())
                if out: full_out.append(out)
                if code != 0:
                    return ("\n".join(full_out), err, code)
            return ("\n".join(full_out), "", 0)

        if ";" in command:
            subcmds = command.split(";")
            full_out = []
            for sc in subcmds:
                out, err, code = await self._run_single_command(session, sc.strip())
                if out: full_out.append(out)
            return ("\n".join(full_out), "", 0)

        return await self._run_single_command(session, command)

    async def _run_single_command(self, session: VirtualShellSession, command: str) -> Tuple[str, str, int]:
        parts = command.split()
        if not parts:
            return ("", "", 0)
        cmd_name = parts[0]
        args = parts[1:]

        # --- Built-in Shell Handlers ---
        if cmd_name == "pwd":
            return (session.cwd, "", 0)

        if cmd_name == "whoami":
            return (session.user, "", 0)

        if cmd_name == "id":
            if session.user == "root":
                return ("uid=0(root) gid=0(root) groups=0(root)", "", 0)
            return (f"uid={session.uid}({session.user}) gid={session.gid}({session.user}) groups=1000({session.user}),27(sudo),110(lxd)", "", 0)

        if cmd_name == "hostname":
            return (config.HOSTNAME, "", 0)

        if cmd_name == "uname":
            if "-a" in args:
                return (config.KERNEL_VERSION, "", 0)
            if "-r" in args:
                return ("5.15.0-105-generic", "", 0)
            if "-m" in args:
                return ("x86_64", "", 0)
            return ("Linux", "", 0)

        if cmd_name == "cd":
            target = args[0] if args else f"/home/{session.user}"
            if target == "~":
                target = f"/home/{session.user}"
            elif target.startswith("~/"):
                target = f"/home/{session.user}/" + target[2:]
            
            node, norm_path = session.fs.resolve_path(target, session.cwd)
            if node and node.is_directory:
                session.cwd = norm_path
                session.env["PWD"] = norm_path
                return ("", "", 0)
            elif node and not node.is_directory:
                return ("", f"bash: cd: {target}: Not a directory", 1)
            else:
                return ("", f"bash: cd: {target}: No such file or directory", 1)

        if cmd_name == "ls":
            return self._exec_ls(session, args)

        if cmd_name == "cat":
            return self._exec_cat(session, args)

        if cmd_name == "head":
            res, err, code = self._exec_cat(session, args)
            if code == 0:
                lines = res.split("\n")[:10]
                return ("\n".join(lines), "", 0)
            return (res, err, code)

        if cmd_name == "tail":
            res, err, code = self._exec_cat(session, args)
            if code == 0:
                lines = res.split("\n")[-10:]
                return ("\n".join(lines), "", 0)
            return (res, err, code)

        if cmd_name == "mkdir":
            if not args:
                return ("", "mkdir: missing operand", 1)
            for path in args:
                if path.startswith("-"): continue
                session.fs.mkdir_p(path, cwd=session.cwd, owner=session.user)
            return ("", "", 0)

        if cmd_name == "touch":
            if not args:
                return ("", "touch: missing file operand", 1)
            for path in args:
                if path.startswith("-"): continue
                session.fs.write_file(path, "", cwd=session.cwd, owner=session.user)
            return ("", "", 0)

        if cmd_name == "rm":
            if not args:
                return ("", "rm: missing operand", 1)
            for path in args:
                if path.startswith("-"): continue
                session.fs.remove(path, cwd=session.cwd)
            return ("", "", 0)

        if cmd_name == "echo":
            content = " ".join(args).strip("\"'")
            return (content, "", 0)

        if cmd_name == "history":
            if "-c" in args:
                session.history.clear()
                return ("", "", 0)
            lines = [f"{i+1:5d}  {cmd}" for i, cmd in enumerate(session.history)]
            return ("\n".join(lines), "", 0)

        if cmd_name == "env" or cmd_name == "printenv":
            lines = [f"{k}={v}" for k, v in session.env.items()]
            return ("\n".join(lines), "", 0)

        if cmd_name == "export":
            for arg in args:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    session.env[k] = v.strip("\"'")
            return ("", "", 0)

        if cmd_name == "sudo":
            if "-l" in args or "--list" in args:
                return (f"Matching Defaults entries for {session.user} on {config.HOSTNAME}:\n"
                        "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                        f"User {session.user} may run the following commands on {config.HOSTNAME}:\n"
                        "    (ALL : ALL) ALL\n"
                        "    (ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/docker, /usr/bin/nmap", "", 0)
            if "su" in args or "-i" in args or "/bin/bash" in args:
                session.user = "root"
                session.uid = 0
                session.gid = 0
                session.cwd = "/root"
                session.env["USER"] = "root"
                session.env["HOME"] = "/root"
                session.env["PWD"] = "/root"
                return ("", "", 0)

        if cmd_name == "ifconfig" or (cmd_name == "ip" and "a" in " ".join(args)):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    f"        inet {config.IP_ADDRESS}  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                    "        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n"
                    "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n"
                    "        RX packets 1294819  bytes 849201948 (849.2 MB)\n"
                    "        TX packets 984012  bytes 492019481 (492.0 MB)\n\n"
                    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                    "        inet 127.0.0.1  netmask 255.0.0.0\n"
                    "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n", "", 0)

        if cmd_name == "ps":
            return ("  PID TTY          TIME CMD\n"
                    "    1 ?        00:00:04 systemd\n"
                    "  842 ?        00:00:12 nginx\n"
                    " 1024 ?        00:01:05 node /opt/api_gateway/server.js\n"
                    " 1120 ?        00:00:32 postgres\n"
                    " 1240 ?        00:00:08 redis-server\n"
                    " 1429 ?        00:00:00 sshd\n"
                    f" 2048 pts/0    00:00:00 bash\n"
                    f" 2099 pts/0    00:00:00 ps", "", 0)

        if cmd_name == "netstat" or cmd_name == "ss":
            return ("Active Internet connections (only servers)\n"
                    "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1429/sshd\n"
                    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      842/nginx\n"
                    "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      842/nginx\n"
                    "tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      1024/node\n"
                    "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1120/postgres\n"
                    "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      1240/redis-server", "", 0)

        if cmd_name == "crontab":
            if "-l" in args:
                return ("# m h  dom mon dow   command\n"
                        "*/15 * * * * /opt/backup_scripts/sync_db.sh >/dev/null 2>&1\n"
                        "0 2 * * * certbot renew --quiet", "", 0)

        if cmd_name == "find":
            return self._exec_find(session, args)

        if cmd_name == "grep":
            return self._exec_grep(session, args)

        # Fallback to Generative AI / Heuristic Cyber Engine
        gen_output = await llm_driver.generate_shell_output(
            command=command,
            cwd=session.cwd,
            user=session.user,
            environment_context={"env": session.env, "history_len": len(session.history)}
        )
        return (gen_output, "", 0)

    def _exec_ls(self, session: VirtualShellSession, args: List[str]) -> Tuple[str, str, int]:
        target_path = session.cwd
        show_all = False
        show_long = False

        for a in args:
            if a.startswith("-"):
                if "a" in a: show_all = True
                if "l" in a: show_long = True
            else:
                target_path = a

        node, _ = session.fs.resolve_path(target_path, session.cwd)
        if not node:
            return ("", f"ls: cannot access '{target_path}': No such file or directory", 2)
        if not node.is_directory:
            return (node.name, "", 0)

        children = node.children
        items = sorted(list(children.keys()))
        if not show_all:
            items = [i for i in items if not i.startswith(".")]

        if show_long:
            lines = [f"total {len(items) * 4}"]
            for item_name in items:
                child = children[item_name]
                date_str = time.strftime("%b %d %H:%M", time.gmtime(child.mtime))
                lines.append(f"{child.mode} 1 {child.owner} {child.group} {child.size:5d} {date_str} {item_name}")
            return ("\n".join(lines), "", 0)
        else:
            return ("  ".join(items), "", 0)

    def _exec_cat(self, session: VirtualShellSession, args: List[str]) -> Tuple[str, str, int]:
        if not args:
            return ("", "", 0)
        outputs = []
        for path in args:
            if path.startswith("-"): continue
            node, _ = session.fs.resolve_path(path, session.cwd)
            if not node:
                return ("", f"cat: {path}: No such file or directory", 1)
            if node.is_directory:
                return ("", f"cat: {path}: Is a directory", 1)
            outputs.append(node.content.rstrip("\n"))
        return ("\n".join(outputs), "", 0)

    def _exec_find(self, session: VirtualShellSession, args: List[str]) -> Tuple[str, str, int]:
        # Handle `find / -perm -u=s` or `find . -name "*.env"`
        arg_str = " ".join(args)
        if "-perm" in arg_str:
            return ("/usr/bin/sudo\n/usr/bin/pkexec\n/usr/bin/passwd\n/usr/bin/chsh\n/usr/bin/newgrp\n/usr/bin/gpasswd", "", 0)
        if ".env" in arg_str:
            return ("/opt/api_gateway/.env", "", 0)
        if "credentials" in arg_str or "aws" in arg_str:
            return ("/home/admin/.aws/credentials\n/home/admin/.git-credentials", "", 0)
        if "id_rsa" in arg_str:
            return ("/root/.ssh/id_rsa", "", 0)
        return (f"{session.cwd}", "", 0)

    def _exec_grep(self, session: VirtualShellSession, args: List[str]) -> Tuple[str, str, int]:
        if len(args) >= 2:
            pattern = args[0].strip("\"'")
            filepath = args[-1]
            content = session.fs.read_file(filepath, cwd=session.cwd)
            if content:
                matching_lines = [l for l in content.split("\n") if pattern in l]
                return ("\n".join(matching_lines), "", 0)
        return ("", "", 0)

virtual_kernel = VirtualKernel()
