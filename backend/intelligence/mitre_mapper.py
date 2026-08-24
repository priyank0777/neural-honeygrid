import re
from typing import List, Dict, Optional
from pydantic import BaseModel

class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float

class MitreMapper:
    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict]:
        return [
            # Discovery (TA0007)
            {
                "patterns": [r"\bwhoami\b", r"\bid\b", r"\bcat\s+/etc/passwd\b", r"\busers\b", r"\blast\b"],
                "technique_id": "T1087.001",
                "name": "Account Discovery: Local Account",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is attempting to identify local user accounts on the system.",
                "severity": "LOW"
            },
            {
                "patterns": [r"\buname(\s+-a)?\b", r"\bcat\s+/etc/os-release\b", r"\bcat\s+/etc/issue\b", r"\bhostname\b", r"\blscpu\b", r"\barch\b"],
                "technique_id": "T1082",
                "name": "System Information Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is identifying OS version, kernel release, and hardware architecture.",
                "severity": "LOW"
            },
            {
                "patterns": [r"\bls(\s+-[a-zA-Z0-9]+)?\b", r"\bfind\s+", r"\btree\b", r"\blocate\s+"],
                "technique_id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is enumerating file system structure and sensitive files.",
                "severity": "LOW"
            },
            {
                "patterns": [r"\bnetstat\b", r"\bss(\s+-[a-zA-Z0-9]+)?\b", r"\blsof\s+-i\b", r"\bip\s+route\b", r"\broute\b"],
                "technique_id": "T1049",
                "name": "System Network Connections Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is checking active network sockets and listening ports.",
                "severity": "MEDIUM"
            },
            {
                "patterns": [r"\bifconfig\b", r"\bip\s+a(ddr)?\b", r"\bcat\s+/etc/hosts\b", r"\bcat\s+/etc/resolv\.conf\b", r"\barp\b"],
                "technique_id": "T1016",
                "name": "System Network Configuration Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is mapping IP addresses, DNS resolvers, and network interfaces.",
                "severity": "LOW"
            },
            {
                "patterns": [r"\bps(\s+-[a-zA-Z0-9]+|\s+aux)?\b", r"\btop\b", r"\bhtop\b", r"\bpstree\b"],
                "technique_id": "T1057",
                "name": "Process Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is inspecting running processes and daemon services.",
                "severity": "LOW"
            },
            {
                "patterns": [r"\bdpkg\s+-l\b", r"\brpm\s+-qa\b", r"\bwhich\s+", r"\bdocker\s+ps\b", r"\bnginx\s+-v\b"],
                "technique_id": "T1518.001",
                "name": "Software Discovery: Security Software / Installed Apps",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is querying installed software packages and container runtimes.",
                "severity": "MEDIUM"
            },
            {
                "patterns": [r"\bnmap\b", r"\bmasscan\b", r"\bnc\s+-z", r"\bping\s+", r"\btraceroute\b"],
                "technique_id": "T1046",
                "name": "Network Service Discovery / Port Scanning",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Adversary is performing network port scans or ping sweeps across subnet.",
                "severity": "MEDIUM"
            },

            # Credential Access (TA0006)
            {
                "patterns": [r"\bcat\s+/etc/shadow\b", r"\bcat\s+/etc/security/passwd\b", r"\bunshadow\b", r"\bhashcat\b", r"\bjohn\b"],
                "technique_id": "T1003.008",
                "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                "tactic": "Credential Access",
                "tactic_id": "TA0006",
                "description": "High-risk attempt to exfiltrate password hashes from the Linux shadow database.",
                "severity": "CRITICAL"
            },
            {
                "patterns": [r"(\.env|credentials|id_rsa|id_dsa|id_ecdsa|\.aws|\.git-credentials|\.npmrc|\.dockercfg|api_key|token)"],
                "technique_id": "T1552.001",
                "name": "Unsecured Credentials: Credentials In Files",
                "tactic": "Credential Access",
                "tactic_id": "TA0006",
                "description": "Adversary is actively searching for API keys, AWS credentials, or SSH private keys.",
                "severity": "HIGH"
            },
            {
                "patterns": [r"\bhistory\b", r"\bcat\s+.*bash_history\b", r"\bcat\s+.*zsh_history\b"],
                "technique_id": "T1552.003",
                "name": "Unsecured Credentials: Bash History",
                "tactic": "Credential Access",
                "tactic_id": "TA0006",
                "description": "Adversary is inspecting shell command history for typed passwords and secrets.",
                "severity": "MEDIUM"
            },

            # Execution (TA0002)
            {
                "patterns": [r"\bpython3?\s+-c\b", r"\bperl\s+-e\b", r"\bruby\s+-e\b", r"\bphp\s+-r\b", r"\bsh\s+-c\b"],
                "technique_id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "description": "Adversary is executing inline scripts via runtime interpreters (Python/Perl/Bash).",
                "severity": "HIGH"
            },
            {
                "patterns": [r"\b(curl|wget).*\|\s*(ba)?sh\b", r"\bcurl\s+-s.*\|\s*python\b"],
                "technique_id": "T1203",
                "name": "Exploitation for Client Execution / Remote Script Pipe",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "description": "Adversary is downloading and piping an untrusted remote payload directly into shell.",
                "severity": "CRITICAL"
            },
            {
                "patterns": [r"\bcrontab\s+-[le]\b", r"\bcat\s+/etc/crontab\b"],
                "technique_id": "T1053.003",
                "name": "Scheduled Task/Job: Cron",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "description": "Adversary is enumerating or manipulating scheduled cron jobs.",
                "severity": "MEDIUM"
            },

            # Privilege Escalation (TA0004)
            {
                "patterns": [r"\bsudo\s+-l\b", r"\bsudo\s+su\b", r"\bsudo\s+-i\b", r"\bsudo\s+/bin/bash\b"],
                "technique_id": "T1548.003",
                "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                "tactic": "Privilege Escalation",
                "tactic_id": "TA0004",
                "description": "Adversary is testing sudo permissions and looking for NOPASSWD vulnerabilities.",
                "severity": "HIGH"
            },
            {
                "patterns": [r"find\s+.*-perm\s+(-4000|-u=s|\/4000)", r"\bchmod\s+u\+s\b"],
                "technique_id": "T1548.001",
                "name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
                "tactic": "Privilege Escalation",
                "tactic_id": "TA0004",
                "description": "Adversary is hunting for SUID binaries to execute privilege escalation exploits.",
                "severity": "HIGH"
            },
            {
                "patterns": [r"\bpwnkit\b", r"\bdirtycow\b", r"\bcve-202\d-\d+\b", r"\blinpeas\b", r"\blinenum\b"],
                "technique_id": "T1068",
                "name": "Exploitation for Privilege Escalation / Automated Enumerators",
                "tactic": "Privilege Escalation",
                "tactic_id": "TA0004",
                "description": "Adversary is executing LinPEAS or known Linux kernel privilege escalation exploits.",
                "severity": "CRITICAL"
            },

            # Defense Evasion (TA0005)
            {
                "patterns": [r"\bhistory\s+-c\b", r"\bunset\s+HISTFILE\b", r"\brm\s+.*bash_history\b", r"\bexport\s+HISTSIZE=0\b"],
                "technique_id": "T1070.003",
                "name": "Indicator Removal: Clear Command History",
                "tactic": "Defense Evasion",
                "tactic_id": "TA0005",
                "description": "Adversary is attempting to scrub forensics artifacts and bash history logs.",
                "severity": "HIGH"
            },
            {
                "patterns": [r"\biptables\s+-F\b", r"\bufw\s+disable\b", r"\bsetenforce\s+0\b", r"\bsystemctl\s+stop\s+apparmor\b"],
                "technique_id": "T1562.001",
                "name": "Impair Defenses: Disable or Modify Tools",
                "tactic": "Defense Evasion",
                "tactic_id": "TA0005",
                "description": "Adversary is disabling firewall rules, SELinux, or host security agents.",
                "severity": "CRITICAL"
            },
            {
                "patterns": [r"\bbase64\s+-d\b", r"\beval\s+\$\(", r"\bxxd\s+-r\b"],
                "technique_id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "tactic_id": "TA0005",
                "description": "Adversary is using base64 decoding or dynamic evaluation to hide malicious commands.",
                "severity": "MEDIUM"
            },

            # Persistence (TA0003)
            {
                "patterns": [r"\buseradd\b", r"\badduser\b", r"\busermod\s+-aG\s+(sudo|wheel|root)\b", r"\bchpasswd\b"],
                "technique_id": "T1136.001",
                "name": "Create Account: Local Account Backdoor",
                "tactic": "Persistence",
                "tactic_id": "TA0003",
                "description": "Adversary is creating a backdoor user account with administrative privileges.",
                "severity": "CRITICAL"
            },
            {
                "patterns": [r">>.*authorized_keys", r"\.ssh/authorized_keys"],
                "technique_id": "T1098.004",
                "name": "Account Manipulation: SSH Authorized Keys",
                "tactic": "Persistence",
                "tactic_id": "TA0003",
                "description": "Adversary is appending their public key to authorized_keys for persistent SSH access.",
                "severity": "CRITICAL"
            },

            # Collection & Exfiltration (TA0009 / TA0010)
            {
                "patterns": [r"\btar\s+-[a-zA-Z]*c[a-zA-Z]*f?\b", r"\bzip\s+-r\b", r"\bgzip\b"],
                "technique_id": "T1560.001",
                "name": "Archive Collected Data: Archive via Utility",
                "tactic": "Collection",
                "tactic_id": "TA0009",
                "description": "Adversary is compressing sensitive directories into an archive for staged exfiltration.",
                "severity": "MEDIUM"
            },
            {
                "patterns": [r"\bnc\s+-[a-zA-Z0-9]*\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", r"\bcurl\s+-F\s+", r"\bscp\s+", r"\brsync\s+"],
                "technique_id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "tactic_id": "TA0010",
                "description": "Adversary is streaming or uploading stolen data to external IP address.",
                "severity": "HIGH"
            },

            # Command and Control & Resource Hijacking (TA0011 / TA0040)
            {
                "patterns": [r"\bbash\s+-i\s+>& /dev/tcp/", r"\bnc\s+-e\s+/bin/(ba)?sh", r"\bmkfifo\s+/tmp/"],
                "technique_id": "T1059.004",
                "name": "Interactive Reverse Shell Execution",
                "tactic": "Command and Control",
                "tactic_id": "TA0011",
                "description": "Adversary initiated an interactive TCP reverse shell connection to remote listener.",
                "severity": "CRITICAL"
            },
            {
                "patterns": [r"\bxmrig\b", r"\bminerd\b", r"\bcryptonight\b", r"\bstratum\+tcp://\b"],
                "technique_id": "T1496",
                "name": "Resource Hijacking: Cryptocurrency Mining",
                "tactic": "Impact",
                "tactic_id": "TA0040",
                "description": "Adversary is deploying an unauthorized cryptocurrency miner to hijack CPU/GPU.",
                "severity": "CRITICAL"
            }
        ]

    def analyze_command(self, command: str) -> List[MitreTechnique]:
        matches: List[MitreTechnique] = []
        clean_cmd = command.strip()
        if not clean_cmd:
            return matches

        for rule in self.rules:
            for pattern in rule["patterns"]:
                if re.search(pattern, clean_cmd, re.IGNORECASE):
                    matches.append(MitreTechnique(
                        technique_id=rule["technique_id"],
                        name=rule["name"],
                        tactic=rule["tactic"],
                        tactic_id=rule["tactic_id"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=0.95
                    ))
                    break # avoid duplicate matches for same rule
        return matches

mitre_mapper = MitreMapper()
