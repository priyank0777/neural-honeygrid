import time
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel

class CanaryToken(BaseModel):
    token_id: str
    token_type: str # "aws_key", "github_pat", "db_password", "ssh_key", "jwt_secret", "env_file"
    token_value: str
    location_planted: str
    description: str
    planted_at: float
    triggered: bool = False
    triggered_at: Optional[float] = None
    triggered_by_session: Optional[str] = None
    trigger_context: Optional[str] = None

class HoneyTokenManager:
    def __init__(self):
        self.tokens: Dict[str, CanaryToken] = {}
        self.alerts: List[Dict] = []
        self._init_default_honeytokens()

    def _init_default_honeytokens(self):
        defaults = [
            CanaryToken(
                token_id="canary-aws-01",
                token_type="aws_key",
                token_value="CANARY_AWS_KEY_BAIT_94X7F",
                location_planted="/home/admin/.aws/credentials",
                description="Production AWS Admin Access Key Bait",
                planted_at=time.time()
            ),
            CanaryToken(
                token_id="canary-env-02",
                token_type="env_file",
                token_value="DATABASE_URL=postgres://superadmin:P@ssw0rd_Canary_2024!@10.0.4.12:5432/core_production",
                location_planted="/opt/api_gateway/.env",
                description="Production Database Credentials Bait in .env",
                planted_at=time.time()
            ),
            CanaryToken(
                token_id="canary-gh-03",
                token_type="github_pat",
                token_value="CANARY_GH_PAT_CorpDeployKey_99281",
                location_planted="/home/admin/.git-credentials",
                description="Corporate GitHub Deployment PAT Bait",
                planted_at=time.time()
            ),
            CanaryToken(
                token_id="canary-jwt-04",
                token_type="jwt_secret",
                token_value="SUPER_SECRET_INTERNAL_CANARY_JWT_SIGNING_KEY_9921",
                location_planted="/var/www/auth/config.json",
                description="Master JWT Signing Key Bait",
                planted_at=time.time()
            ),
            CanaryToken(
                token_id="canary-ssh-05",
                token_type="ssh_key",
                token_value="-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAYEAv9CanaryBaitKey9940xRootProdClusterMasterKeyBait==\n-----END OPENSSH PRIVATE KEY-----",
                location_planted="/root/.ssh/id_rsa",
                description="Root Cluster Master SSH Private Key Bait",
                planted_at=time.time()
            )
        ]
        for token in defaults:
            self.tokens[token.token_id] = token

    def check_for_canary_access(self, session_id: str, target_path_or_content: str, command: str) -> Optional[CanaryToken]:
        """Inspects if an attacker read, cat-ed, grepped, or accessed a planted canary."""
        for token in self.tokens.values():
            if (token.location_planted.lower() in target_path_or_content.lower() or 
                token.token_value in target_path_or_content or
                token.token_id in target_path_or_content):
                
                token.triggered = True
                token.triggered_at = time.time()
                token.triggered_by_session = session_id
                token.trigger_context = f"Command: {command}"
                
                alert_entry = {
                    "alert_id": f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    "timestamp": time.time(),
                    "session_id": session_id,
                    "token_id": token.token_id,
                    "token_type": token.token_type,
                    "location": token.location_planted,
                    "description": token.description,
                    "severity": "CRITICAL",
                    "command": command,
                    "details": f"Attacker accessed honeypot bait token: {token.description}"
                }
                self.alerts.insert(0, alert_entry)
                return token
        return None

    def get_all_tokens(self) -> List[Dict]:
        return [t.model_dump() for t in self.tokens.values()]

    def get_alerts(self, limit: int = 50) -> List[Dict]:
        return self.alerts[:limit]

honeytoken_manager = HoneyTokenManager()
