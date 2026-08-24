import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True, parents=True)

class HoneypotConfig(BaseModel):
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # Fake OS Persona
    HOSTNAME: str = "prod-corp-sec-srv01"
    OS_NAME: str = "Ubuntu 22.04.4 LTS (Jammy Jellyfish)"
    KERNEL_VERSION: str = "Linux prod-corp-sec-srv01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
    DEFAULT_USER: str = "admin"
    DEFAULT_UID: int = 1000
    DEFAULT_GID: int = 1000
    IP_ADDRESS: str = "192.168.1.104"
    
    # Response Emulation
    SIMULATE_LATENCY: bool = True
    MIN_LATENCY_MS: int = 40
    MAX_LATENCY_MS: int = 220
    
    # LLM Settings
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "auto") # auto, gemini, groq, openai, mock
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    
    # Storage
    DB_PATH: Path = DATA_DIR / "honeygrid.db"
    REPORTS_DIR: Path = DATA_DIR / "reports"

config = HoneypotConfig()
config.REPORTS_DIR.mkdir(exist_ok=True, parents=True)
