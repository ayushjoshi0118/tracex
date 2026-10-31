import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "TRACEX"
    TAGLINE: str = "Investigate. Analyze. Correlate. Discover."
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Storage & Uploads (Outside public web root, isolated quarantine)
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    STORAGE_DIR: Path = BASE_DIR / "storage"
    QUARANTINE_DIR: Path = STORAGE_DIR / "quarantine"
    REPORTS_DIR: Path = STORAGE_DIR / "reports"
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    
    # Database
    DATABASE_URL: str = "sqlite:///./tracex.db"
    
    # Threat Intelligence API keys (Optional live integrations)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_API_KEY: str = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    
    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "*"]
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Ensure critical isolated directories exist
settings.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
