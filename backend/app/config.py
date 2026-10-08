from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./cyberguard.db"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "development-only-change-me"
    cors_origins: str = "http://localhost:3000"
    upload_dir: str = "/tmp/cyberguard-uploads"
    max_upload_bytes: int = 10 * 1024 * 1024
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    abuseipdb_api_key: str = ""
    ai_api_key: str = ""

@lru_cache
def get_settings() -> Settings:
    return Settings()
