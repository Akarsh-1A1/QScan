from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Redis

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    # How long a completed scan record lives in Redis (seconds).
    # Default: 7 days.  Set to -1 to keep forever.
    REDIS_SCAN_TTL: int = 604800

    # Server

    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000

    # Scanner

    # seconds before the qscan process is killed
    QSCAN_TIMEOUT: int = 300

    # CORS  (comma-separated origins, or "*" to allow all)

    CORS_ORIGINS: str = "*"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def redis_url(self) -> str:
        if self.REDIS_PASSWORD:
            return (
                f"redis://:{self.REDIS_PASSWORD}@"
                f"{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
            )
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

settings = Settings()
