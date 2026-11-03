"""Pentesa configuration settings powered by Pydantic."""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform-wide settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_prefix="PENTESA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Environment & Debug
    env: str = Field(default="development", description="Environment mode: development, staging, production")
    debug: bool = Field(default=False, description="Enable debug mode and detailed error traces")
    log_level: str = Field(default="INFO", description="Logging level")

    # Security & Cryptography
    secret_key: str = Field(
        default="pentesa-super-secret-default-key-change-in-production-1234567890",
        description="JWT signature HMAC secret key"
    )
    master_key: str = Field(
        default="pentesa-master-key-32-bytes-long-change-in-prod!",
        description="Master encryption key for credential vault"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./pentesa.db",
        description="Async SQLAlchemy database connection string"
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for task queue and cache"
    )

    # Outbound Egress Proxy (Layer 2 Scope Enforcement)
    egress_proxy_host: str = "127.0.0.1"
    egress_proxy_port: int = 8080

    # Local Out-of-Band Callback Sink (OAST)
    callback_sink_host: str = "127.0.0.1"
    callback_sink_http_port: int = 8888
    callback_sink_dns_port: int = 8053

    # Safety Guardrails
    default_max_rps: int = 50
    max_fuzz_requests_without_approval: int = 5000
    max_auth_attempts_without_approval: int = 15

    # CORS
    cors_origins: List[str] = ["*"]


settings = Settings()
