"""Pentesa configuration settings powered by Pydantic."""

import os
import sys
from typing import List
from pydantic import AliasChoices, Field, model_validator
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
    env: str = Field(
        default="development",
        validation_alias=AliasChoices("pentesa_env", "env"),
        description="Environment mode: development, staging, production"
    )
    debug: bool = Field(
        default=False,
        validation_alias=AliasChoices("pentesa_debug", "debug"),
        description="Enable debug mode and detailed error traces"
    )
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("pentesa_log_level", "log_level"),
        description="Logging level"
    )

    # Security & Cryptography
    secret_key: str = Field(
        default="pentesa-super-secret-default-key-change-in-production-1234567890",
        validation_alias=AliasChoices("pentesa_secret_key", "secret_key"),
        description="JWT signature HMAC secret key"
    )
    encryption_key: str = Field(
        default="",
        validation_alias=AliasChoices("pentesa_encryption_key", "encryption_key"),
        description="AES-256-GCM master encryption key for credentials at rest (must be >= 32 bytes)"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = Field(
        default="",
        validation_alias=AliasChoices("pentesa_database_url", "database_url"),
        description="Async SQLAlchemy database connection string"
    )
    allow_test_sqlite: bool = Field(
        default=False,
        validation_alias=AliasChoices("pentesa_allow_test_sqlite", "allow_test_sqlite"),
        description="Explicitly permit SQLite fallback for unit test suites only"
    )

    @model_validator(mode="after")
    def validate_database_config(self) -> "Settings":
        env = (self.env or "").strip().lower()
        url = (self.database_url or "").strip()
        is_test_runner = (
            "pytest" in sys.modules
            or "PYTEST_CURRENT_TEST" in os.environ
            or any("pytest" in arg.lower() for arg in sys.argv)
        )
        allow_sqlite = (
            self.allow_test_sqlite
            or os.getenv("PENTESA_ALLOW_TEST_SQLITE", "").strip().lower() in ("1", "true", "yes")
            or env == "test"
            or is_test_runner
        )

        # 1. Production & Staging: Fail closed if DATABASE_URL is missing or not PostgreSQL
        if env in ("production", "staging"):
            if not url:
                raise ValueError(
                    f"CRITICAL CONFIGURATION ERROR: PENTESA_DATABASE_URL is not set in environment '{env}'. "
                    "Production mode fails closed and requires an explicit PostgreSQL connection string (postgresql+asyncpg://...)."
                )
            if "sqlite" in url.lower():
                raise ValueError(
                    f"CRITICAL CONFIGURATION ERROR: SQLite database is strictly prohibited in environment '{env}'. "
                    "Production mode requires a valid PostgreSQL connection (postgresql+asyncpg://...)."
                )
            if not (url.startswith("postgresql+asyncpg://") or url.startswith("postgresql://") or url.startswith("postgres://")):
                raise ValueError(
                    f"CRITICAL CONFIGURATION ERROR: Database URL '{url[:20]}...' in environment '{env}' is not PostgreSQL. "
                    "Production mode requires a valid PostgreSQL connection (postgresql+asyncpg://...)."
                )

        # 2. SQLite is permitted ONLY under explicit test setting
        if "sqlite" in url.lower() and not allow_sqlite:
            raise ValueError(
                "CRITICAL CONFIGURATION ERROR: SQLite database is prohibited. "
                "SQLite is only permitted under an explicit test setting (PENTESA_ALLOW_TEST_SQLITE=1 or PENTESA_ENV=test)."
            )

        # 3. Default to SQLite only in test setting if url was omitted
        if not url and allow_sqlite:
            self.database_url = "sqlite+aiosqlite:///./pentesa.db"
        elif not url and env not in ("production", "staging"):
            # Local dev fallback to PostgreSQL
            self.database_url = "postgresql+asyncpg://pentesa:pentesa_dev@localhost:5432/pentesa"

        return self

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias=AliasChoices("pentesa_redis_url", "redis_url"),
        description="Redis connection URL for task queue and cache"
    )

    # Outbound Egress Proxy (Layer 2 Scope Enforcement)
    egress_proxy_host: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices("pentesa_egress_proxy_host", "egress_proxy_host")
    )
    egress_proxy_port: int = Field(
        default=8080,
        validation_alias=AliasChoices("pentesa_egress_proxy_port", "egress_proxy_port")
    )

    # Local Out-of-Band Callback Sink (OAST)
    callback_sink_host: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices("pentesa_callback_sink_host", "callback_sink_host")
    )
    callback_sink_http_port: int = Field(
        default=8888,
        validation_alias=AliasChoices("pentesa_callback_sink_http_port", "callback_sink_http_port")
    )
    callback_sink_dns_port: int = Field(
        default=8053,
        validation_alias=AliasChoices("pentesa_callback_sink_dns_port", "callback_sink_dns_port")
    )

    # Storage Mounts
    report_storage_dir: str = Field(
        default="./data/reports",
        validation_alias=AliasChoices("pentesa_report_storage_dir", "report_storage_dir"),
        description="Directory path for compiled HTML/PDF deliverables"
    )
    evidence_storage_dir: str = Field(
        default="./data/evidence",
        validation_alias=AliasChoices("pentesa_evidence_storage_dir", "evidence_storage_dir"),
        description="Directory path for forensic request/response artifacts"
    )

    # Safety Guardrails
    default_max_rps: int = Field(
        default=50,
        validation_alias=AliasChoices("pentesa_default_max_rps", "default_max_rps")
    )
    max_fuzz_requests_without_approval: int = Field(
        default=5000,
        validation_alias=AliasChoices(
            "pentesa_max_fuzz_requests_without_approval",
            "max_fuzz_requests_without_approval"
        )
    )
    max_auth_attempts_without_approval: int = Field(
        default=15,
        validation_alias=AliasChoices(
            "pentesa_max_auth_attempts_without_approval",
            "max_auth_attempts_without_approval"
        )
    )

    # LLM Budget Enforcement Guardrails (Phase 3 Amendment)
    llm_max_budget_usd: float = Field(
        default=10.0,
        validation_alias=AliasChoices("pentesa_llm_max_budget_usd", "llm_max_budget_usd"),
        description="Maximum platform-wide / benchmark LLM spend in USD"
    )
    llm_max_tokens: int = Field(
        default=300000,
        validation_alias=AliasChoices("pentesa_llm_max_tokens", "llm_max_tokens"),
        description="Maximum cumulative LLM token limit"
    )
    llm_budget_enforcement_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("pentesa_llm_budget_enforcement_enabled", "llm_budget_enforcement_enabled"),
        description="Enforce hard cutoff when LLM token or cost limits are exceeded"
    )

    # LLM Provider Configuration
    llm_provider: str = Field(
        default="",
        validation_alias=AliasChoices("pentesa_llm_provider", "llm_provider"),
        description="Active LLM provider: 'litellm', 'ollama', 'openai', or 'mock' (test-only)"
    )

    # LiteLLM Configuration (Proxy / Enterprise Gateway)
    litellm_base_url: str = Field(
        default="http://localhost:4000",
        validation_alias=AliasChoices("pentesa_litellm_base_url", "litellm_base_url", "litellm_url"),
        description="LiteLLM proxy server URL (e.g. http://localhost:4000 or http://localhost:4000/v1)"
    )
    litellm_api_key: str = Field(
        default="sk-placeholder",
        validation_alias=AliasChoices("pentesa_litellm_api_key", "litellm_api_key"),
        description="LiteLLM proxy API key or virtual token"
    )
    litellm_model: str = Field(
        default="gpt-4o",
        validation_alias=AliasChoices("pentesa_litellm_model", "litellm_model"),
        description="Model routed via LiteLLM proxy (e.g., gpt-4o, claude-3-5-sonnet, gemini-1.5-pro, ollama/llama3)"
    )
    litellm_timeout: float = Field(
        default=120.0,
        validation_alias=AliasChoices("pentesa_litellm_timeout", "litellm_timeout"),
        description="LiteLLM proxy timeout in seconds"
    )

    # Local Ollama Configuration
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias=AliasChoices("pentesa_ollama_base_url", "ollama_base_url"),
        description="Ollama server base URL"
    )
    ollama_model: str = Field(
        default="llama3.1",
        validation_alias=AliasChoices("pentesa_ollama_model", "ollama_model"),
        description="Ollama model name"
    )

    # Direct OpenAI / Compatible Configuration
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        validation_alias=AliasChoices("pentesa_openai_base_url", "openai_base_url"),
        description="Direct OpenAI-compatible API base URL"
    )
    openai_api_key: str = Field(
        default="sk-placeholder",
        validation_alias=AliasChoices("pentesa_openai_api_key", "openai_api_key"),
        description="OpenAI API key"
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        validation_alias=AliasChoices("pentesa_openai_model", "openai_model"),
        description="OpenAI model name"
    )

    # CORS
    cors_origins: List[str] = ["*"]


settings = Settings()

