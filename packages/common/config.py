"""Pentesa configuration settings powered by Pydantic."""

from typing import List
from pydantic import AliasChoices, Field
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
    master_key: str = Field(
        default="pentesa-master-key-32-bytes-long-change-in-prod!",
        validation_alias=AliasChoices("pentesa_master_key", "master_key"),
        description="Master encryption key for credential vault"
    )
    encryption_key: str = Field(
        default="",
        validation_alias=AliasChoices("pentesa_encryption_key", "encryption_key"),
        description="AES-256-GCM master encryption key for credentials at rest"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./pentesa.db",
        validation_alias=AliasChoices("pentesa_database_url", "database_url"),
        description="Async SQLAlchemy database connection string"
    )

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

    # LLM Provider Configuration
    llm_provider: str = Field(
        default="mock",
        validation_alias=AliasChoices("pentesa_llm_provider", "llm_provider"),
        description="Active LLM provider: 'mock', 'litellm', 'ollama', 'openai'"
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

