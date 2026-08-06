from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    APP_NAME : str = "SECURITY LAYER"
    VERSION : str = "0.1.0"
    DEBUG : bool = False
    LOG_LEVEL : str = "INFO"

    # database
    DATABASE_URL :str = "sqlite+aiosqlite:///./d5_dev.db"
    # Production: "postgresql+asyncpg://user:pass@localhost:5432/d5"
    # Create tables on startup (dev convenience). Set false in prod — use alembic.
    DB_AUTO_CREATE: bool = True

    #security
    JWT_ALGORITHM : str = "RS256"
    JWT_ACCESS_EXPIRE_MINUTE :  int = 15
    JWT_REFRESH_EXPIRE_DAYS: int = 7
    JWT_PRIVATE_KEY_PATH: str = str(Path("keys/private.pem"))
    JWT_PUBLIC_KEY_PATH: str = str(Path("keys/public.pem"))
    JWT_ISSUER: str = "d5-security-layer"
    JWT_AUDIENCE: str = "d5-gateway"
    AUTH_MAX_FAILED_ATTEMPTS: int = 5
    AUTH_LOCKOUT_MINUTES: int = 15

    # LangSmith (set in .env to enable)
    LANGSMITH_API_KEY: str = ""
    LANGSMITH_PROJECT: str = "d5-poc"

    # Guardrails
    # TOPIC_GUARD_MODE / LANGUAGE_GUARD_MODE: "warn" (log only) | "block" (reject request)
    GUARDRAIL_TOPIC_MODE: str = "warn"
    GUARDRAIL_LANGUAGE_MODE: str = "warn"
    # Hard ceiling on raw UTF-8 bytes in the input field (default 32 KB)
    GUARDRAIL_MAX_INPUT_BYTES: int = 32768
    # Whether to outright block base64/hex-encoded suspicious payloads
    GUARDRAIL_ENCODED_PAYLOAD_BLOCK: bool = True

    # LLM-based Guardrail Settings (Layer 5)
    LLM_GUARDRAIL_ENABLED: bool = True
    LLM_GUARDRAIL_PROVIDER: str = "gemini"    # "gemini" | "openai" | "ollama" | "mock"
    LLM_GUARDRAIL_API_KEY: str = ""           # GEMINI_API_KEY from environment
    LLM_GUARDRAIL_MODEL: str = "gemini-3.1-flash-lite"
    LLM_GUARDRAIL_MODE: str = "block"          # "block" | "warn"
    LLM_GUARDRAIL_TIMEOUT_SEC: float = 2.0     # Maximum execution timeout in seconds

    # Presidio PII/PHI Engine Settings
    PRESIDIO_ENABLED: bool = True                   # Master switch for Presidio NLP detection
    PRESIDIO_NLP_MODEL: str = "en_core_web_lg"      # spaCy model: "en_core_web_sm" | "en_core_web_lg" | "en_core_web_trf"
    PRESIDIO_MIN_SCORE: float = 0.6                 # Minimum confidence score to report a finding (0.0–1.0)
    PRESIDIO_ANONYMIZER_MODE: str = "replace"       # "replace" | "redact" | "hash"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}
    
settings = Settings()
