from pathlib import Path

from pydantic_settings import BaseSettings


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

    # CORS — comma-separated allowlist of origins; empty = same-origin only
    CORS_ALLOW_ORIGINS: str = ""

    # Server-level cap on the raw request body in bytes (reject early, before parsing)
    MAX_REQUEST_BODY_BYTES: int = 65536

    # Per-IP rate limits for credential endpoints (per-account lockout is separate)
    AUTH_LOGIN_RATE_LIMIT: str = "100/minute"
    AUTH_REFRESH_RATE_LIMIT: str = "30/minute"

    # Number of trusted reverse proxies in front of the gateway (0 = direct).
    # When > 0, rate limits key on the real client IP from X-Forwarded-For.
    TRUST_PROXY_COUNT: int = 0

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
    # Deny requests that omit explicit consent_granted=true (default-deny in prod)
    GUARDRAIL_CONSENT_DEFAULT_GRANTED: bool = False

    # LLM-based Guardrail Settings (Layer 5 – Ingress)
    LLM_GUARDRAIL_ENABLED: bool = True
    LLM_GUARDRAIL_PROVIDER: str = "gemini"    # "gemini" | "openai" | "ollama" | "mock"
    LLM_GUARDRAIL_API_KEY: str = ""           # GEMINI_API_KEY from environment
    LLM_GUARDRAIL_MODEL: str = "gemini-3.1-flash-lite"
    LLM_GUARDRAIL_MODE: str = "block"          # "block" | "warn"
    LLM_GUARDRAIL_TIMEOUT_SEC: float = 2.0     # Maximum execution timeout in seconds

    # ── Egress / Output Guardrails ──────────────────────────────────────────
    # Hard ceiling on raw UTF-8 bytes in the LLM output field (default 64 KB)
    GUARDRAIL_MAX_OUTPUT_BYTES: int = 65536
    # PHI leak guard: fires BEFORE mask_phi() as a forensic audit checkpoint
    # "warn" = log + pass (masker downstream handles it)  | "block" = hard stop
    GUARDRAIL_EGRESS_PHI_MODE: str = "warn"
    # Hallucination / citation grounding checks
    # "warn" = log + pass  |  "block" = suppress response
    GUARDRAIL_EGRESS_GROUNDING_MODE: str = "warn"
    # LLM-based semantic re-evaluation of the output (Layer 5 – Egress)
    GUARDRAIL_EGRESS_LLM_ENABLED: bool = True
    GUARDRAIL_EGRESS_LLM_MODE: str = "block"         # "block" | "warn"
    GUARDRAIL_EGRESS_LLM_MODEL: str = "gemini-3.1-flash-lite"
    GUARDRAIL_EGRESS_LLM_TIMEOUT_SEC: float = 2.0

    # Presidio PII/PHI Engine Settings
    PRESIDIO_ENABLED: bool = True                   # Master switch for Presidio NLP detection
    PRESIDIO_NLP_MODEL: str = "en_core_web_lg"      # spaCy model: "en_core_web_sm" | "en_core_web_lg" | "en_core_web_trf"
    PRESIDIO_MIN_SCORE: float = 0.6                 # Minimum confidence score to report a finding (0.0–1.0)
    PRESIDIO_ANONYMIZER_MODE: str = "replace"       # "replace" | "redact" | "hash"

    # D3 Egress — timeout, retry, circuit breaker
    D3_TIMEOUT_SEC: float = 5.0                     # Per-attempt timeout for the D3 call
    D3_MAX_RETRIES: int = 2                         # Additional attempts after the first (exponential backoff)
    D3_RETRY_BASE_DELAY_SEC: float = 0.25           # First backoff base (doubles per retry)
    D3_CIRCUIT_FAILURE_THRESHOLD: int = 5           # Consecutive failures before the breaker opens
    D3_CIRCUIT_RESET_SEC: float = 30.0              # Time in open state before a half-open probe

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}
    
settings = Settings()
