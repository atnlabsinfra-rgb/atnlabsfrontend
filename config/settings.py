# config/settings.py
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,        # env var names are matched exactly
        extra="ignore",             # ignore unknown vars in .env silently
    )

    # ── App ───────────────────────────────────────────────────────────────────
    APP_NAME: str = "ScamDetectorAPI"
    DEBUG: bool = False

    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440         # 24 hours

    # ── MongoDB ───────────────────────────────────────────────────────────────
    MONGO_URI: str
    MONGO_DB_NAME: str

    # ── Google OAuth2 — user login ────────────────────────────────────────────
    GOOGLE_CLIENT_ID: str

    # ── Google Safe Browsing — URL scanning ───────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str

    # ── Anthropic Claude — AI analysis ───────────────────────────────────────
    ANTHROPIC_API_KEY: str

    # ── Stripe — payments ─────────────────────────────────────────────────────
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str
    STRIPE_MONTHLY_PRICE_ID: str
    STRIPE_BIANNUAL_PRICE_ID: str
    STRIPE_YEARLY_PRICE_ID: str

    # ── Scan limits per plan ──────────────────────────────────────────────────
    FREE_SCAN_LIMIT: int = 7
    MONTHLY_SCAN_LIMIT: int = 90
    BIANNUAL_SCAN_LIMIT: int = 600
    YEARLY_SCAN_LIMIT: int = 1200

    # ── Validators ────────────────────────────────────────────────────────────
    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long.")
        return v

    @field_validator("ALGORITHM")
    @classmethod
    def algorithm_must_be_valid(cls, v: str) -> str:
        allowed = {"HS256", "HS384", "HS512"}
        if v not in allowed:
            raise ValueError(f"ALGORITHM must be one of {allowed}.")
        return v

    @field_validator("ACCESS_TOKEN_EXPIRE_MINUTES")
    @classmethod
    def expire_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer.")
        return v


# ── Singleton instance ─────────────────────────────────────────────────────────
# Import this everywhere: from config.settings import settings
settings = Settings()


# ── Derived lookup tables ──────────────────────────────────────────────────────
# Built once at startup from the validated settings object.

PLAN_SCAN_LIMITS: dict[str, int] = {
    "free":     settings.FREE_SCAN_LIMIT,
    "monthly":  settings.MONTHLY_SCAN_LIMIT,
    "biannual": settings.BIANNUAL_SCAN_LIMIT,
    "yearly":   settings.YEARLY_SCAN_LIMIT,
}

PLAN_PRICE_IDS: dict[str, str] = {
    "monthly":  settings.STRIPE_MONTHLY_PRICE_ID,
    "biannual": settings.STRIPE_BIANNUAL_PRICE_ID,
    "yearly":   settings.STRIPE_YEARLY_PRICE_ID,
}