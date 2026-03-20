# database/models.py
from beanie import Document, Indexed
from pydantic import EmailStr, Field, field_validator
from typing import Optional, Literal
from datetime import datetime, timezone
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────────

class PlanType(str, Enum):
    FREE     = "free"
    MONTHLY  = "monthly"
    BIANNUAL = "biannual"
    YEARLY   = "yearly"


class ScanType(str, Enum):
    TEXT = "text"
    URL  = "url"


class ScamCategory(str, Enum):
    PHISHING           = "phishing"
    OTP_FRAUD          = "otp_fraud"
    IMPERSONATION      = "impersonation"
    MONEY_REQUEST      = "money_request"
    FAKE_PRIZE         = "fake_prize"
    JOB_SCAM           = "job_scam"
    MALWARE            = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    UNWANTED_SOFTWARE  = "unwanted_software"
    NONE               = "none"


# ── User ───────────────────────────────────────────────────────────────────────

class User(Document):
    """
    Represents an authenticated user.
    Indexed fields: email, google_id, stripe_customer_id
    — all are used as lookup keys in repositories.
    """
    email:                   Indexed(EmailStr, unique=True)
    google_id:               Indexed(str, unique=True)
    name:                    str
    avatar:                  Optional[str] = None

    plan:                    PlanType = PlanType.FREE
    scans_remaining:         int = 7

    stripe_customer_id:      Optional[Indexed(str)] = None  # type: ignore[valid-type]
    stripe_subscription_id:  Optional[str] = None

    is_active:               bool = True

    # Use Field(default_factory=...) to avoid shared mutable datetime default
    created_at:              datetime = Field(
                                 default_factory=lambda: datetime.now(timezone.utc)
                             )

    @field_validator("scans_remaining")
    @classmethod
    def scans_must_not_be_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("scans_remaining cannot be negative.")
        return v

    class Settings:
        name = "users"                  # MongoDB collection name
        use_state_management = True     # enables .save() to only update changed fields


# ── ScanRecord ─────────────────────────────────────────────────────────────────

class ScanRecord(Document):
    """
    Stores every scan result for analytics and future model training.
    Indexed on user_id for fast per-user history lookups.
    """
    user_id:                    Indexed(str)            # type: ignore[valid-type]
    scan_type:                  ScanType

    # Raw input — one will be set, the other None depending on scan_type
    input_text:                 Optional[str] = None
    input_url:                  Optional[str] = None

    # Rule engine output
    rule_triggered:             bool = False
    rule_flags:                 list[str] = Field(default_factory=list)

    # Safe Browsing output (URL scans only)
    safe_browsing_flagged:      bool = False
    safe_browsing_threat_type:  Optional[str] = None

    # AI output
    verdict:                    str
    reason:                     str
    advice:                     str
    scam_category:              Optional[ScamCategory] = None

    scanned_at:                 datetime = Field(
                                    default_factory=lambda: datetime.now(timezone.utc)
                                )

    class Settings:
        name = "scan_records"           # MongoDB collection name