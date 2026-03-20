# schemas/scan.py
from pydantic import BaseModel, Field, field_validator, AnyHttpUrl
from pydantic import model_config as pydantic_model_config
from typing import Optional
from datetime import datetime
from database.models import ScanType, ScamCategory


# ── Request Schemas ────────────────────────────────────────────────────────────

class TextScanRequest(BaseModel):
    """
    Request body for POST /scan/text.
    Validates that the message is a non-empty string within a safe length limit.
    """
    model_config = pydantic_model_config(str_strip_whitespace=True)

    message: str = Field(
        ...,
        min_length=5,
        max_length=2000,
        description="The suspicious text message to analyze.",
        examples=["URGENT: Your SBI account has been blocked. Share your OTP to restore access."],
    )

    @field_validator("message")
    @classmethod
    def message_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be blank.")
        return v


class UrlScanRequest(BaseModel):
    """
    Request body for POST /scan/url.
    Validates that the input is a well-formed HTTP/HTTPS URL.
    """
    model_config = pydantic_model_config(str_strip_whitespace=True)

    url: AnyHttpUrl = Field(
        ...,
        description="The suspicious URL to analyze.",
        examples=["http://fake-sbi-login.xyz/verify-kyc"],
    )

    @field_validator("url", mode="before")
    @classmethod
    def url_must_have_valid_scheme(cls, v: str) -> str:
        v = str(v).strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# ── Response Schemas ───────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """
    Returned after every successful scan (text or URL).
    Contains the AI verdict, explanation, user advice, and updated scan count.
    """
    verdict:          str            # e.g. "Likely Scam" | "⚠️ Dangerous Website" | "Likely Safe"
    reason:           str            # 1-2 sentence explanation
    advice:           str            # short action for the user
    scans_remaining:  int = Field(ge=0)


class ScanHistoryItem(BaseModel):
    """
    A single scan record — used for future GET /scan/history endpoint.
    Safe to return to the client (no internal IDs exposed beyond scan_id).
    """
    model_config = pydantic_model_config(from_attributes=True)

    scan_id:                    str
    scan_type:                  ScanType                    # "text" | "url"
    input_text:                 Optional[str]   = None
    input_url:                  Optional[str]   = None
    verdict:                    str
    reason:                     str
    advice:                     str
    scam_category:              Optional[ScamCategory] = None
    rule_flags:                 list[str]       = Field(default_factory=list)
    safe_browsing_flagged:      bool            = False
    scanned_at:                 datetime