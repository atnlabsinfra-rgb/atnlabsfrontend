# utils/helpers.py
"""
Pure utility functions shared across the app.
No business logic here — only reusable helpers that have no better home.

Sections:
  1. Logging setup
  2. Model → Schema conversion
  3. String & input sanitization
  4. Response builders
  5. Date & time helpers
"""
import logging
import sys
import re
from datetime import datetime, timezone
from typing import Optional

from database.models import User, ScanRecord
from schemas.user import UserOut
from schemas.scan import ScanResponse, ScanHistoryItem


# ── 1. Logging Setup ───────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO") -> None:
    """
    Configures app-wide logging with a consistent format.
    Called once at startup in main.py lifespan.

    Format: 2025-01-01 12:00:00 | INFO     | scam_detector.auth | User signed in
    """
    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers = [handler]   # replace any existing handlers — prevents duplicate logs

    # Silence noisy third-party libraries — their DEBUG/INFO logs are rarely useful
    for lib in ("motor", "httpx", "stripe", "anthropic", "urllib3", "google"):
        logging.getLogger(lib).setLevel(logging.WARNING)


# ── 2. Model → Schema Conversion ──────────────────────────────────────────────

def user_to_out(user: User) -> UserOut:
    """
    Converts a User Beanie document into a UserOut response schema.
    Centralised here so every controller uses the same mapping —
    no risk of one controller accidentally exposing a private field.
    """
    return UserOut(
        id=str(user.id),
        email=user.email,
        name=user.name,
        avatar=user.avatar,
        plan=user.plan,
        scans_remaining=user.scans_remaining,
        created_at=user.created_at,
    )


def scan_record_to_history_item(record: ScanRecord) -> ScanHistoryItem:
    """
    Converts a ScanRecord Beanie document into a ScanHistoryItem response schema.
    Used by the GET /scan/history endpoint (future).
    """
    return ScanHistoryItem(
        scan_id=str(record.id),
        scan_type=record.scan_type,
        input_text=record.input_text,
        input_url=record.input_url,
        verdict=record.verdict,
        reason=record.reason,
        advice=record.advice,
        scam_category=record.scam_category,
        rule_flags=record.rule_flags,
        safe_browsing_flagged=record.safe_browsing_flagged,
        scanned_at=record.scanned_at,
    )


def build_scan_response(ai_result: dict, scans_remaining: int) -> ScanResponse:
    """
    Builds a ScanResponse from an AI service result dict.
    Centralised here so scan_controller doesn't manually unpack the dict.
    """
    return ScanResponse(
        verdict=ai_result.get("verdict", "Unknown"),
        reason=ai_result.get("reason", ""),
        advice=ai_result.get("advice", ""),
        scans_remaining=scans_remaining,
    )


# ── 3. String & Input Sanitization ────────────────────────────────────────────

def sanitize_text(text: str, max_length: int = 2000) -> str:
    """
    Cleans a user-submitted text message before processing:
      - Strips leading/trailing whitespace
      - Collapses multiple consecutive whitespace into a single space
      - Truncates to max_length (safety net — schema validation should catch this first)
    """
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_length]


def sanitize_url(url: str) -> str:
    """
    Strips whitespace from a URL and ensures it has a scheme.
    Pydantic's AnyHttpUrl handles structural validation —
    this is a lightweight pre-clean before passing to Safe Browsing.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def mask_email(email: str) -> str:
    """
    Masks an email for safe logging: "john.doe@gmail.com" → "jo***@gmail.com"
    Use this whenever logging user identifiers to avoid PII in logs.
    """
    local, _, domain = email.partition("@")
    masked_local = local[:2] + "***" if len(local) > 2 else "***"
    return f"{masked_local}@{domain}"


# ── 4. Date & Time Helpers ────────────────────────────────────────────────────

def utc_now() -> datetime:
    """Returns the current UTC time as a timezone-aware datetime object."""
    return datetime.now(timezone.utc)


def format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """
    Formats a datetime to ISO 8601 string for consistent API responses.
    Returns None if dt is None.
    Example: "2025-01-15T10:30:00+00:00"
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)    # treat naive datetimes as UTC
    return dt.isoformat()