# controllers/scan_controller.py
"""
Scan business logic.

Responsibilities:
  - Enforce scan limits before any processing
  - Orchestrate the full scan pipeline (sanitize → detect → AI → save → respond)
  - Provide scan history and statistics for the authenticated user
  - Never touch Stripe, Auth, or Subscription concerns

Two scan types supported:
  scan_text() — suspicious text message analysis
  scan_url()  — URL safety analysis

Both follow the same 7-step pipeline for consistency.
"""
import logging
import time
from typing import Optional

from fastapi import HTTPException, status

from database.models import User, ScamCategory, ScanType
from repositories import user_repo, scan_repo
from schemas.scan import ScanResponse, ScanHistoryItem
from services import ai_service
from services.url_security_service import check_url, UrlCheckResult
from services.text_scan_service import check_text
from utils.helpers import (
    sanitize_text,
    sanitize_url,
    build_scan_response,
    scan_record_to_history_item,
)

logger = logging.getLogger("scam_detector.scan")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _enforce_scan_limit(user: User) -> None:
    """
    Raises 402 Payment Required if the user has no scans left.
    Called at the very start of every pipeline — nothing runs past this gate.
    """
    if user.scans_remaining <= 0:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                "You have used all your scans. "
                "Please subscribe to continue scanning."
            ),
        )


def _enforce_input_length(text: str, max_len: int, field: str) -> None:
    """
    Raises 400 if the input exceeds the allowed length after sanitization.
    Acts as a last-resort guard after schema-level validation.
    Prevents oversized inputs from reaching AI or pattern detection.
    """
    if len(text) > max_len:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} exceeds maximum allowed length of {max_len} characters.",
        )


def _to_scam_category(value: str) -> ScamCategory:
    """
    Safely converts an AI-returned string to a ScamCategory enum.
    Falls back to ScamCategory.NONE if the value is unrecognized.
    Prevents invalid strings from reaching the database.
    """
    try:
        return ScamCategory(value)
    except ValueError:
        logger.warning(f"Unrecognized scam_category from AI: '{value}' — defaulting to NONE.")
        return ScamCategory.NONE


def _log_scan_complete(scan_type: str, user_id: str, start: float, verdict: str) -> None:
    """Logs scan completion with duration for performance monitoring."""
    ms = (time.perf_counter() - start) * 1000
    logger.info(
        f"{scan_type.upper()} scan complete | "
        f"user={user_id} | "
        f"verdict={verdict} | "
        f"duration={ms:.0f}ms"
    )


# ── Text scan pipeline ─────────────────────────────────────────────────────────

async def scan_text(message: str, user: User) -> ScanResponse:
    """
    Full text scan pipeline:
      1. Enforce scan limit       — gate, raises 402 if exhausted
      2. Sanitize input           — strip/collapse whitespace
      3. Enforce length guard     — max 2000 chars after sanitization
      4. Pattern detection        — fast regex pre-screen (text_security_service)
      5. AI analysis              — Claude AI with flag context (ai_service)
      6. Atomic scan deduction    — MongoDB $inc (user_repo)
      7. Persist scan record      — for analytics and history (scan_repo)
      8. Return structured result

    Scan is deducted AFTER AI analysis — if AI returns a fallback due to
    an error, the scan is still deducted because a valid request was made
    and a response was returned to the user.
    """
    _enforce_scan_limit(user)
    start = time.perf_counter()

    # Sanitize then guard length
    message = sanitize_text(message)
    _enforce_input_length(message, max_len=2000, field="message")

    # Pattern detection — fast, offline, no network
    flags = check_text(message)
    logger.info(
        f"Text scan started | user={user.id} | "
        f"flags={flags if flags else 'none'}"
    )

    # AI analysis — async network call to Anthropic
    ai_result = await ai_service.analyze_text(
        message=message,
        rule_flags=flags,
    )

    # Atomic deduction — $inc prevents race conditions
    user = await user_repo.deduct_scan(user)

    # Persist scan record for data collection / history
    await scan_repo.create_text_scan(
        user_id=str(user.id),
        input_text=message,
        rule_triggered=len(flags) > 0,
        rule_flags=flags,
        verdict=ai_result["verdict"],
        reason=ai_result["reason"],
        advice=ai_result["advice"],
        scam_category=_to_scam_category(ai_result.get("scam_category", "none")),
    )

    _log_scan_complete("text", str(user.id), start, ai_result["verdict"])
    return build_scan_response(ai_result, user.scans_remaining)


# ── URL scan pipeline ──────────────────────────────────────────────────────────

async def scan_url(url: str, user: User) -> ScanResponse:
    """
    Full URL scan pipeline:
      1. Enforce scan limit       — gate, raises 402 if exhausted
      2. Sanitize URL             — strip whitespace, ensure scheme
      3. Enforce length guard     — max 2083 chars (IE/browser URL limit)
      4. Two-layer URL check      — local patterns + Google Safe Browsing
      5. AI analysis              — Claude AI with full security context
      6. Atomic scan deduction    — MongoDB $inc (user_repo)
      7. Persist scan record      — for analytics and history (scan_repo)
      8. Return structured result

    UrlCheckResult carries both local flag results and Safe Browsing results.
    Both are passed to the AI for the most informed verdict.
    """
    _enforce_scan_limit(user)
    start = time.perf_counter()

    # Sanitize then guard length (2083 = max URL length supported by IE/browsers)
    url = sanitize_url(url)
    _enforce_input_length(url, max_len=2083, field="url")

    # Two-layer URL security check
    url_result: UrlCheckResult = await check_url(url)
    logger.info(
        f"URL scan started | user={user.id} | "
        f"sb_flagged={url_result.safe_browsing_flagged} | "
        f"local_flagged={url_result.local_suspicious} | "
        f"local_flags={url_result.local_flags if url_result.local_flags else 'none'} | "
        f"sb_error={url_result.safe_browsing_error}"
    )

    # AI analysis — receives full context from both security layers
    ai_result = await ai_service.analyze_url(
        url=url,
        safe_browsing_flagged=url_result.safe_browsing_flagged,
        threat_type=url_result.primary_threat,
    )

    # Atomic deduction
    user = await user_repo.deduct_scan(user)

    # Persist scan record
    await scan_repo.create_url_scan(
        user_id=str(user.id),
        input_url=url,
        safe_browsing_flagged=url_result.safe_browsing_flagged,
        safe_browsing_threat_type=url_result.safe_browsing_threat,
        verdict=ai_result["verdict"],
        reason=ai_result["reason"],
        advice=ai_result["advice"],
        scam_category=_to_scam_category(ai_result.get("scam_category", "none")),
    )

    _log_scan_complete("url", str(user.id), start, ai_result["verdict"])
    return build_scan_response(ai_result, user.scans_remaining)


# ── Scan history & stats ───────────────────────────────────────────────────────

async def get_scan_history(
    user: User,
    limit: int = 20,
    skip: int = 0,
    scan_type: Optional[ScanType] = None,
) -> list[ScanHistoryItem]:
    """
    Returns the authenticated user's scan history with pagination.

    Args:
        user:      The authenticated user (injected by middleware).
        limit:     Max records per page (default 20, hard-capped at 100 in repo).
        skip:      Records to skip — page 2 = skip 20, page 3 = skip 40.
        scan_type: Optional filter — ScanType.TEXT or ScanType.URL.

    Called by: routes/scan.py → GET /scan/history
    """
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit must be between 1 and 100.",
        )
    if skip < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="skip must be 0 or greater.",
        )

    records = await scan_repo.get_by_user(
        user_id=str(user.id),
        limit=limit,
        skip=skip,
        scan_type=scan_type,
    )
    return [scan_record_to_history_item(r) for r in records]


async def get_scan_stats(user: User) -> dict:
    """
    Returns aggregated scan statistics for the authenticated user.
    Called by: routes/scan.py → GET /scan/stats
    """
    return await scan_repo.get_stats_by_user(str(user.id))


async def get_scan_by_id(record_id: str, user: User) -> ScanHistoryItem:
    """
    Returns a single scan record by ID — only if it belongs to the requesting user.
    Raises 404 if not found, 403 if the record belongs to a different user.
    Called by: routes/scan.py → GET /scan/{record_id}
    """
    record = await scan_repo.get_by_id(record_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    # Ownership check — users can only access their own scan records
    if record.user_id != str(user.id):
        logger.warning(
            f"Unauthorized scan access | "
            f"user={user.id} attempted to access record={record_id} "
            f"owned by user={record.user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this scan record.",
        )

    return scan_record_to_history_item(record)