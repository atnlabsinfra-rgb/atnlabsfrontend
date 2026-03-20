# repositories/scan_repo.py
"""
All database read/write operations for the ScanRecord collection.

Rule: Controllers never call ScanRecord.find / ScanRecord.insert directly.
All MongoDB access for scan records goes through this file.
"""
import logging
from typing import Optional
from datetime import datetime

from database.models import ScanRecord, ScanType, ScamCategory

logger = logging.getLogger("scam_detector.scan_repo")


# ── Writes ─────────────────────────────────────────────────────────────────────

async def create_text_scan(
    user_id: str,
    input_text: str,
    rule_triggered: bool,
    rule_flags: list[str],
    verdict: str,
    reason: str,
    advice: str,
    scam_category: Optional[ScamCategory],
) -> ScanRecord:
    """
    Persists a completed text scan result.
    Called by scan_controller after AI analysis and scan deduction.
    """
    record = ScanRecord(
        user_id=user_id,
        scan_type=ScanType.TEXT,
        input_text=input_text,
        rule_triggered=rule_triggered,
        rule_flags=rule_flags,
        verdict=verdict,
        reason=reason,
        advice=advice,
        scam_category=scam_category,
    )
    await record.insert()
    logger.debug(
        f"Text scan saved | user_id={user_id} | "
        f"verdict={verdict} | flags={rule_flags}"
    )
    return record


async def create_url_scan(
    user_id: str,
    input_url: str,
    safe_browsing_flagged: bool,
    safe_browsing_threat_type: Optional[str],
    verdict: str,
    reason: str,
    advice: str,
    scam_category: Optional[ScamCategory],
) -> ScanRecord:
    """
    Persists a completed URL scan result.
    Called by scan_controller after AI analysis and scan deduction.
    """
    record = ScanRecord(
        user_id=user_id,
        scan_type=ScanType.URL,
        input_url=input_url,
        safe_browsing_flagged=safe_browsing_flagged,
        safe_browsing_threat_type=safe_browsing_threat_type,
        verdict=verdict,
        reason=reason,
        advice=advice,
        scam_category=scam_category,
    )
    await record.insert()
    logger.debug(
        f"URL scan saved | user_id={user_id} | "
        f"verdict={verdict} | sb_flagged={safe_browsing_flagged}"
    )
    return record


# ── Reads ──────────────────────────────────────────────────────────────────────

async def get_by_user(
    user_id: str,
    limit: int = 20,
    skip: int = 0,
    scan_type: Optional[ScanType] = None,
) -> list[ScanRecord]:
    """
    Fetch a user's scan history with pagination and optional type filter.

    Args:
        user_id:   Filter records to this user only.
        limit:     Max records to return (default 20, capped at 100).
        skip:      Number of records to skip — used for pagination.
        scan_type: Optional filter — ScanType.TEXT or ScanType.URL.

    Returns newest scans first (sorted by scanned_at descending).
    """
    limit = min(limit, 100)     # hard cap — prevent pulling thousands of records

    query = ScanRecord.find(ScanRecord.user_id == user_id)

    if scan_type is not None:
        query = query.find(ScanRecord.scan_type == scan_type)

    return (
        await query
        .sort(-ScanRecord.scanned_at)   # newest first
        .skip(skip)
        .limit(limit)
        .to_list()
    )


async def get_by_id(record_id: str) -> Optional[ScanRecord]:
    """Fetch a single scan record by its document ID."""
    try:
        return await ScanRecord.get(record_id)
    except Exception:
        logger.warning(f"get_by_id failed for record_id={record_id}")
        return None


async def count_by_user(user_id: str) -> int:
    """Returns the total number of scans performed by a user."""
    return await ScanRecord.find(ScanRecord.user_id == user_id).count()


async def get_stats_by_user(user_id: str) -> dict:
    """
    Returns a summary of a user's scan activity.
    Used for a future dashboard/stats endpoint.

    Returns:
        {
            "total":        int,   # all scans ever
            "text_scans":   int,   # text-only count
            "url_scans":    int,   # url-only count
            "scams_found":  int,   # scans where verdict contains "Scam" or "Dangerous"
        }
    """
    all_records = await ScanRecord.find(ScanRecord.user_id == user_id).to_list()

    total       = len(all_records)
    text_scans  = sum(1 for r in all_records if r.scan_type == ScanType.TEXT)
    url_scans   = sum(1 for r in all_records if r.scan_type == ScanType.URL)
    scams_found = sum(
        1 for r in all_records
        if "scam" in r.verdict.lower() or "dangerous" in r.verdict.lower()
    )

    return {
        "total":       total,
        "text_scans":  text_scans,
        "url_scans":   url_scans,
        "scams_found": scams_found,
    }


async def get_recent_flagged(limit: int = 50) -> list[ScanRecord]:
    """
    Fetch the most recent scans flagged as scams across all users.
    For admin/analytics use only — never expose this to regular users.
    """
    limit = min(limit, 200)
    all_recent = (
        await ScanRecord.find()
        .sort(-ScanRecord.scanned_at)
        .limit(limit * 3)           # fetch extra then filter
        .to_list()
    )
    flagged = [
        r for r in all_recent
        if "scam" in r.verdict.lower() or "dangerous" in r.verdict.lower()
    ]
    return flagged[:limit]