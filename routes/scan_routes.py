# routes/scan_routes.py
"""
Scan routes — thin HTTP layer only.

Rule: No business logic here. Every route does exactly three things:
  1. Declare the endpoint (method, path, response model, status code)
  2. Inject dependencies (auth middleware, query params, request body)
  3. Call the controller and return its result

All logic lives in controllers/scan_controller.py.

Endpoints:
  POST /scan/text          — analyze a suspicious text message
  POST /scan/url           — analyze a suspicious URL
  GET  /scan/history       — paginated scan history for current user
  GET  /scan/stats         — scan statistics for current user
  GET  /scan/{record_id}   — single scan record by ID
"""
from fastapi import APIRouter, Depends, Query, status
from typing import Optional

from schemas.scan import (
    TextScanRequest,
    UrlScanRequest,
    ScanResponse,
    ScanHistoryItem,
)
from controllers.scan_controller import (
    scan_text,
    scan_url,
    get_scan_history,
    get_scan_stats,
    get_scan_by_id,
)
from database.models import User, ScanType
from middleware.auth_middleware import get_current_user

router = APIRouter(prefix="/scan", tags=["Scanning"])


# ── POST /scan/text ────────────────────────────────────────────────────────────

@router.post(
    "/text",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a suspicious text message",
    description="""
Analyzes a text message for scam indicators using two layers:

**Layer 1 — Pattern detection** (instant, offline)
Checks for: urgent language, OTP requests, suspicious links,
bank/authority impersonation, money requests.

**Layer 2 — Claude AI analysis**
Claude receives the message and the pattern flags as context
and returns a structured verdict.

**Scan pipeline:**
`limit check → sanitize → pattern detect → AI analyze → deduct scan → save record`

**Returns 402** if the user has no scans remaining — subscribe to continue.

**Verdicts returned:**
- `Likely Scam` — high confidence scam
- `Possibly Suspicious` — treat with caution
- `Likely Safe` — no strong indicators found
    """,
    responses={
        200: {"description": "Scan completed successfully"},
        402: {"description": "No scans remaining — subscription required"},
        422: {"description": "Validation error — message too short or too long"},
    },
)
async def scan_text_route(
    body: TextScanRequest,
    current_user: User = Depends(get_current_user),
):
    return await scan_text(message=body.message, user=current_user)


# ── POST /scan/url ─────────────────────────────────────────────────────────────

@router.post(
    "/url",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a suspicious URL",
    description="""
Analyzes a URL for safety using two layers:

**Layer 1 — Local pattern checks** (instant, offline)
Checks for: IP-based URLs, suspicious TLDs (.xyz, .tk, .ml),
URL shorteners, phishing path keywords, excessive subdomains,
brand impersonation in subdomains.

**Layer 2 — Google Safe Browsing API**
Checks against Google's live threat database for malware,
phishing, unwanted software, and harmful apps.

**Claude AI** then analyzes the URL with full context from both layers.

**Scan pipeline:**
`limit check → sanitize → local check + Safe Browsing → AI analyze → deduct scan → save record`

**Returns 402** if the user has no scans remaining — subscribe to continue.

**Verdicts returned:**
- `⚠️ Dangerous Website` — confirmed threat (Safe Browsing or AI)
- `Suspicious Website` — treat with caution
- `Likely Safe` — no threats detected
    """,
    responses={
        200: {"description": "Scan completed successfully"},
        402: {"description": "No scans remaining — subscription required"},
        422: {"description": "Validation error — invalid URL format"},
    },
)
async def scan_url_route(
    body: UrlScanRequest,
    current_user: User = Depends(get_current_user),
):
    return await scan_url(url=str(body.url), user=current_user)


# ── GET /scan/history ──────────────────────────────────────────────────────────

@router.get(
    "/history",
    response_model=list[ScanHistoryItem],
    status_code=status.HTTP_200_OK,
    summary="Get scan history",
    description="""
Returns the authenticated user's scan history, sorted newest first.

Supports pagination via `limit` and `skip`, and optional filtering by scan type.

**Examples:**
- First 20 scans: `GET /scan/history`
- Next 20 scans:  `GET /scan/history?skip=20`
- Text scans only: `GET /scan/history?scan_type=text`
- URL scans only:  `GET /scan/history?scan_type=url`
    """,
)
async def get_history(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Number of records to return (1–100).",
    ),
    skip: int = Query(
        default=0,
        ge=0,
        description="Number of records to skip for pagination.",
    ),
    scan_type: Optional[ScanType] = Query(
        default=None,
        description="Filter by scan type: `text` or `url`. Omit for all.",
    ),
    current_user: User = Depends(get_current_user),
):
    return await get_scan_history(
        user=current_user,
        limit=limit,
        skip=skip,
        scan_type=scan_type,
    )


# ── GET /scan/stats ────────────────────────────────────────────────────────────

@router.get(
    "/stats",
    status_code=status.HTTP_200_OK,
    summary="Get scan statistics",
    description="""
Returns aggregated scan statistics for the authenticated user.

**Response shape:**
```json
{
  "total":       25,
  "text_scans":  18,
  "url_scans":    7,
  "scams_found": 11
}
```
    """,
)
async def get_stats(current_user: User = Depends(get_current_user)):
    return await get_scan_stats(user=current_user)


# ── GET /scan/{record_id} ──────────────────────────────────────────────────────

@router.get(
    "/{record_id}",
    response_model=ScanHistoryItem,
    status_code=status.HTTP_200_OK,
    summary="Get a single scan record",
    description="""
Returns a single scan record by its ID.

**Ownership enforced** — users can only access their own scan records.
Returns `403 Forbidden` if the record belongs to a different user.
Returns `404 Not Found` if the record does not exist.
    """,
    responses={
        200: {"description": "Scan record found"},
        403: {"description": "Record belongs to a different user"},
        404: {"description": "Scan record not found"},
    },
)
async def get_single_scan(
    record_id: str,
    current_user: User = Depends(get_current_user),
):
    return await get_scan_by_id(record_id=record_id, user=current_user)