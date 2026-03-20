# services/url_security_service.py
"""
URL security checking service.

Two-layer approach:
  Layer 1 — Local pattern check (instant, no API call)
             Catches obvious threats: IP-based URLs, suspicious TLDs,
             URL shorteners, and known phishing URL structures.

  Layer 2 — Google Safe Browsing API v4 (authoritative, network call)
             Checks against Google's live threat database.

The scan_controller calls check_url() and gets back a UrlCheckResult
containing both layers' findings. The AI service then uses this context.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx

from config.settings import settings

logger = logging.getLogger("scam_detector.url_security")


# ── Constants ──────────────────────────────────────────────────────────────────

_SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Threat severity order — used to pick the most severe when multiple matches exist
_THREAT_SEVERITY: dict[str, int] = {
    "MALWARE":                        4,
    "SOCIAL_ENGINEERING":             3,    # phishing
    "POTENTIALLY_HARMFUL_APPLICATION": 2,
    "UNWANTED_SOFTWARE":              1,
}

# Suspicious TLDs commonly used in scam/phishing sites
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".click", ".link", ".work", ".loan", ".win", ".download",
}

# URL shorteners — hide the real destination
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "shorturl.at",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

# Path keywords common in phishing URLs
_PHISHING_PATH_PATTERNS = re.compile(
    r"/(login|verify|secure|update|confirm|account|banking|"
    r"password|reset|validate|authenticate|signin|paypal|sbi|"
    r"hdfc|icici|amazon|flipkart)",
    re.IGNORECASE,
)


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class UrlCheckResult:
    """
    Structured result from check_url().
    Consumed by scan_controller and passed to ai_service for context.
    """
    url:                    str

    # Layer 1 — local pattern checks
    local_suspicious:       bool            = False
    local_flags:            list[str]       = field(default_factory=list)

    # Layer 2 — Google Safe Browsing
    safe_browsing_flagged:  bool            = False
    safe_browsing_threat:   Optional[str]   = None  # e.g. "MALWARE"
    safe_browsing_error:    bool            = False  # True if API call failed

    @property
    def is_flagged(self) -> bool:
        """True if either layer flagged the URL."""
        return self.safe_browsing_flagged or self.local_suspicious

    @property
    def primary_threat(self) -> Optional[str]:
        """
        Returns the most informative threat label.
        Prefers Safe Browsing result (authoritative) over local flags.
        """
        if self.safe_browsing_threat:
            return self.safe_browsing_threat
        if self.local_flags:
            return self.local_flags[0]
        return None


# ── Layer 1: Local pattern checks ─────────────────────────────────────────────

def _run_local_checks(url: str) -> Tuple[bool, list[str]]:
    """
    Fast synchronous checks against known suspicious URL patterns.
    Runs before the Safe Browsing API call — catches obvious threats instantly.

    Returns (is_suspicious, list_of_flags)
    """
    flags = []

    try:
        parsed = urlparse(url)
        host   = parsed.netloc.lower()
        path   = parsed.path.lower()
    except Exception:
        return False, []

    # Check 1: IP address as host (legitimate sites use domain names)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host):
        flags.append("ip_based_url")

    # Check 2: Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            flags.append(f"suspicious_tld:{tld}")
            break

    # Check 3: Known URL shortener (hides real destination)
    base_host = host.removeprefix("www.")
    if base_host in _URL_SHORTENERS:
        flags.append("url_shortener")

    # Check 4: Phishing path keywords
    if _PHISHING_PATH_PATTERNS.search(path):
        flags.append("phishing_path_keyword")

    # Check 5: Excessive subdomains (e.g. sbi.login.verify.malicious.com)
    subdomain_parts = host.split(".")
    if len(subdomain_parts) > 4:
        flags.append("excessive_subdomains")

    # Check 6: Misleading brand name in subdomain (e.g. sbi.malicious.com)
    known_brands = {"sbi", "hdfc", "icici", "paytm", "amazon", "flipkart", "paypal", "google"}
    if len(subdomain_parts) > 2:
        subdomains = subdomain_parts[:-2]   # everything except the registered domain
        for brand in known_brands:
            if brand in subdomains:
                flags.append(f"brand_impersonation:{brand}")
                break

    is_suspicious = len(flags) > 0
    if is_suspicious:
        logger.info(f"Local check flagged URL: {url} | flags={flags}")

    return is_suspicious, flags


# ── Layer 2: Google Safe Browsing API ─────────────────────────────────────────

async def _call_safe_browsing(url: str) -> Tuple[bool, Optional[str], bool]:
    """
    Calls Google Safe Browsing API v4.

    Returns:
        (is_flagged, threat_type, api_error)
        api_error=True means the call failed — caller should log and fail-open.
    """
    payload = {
        "client": {
            "clientId":      "scam-detector",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes":      _THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _SAFE_BROWSING_ENDPOINT,
                params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload,
            )

        if resp.status_code == 400:
            logger.warning(f"Safe Browsing 400 Bad Request — likely invalid URL format: {url}")
            return False, None, False    # not an API error — URL just wasn't checkable

        if resp.status_code == 403:
            logger.error("Safe Browsing API key invalid or quota exceeded.")
            return False, None, True

        if resp.status_code != 200:
            logger.warning(f"Safe Browsing unexpected HTTP {resp.status_code} for URL: {url}")
            return False, None, True

        matches = resp.json().get("matches", [])
        if not matches:
            return False, None, False

        # Pick the most severe threat if multiple matches are returned
        best_match = max(
            matches,
            key=lambda m: _THREAT_SEVERITY.get(m.get("threatType", ""), 0),
        )
        threat_type = best_match.get("threatType", "UNKNOWN")
        logger.info(f"Safe Browsing flagged URL: {url} | threat={threat_type}")
        return True, threat_type, False

    except httpx.TimeoutException:
        logger.warning(f"Safe Browsing API timed out for URL: {url}")
        return False, None, True

    except httpx.RequestError as e:
        logger.error(f"Safe Browsing network error: {e}")
        return False, None, True

    except Exception as e:
        logger.error(f"Safe Browsing unexpected error: {e}")
        return False, None, True


# ── Public API ─────────────────────────────────────────────────────────────────

async def check_url(url: str) -> UrlCheckResult:
    """
    Runs both security layers against the given URL.

    Layer 1 (local) always runs — instant, no network.
    Layer 2 (Safe Browsing) always runs — authoritative, async network call.

    Both layers run regardless of each other's result so the AI gets
    the fullest possible context.

    Fail-open: if Safe Browsing API errors, we still return local results
    and set safe_browsing_error=True so the AI knows the check was incomplete.
    """
    result = UrlCheckResult(url=url)

    # Layer 1: local pattern check (synchronous, instant)
    result.local_suspicious, result.local_flags = _run_local_checks(url)

    # Layer 2: Google Safe Browsing (async, network)
    (
        result.safe_browsing_flagged,
        result.safe_browsing_threat,
        result.safe_browsing_error,
    ) = await _call_safe_browsing(url)

    if result.safe_browsing_error:
        logger.warning(
            f"Safe Browsing unavailable for {url}. "
            f"Decision based on local checks only: flagged={result.local_suspicious}"
        )

    return result