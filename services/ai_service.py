# services/ai_service.py
"""
Claude AI analysis service for text and URL scans.

Responsibilities:
  - Build prompts for text and URL analysis
  - Call the Anthropic API
  - Parse and validate the structured JSON response
  - Return a safe fallback if anything goes wrong

Always returns a dict with keys: verdict, reason, advice, scam_category
The caller (scan_controller) can always trust the return shape.
"""
import json
import logging
import re
from typing import Optional

import anthropic

from config.settings import settings
from database.models import ScamCategory

logger = logging.getLogger("scam_detector.ai")

# ── Client ─────────────────────────────────────────────────────────────────────
# Async client — non-blocking, works correctly inside FastAPI's event loop.
_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

# ── Model config ───────────────────────────────────────────────────────────────
_MODEL       = "claude-sonnet-4-20250514"
_MAX_TOKENS  = 350      # enough for verdict + 2 sentences + advice + category
_MAX_RETRIES = 2        # retry once on transient API errors before falling back

# ── Verdict constants ──────────────────────────────────────────────────────────
# Defined here so controllers/tests can import them instead of using magic strings.
VERDICT_LIKELY_SCAM    = "Likely Scam"
VERDICT_SUSPICIOUS     = "Possibly Suspicious"
VERDICT_LIKELY_SAFE    = "Likely Safe"
VERDICT_DANGEROUS_URL  = "⚠️ Dangerous Website"
VERDICT_SUSPICIOUS_URL = "Suspicious Website"

VALID_TEXT_VERDICTS = {VERDICT_LIKELY_SCAM, VERDICT_SUSPICIOUS, VERDICT_LIKELY_SAFE}
VALID_URL_VERDICTS  = {VERDICT_DANGEROUS_URL, VERDICT_SUSPICIOUS_URL, VERDICT_LIKELY_SAFE}

# ── Fallback responses ─────────────────────────────────────────────────────────
# Returned when the API call fails or returns unparseable output.
# Always safe to show to the user.
_TEXT_FALLBACK = {
    "verdict":       VERDICT_SUSPICIOUS,
    "reason":        "This message could not be fully analyzed. Treat it with caution.",
    "advice":        "Do not click any links or share personal information.",
    "scam_category": ScamCategory.NONE.value,
}

_URL_FALLBACK = {
    "verdict":       VERDICT_SUSPICIOUS_URL,
    "reason":        "This URL could not be fully analyzed. Proceed with caution.",
    "advice":        "Do not enter any personal information on this website.",
    "scam_category": ScamCategory.NONE.value,
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _extract_json(raw: str) -> dict:
    """
    Extracts and parses a JSON object from Claude's raw response.

    Handles three formats Claude might return despite being told not to:
      1. Plain JSON           → {"verdict": ...}
      2. Markdown code block  → ```json\n{"verdict": ...}\n```
      3. JSON embedded in prose → "Here is the result: {"verdict": ...}"
    """
    # Strip markdown fences
    clean = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()

    # Try direct parse first
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    # Try to extract just the JSON object using regex
    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON found in Claude response: {raw[:200]}")


def _validate_text_result(result: dict) -> dict:
    """
    Validates and sanitizes the AI result for a text scan.
    Falls back field-by-field so a partial result is still usable.
    """
    verdict = result.get("verdict", "")
    if verdict not in VALID_TEXT_VERDICTS:
        logger.warning(f"Unexpected text verdict from AI: '{verdict}' — defaulting.")
        verdict = VERDICT_SUSPICIOUS

    category = result.get("scam_category", ScamCategory.NONE.value)
    valid_categories = {c.value for c in ScamCategory}
    if category not in valid_categories:
        category = ScamCategory.NONE.value

    return {
        "verdict":       verdict,
        "reason":        str(result.get("reason", _TEXT_FALLBACK["reason"]))[:500],
        "advice":        str(result.get("advice", _TEXT_FALLBACK["advice"]))[:300],
        "scam_category": category,
    }


def _validate_url_result(result: dict) -> dict:
    """
    Validates and sanitizes the AI result for a URL scan.
    Falls back field-by-field so a partial result is still usable.
    """
    verdict = result.get("verdict", "")
    if verdict not in VALID_URL_VERDICTS:
        logger.warning(f"Unexpected URL verdict from AI: '{verdict}' — defaulting.")
        verdict = VERDICT_SUSPICIOUS_URL

    category = result.get("scam_category", ScamCategory.NONE.value)
    valid_categories = {c.value for c in ScamCategory}
    if category not in valid_categories:
        category = ScamCategory.NONE.value

    return {
        "verdict":       verdict,
        "reason":        str(result.get("reason", _URL_FALLBACK["reason"]))[:500],
        "advice":        str(result.get("advice", _URL_FALLBACK["advice"]))[:300],
        "scam_category": category,
    }


async def _call_claude(prompt: str, fallback: dict, scan_type: str) -> dict:
    """
    Calls the Anthropic API with retry logic.
    Retries up to _MAX_RETRIES times on transient errors.
    Returns the fallback dict if all attempts fail.
    """
    last_error = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = await _client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )

            raw = response.content[0].text.strip()

            # Log token usage for cost monitoring
            usage = response.usage
            logger.debug(
                f"Claude [{scan_type}] | attempt={attempt} | "
                f"input_tokens={usage.input_tokens} | "
                f"output_tokens={usage.output_tokens}"
            )

            return _extract_json(raw)

        except anthropic.RateLimitError as e:
            logger.warning(f"Claude rate limited (attempt {attempt}): {e}")
            last_error = e
            break   # no point retrying immediately on rate limit

        except anthropic.APIStatusError as e:
            logger.warning(f"Claude API error (attempt {attempt}): {e.status_code} {e.message}")
            last_error = e

        except (ValueError, json.JSONDecodeError) as e:
            logger.warning(f"Claude response parse error (attempt {attempt}): {e}")
            last_error = e

        except Exception as e:
            logger.error(f"Unexpected Claude error (attempt {attempt}): {e}")
            last_error = e

    logger.error(f"All Claude attempts failed for {scan_type} scan. Using fallback. Last error: {last_error}")
    return fallback


# ── Public API ─────────────────────────────────────────────────────────────────

async def analyze_text(message: str, rule_flags: list[str]) -> dict:
    """
    Analyzes a text message for scam indicators using Claude.

    Args:
        message:    The user-submitted message (already sanitized by controller).
        rule_flags: List of rule names triggered by the rule engine.
                    Passed to Claude as context to improve accuracy.

    Returns:
        { verdict, reason, advice, scam_category }
    """
    flags_str = ", ".join(rule_flags) if rule_flags else "none detected"

    prompt = f"""You are a scam detection assistant helping protect users from fraud.
Analyze the following message carefully.

Message:
\"\"\"
{message}
\"\"\"

Rule-based pre-screening flags: {flags_str}

Instructions:
- Consider the rule flags as hints, but make your own assessment.
- Be concise — reason and advice must each be 1-2 sentences maximum.
- reason explains WHY it is or isn't a scam.
- advice tells the user exactly what to DO.

Respond ONLY with this exact JSON structure, no markdown, no extra text:
{{
  "verdict": "Likely Scam" | "Possibly Suspicious" | "Likely Safe",
  "reason": "<1-2 sentences explaining your assessment>",
  "advice": "<1-2 sentences telling the user what to do>",
  "scam_category": "phishing" | "otp_fraud" | "impersonation" | "money_request" | "fake_prize" | "job_scam" | "none"
}}"""

    raw_result = await _call_claude(prompt, _TEXT_FALLBACK, "text")
    return _validate_text_result(raw_result)


async def analyze_url(
    url: str,
    safe_browsing_flagged: bool,
    threat_type: Optional[str],
) -> dict:
    """
    Analyzes a URL for safety using Claude, incorporating Safe Browsing context.

    Args:
        url:                    The URL to analyze.
        safe_browsing_flagged:  Whether Google Safe Browsing flagged this URL.
        threat_type:            The threat category from Safe Browsing (if flagged).

    Returns:
        { verdict, reason, advice, scam_category }
    """
    if safe_browsing_flagged:
        sb_context = (
            f"⚠️ IMPORTANT: Google Safe Browsing has flagged this URL as: {threat_type}. "
            f"Weight this heavily in your assessment."
        )
    else:
        sb_context = "Google Safe Browsing did NOT flag this URL."

    prompt = f"""You are a scam detection assistant helping protect users from dangerous websites.
Analyze the following URL carefully.

URL: {url}
Safe Browsing result: {sb_context}

Instructions:
- If Safe Browsing flagged it, verdict should almost certainly be "⚠️ Dangerous Website".
- Examine the URL structure: suspicious TLDs, IP addresses, misleading domains, etc.
- Be concise — reason and advice must each be 1-2 sentences maximum.
- reason explains WHY the URL is or isn't safe.
- advice tells the user exactly what to DO.

Respond ONLY with this exact JSON structure, no markdown, no extra text:
{{
  "verdict": "⚠️ Dangerous Website" | "Suspicious Website" | "Likely Safe",
  "reason": "<1-2 sentences explaining your assessment>",
  "advice": "<1-2 sentences telling the user what to do>",
  "scam_category": "phishing" | "malware" | "social_engineering" | "unwanted_software" | "none"
}}"""

    raw_result = await _call_claude(prompt, _URL_FALLBACK, "url")
    return _validate_url_result(raw_result)