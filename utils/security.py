# utils/security.py
"""
JWT token creation and verification.
All cryptographic operations live here — no other file touches jose directly.

Used by:
  - controllers/auth_controller.py  → create_access_token() after sign-in
  - middleware/auth.py              → decode_access_token() on every protected request
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from config.settings import settings

logger = logging.getLogger("scam_detector.security")


# ── Token Creation ─────────────────────────────────────────────────────────────

def create_access_token(user_id: str) -> str:
    """
    Creates a signed JWT access token embedding the user's ID.

    Payload:
      sub  — subject (user_id as string)
      exp  — expiry timestamp (now + ACCESS_TOKEN_EXPIRE_MINUTES)
      iat  — issued-at timestamp (useful for token age checks)

    Returns the encoded JWT string to send to the frontend.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
    }

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    logger.debug(f"Access token created for user_id={user_id}, expires={expire.isoformat()}")
    return token


# ── Token Verification ────────────────────────────────────────────────────────

def decode_access_token(token: str) -> Optional[str]:
    """
    Decodes and verifies a JWT access token.

    Verifies:
      - Signature (using SECRET_KEY)
      - Expiry (jose raises JWTError if expired)
      - Presence of 'sub' claim

    Returns:
      user_id (str) if token is valid
      None          if token is invalid, expired, or malformed
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            logger.warning("JWT decoded but 'sub' claim is missing.")
            return None
        return user_id

    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None


# ── Token Introspection (optional utility) ────────────────────────────────────

def get_token_expiry(token: str) -> Optional[datetime]:
    """
    Extracts the expiry datetime from a token without raising on failure.
    Useful for logging or returning token TTL info to the frontend.
    Returns None if the token is unreadable.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        exp = payload.get("exp")
        if exp is None:
            return None
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    except JWTError:
        return None