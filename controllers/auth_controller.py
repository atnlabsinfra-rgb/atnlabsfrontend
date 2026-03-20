# controllers/auth_controller.py
"""
Auth business logic.

Responsibilities:
  - Verify Google ID token with Google's public keys
  - Validate required claims inside the token payload
  - Find existing user or create a new one
  - Issue a JWT access token
  - Return user profile

This controller is the single entry point for all authentication logic.
The route (routes/auth.py) only calls functions from here — no auth
logic lives in the route file.
"""
import logging
from fastapi import HTTPException, status
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google.auth.exceptions import GoogleAuthError

from config.settings import settings
from database.models import User
from repositories import user_repo
from schemas.user import AuthResponse, UserOut
from utils.security import create_access_token
from utils.helpers import user_to_out, mask_email

logger = logging.getLogger("scam_detector.auth")

# Clock skew tolerance in seconds.
# Allows tokens issued up to 10s in the future — handles minor
# clock differences between Google's servers and ours.
_CLOCK_SKEW_SECONDS = 10


# ── Internal helpers ───────────────────────────────────────────────────────────

def _verify_google_token(raw_token: str) -> dict:
    """
    Verifies a Google ID token and returns the decoded claims payload.

    Checks performed by google-auth library:
      - Signature validity (against Google's public keys)
      - Token expiry (with clock skew tolerance)
      - Audience matches our GOOGLE_CLIENT_ID
      - Issuer is accounts.google.com or accounts.google.com

    Additional checks we perform:
      - 'sub' claim present (Google user ID)
      - 'email' claim present
      - 'email_verified' is True (Google-verified email only)

    Raises:
      401 UNAUTHORIZED — on any verification failure
    """
    try:
        claims = id_token.verify_oauth2_token(
            id_token=raw_token,
            request=google_requests.Request(),
            audience=settings.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=_CLOCK_SKEW_SECONDS,
        )
    except GoogleAuthError as e:
        logger.warning(f"Google token verification failed (GoogleAuthError): {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google token. Please sign in again.",
        )
    except ValueError as e:
        logger.warning(f"Google token verification failed (ValueError): {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token format.",
        )

    # Validate required claims are present
    if not claims.get("sub"):
        logger.warning("Google token missing 'sub' claim.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token: missing user ID.",
        )

    if not claims.get("email"):
        logger.warning("Google token missing 'email' claim.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google account must have an email address.",
        )

    # Only accept verified email addresses.
    # Unverified emails can be set to any value — a security risk.
    if not claims.get("email_verified", False):
        logger.warning(f"Unverified Google email attempted sign-in: {claims.get('email')}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google account email is not verified.",
        )

    return claims


async def _find_or_create_user(claims: dict) -> tuple[User, bool]:
    """
    Looks up the user by Google ID.
    Creates a new user record if this is their first sign-in.

    Also handles reactivation: if a previously deactivated user signs in
    again, their account is restored rather than rejected.

    Returns:
        (user, is_new_user)
    """
    google_id = claims["sub"]
    email     = claims["email"]
    name      = claims.get("name", "")
    avatar    = claims.get("picture")

    user = await user_repo.get_by_google_id(google_id)

    # New user — create account with free scan limit
    if not user:
        user = await user_repo.create(
            email=email,
            google_id=google_id,
            name=name,
            avatar=avatar,
            scans_remaining=settings.FREE_SCAN_LIMIT,
        )
        logger.info(f"New user registered | {mask_email(email)}")
        return user, True

    # Existing but deactivated user — reactivate on sign-in
    if not user.is_active:
        user.is_active = True
        await user.save()
        logger.info(f"User reactivated on sign-in | {mask_email(email)}")

    # Update avatar if Google profile picture changed
    if avatar and user.avatar != avatar:
        user.avatar = avatar
        await user.save()

    logger.info(f"User signed in | {mask_email(email)} | plan={user.plan.value}")
    return user, False


# ── Public API ─────────────────────────────────────────────────────────────────

async def google_sign_in(raw_token: str) -> AuthResponse:
    """
    Full Google OAuth2 sign-in flow.

    Steps:
      1. Verify Google ID token → extract claims
      2. Find or create user in MongoDB
      3. Issue JWT access token
      4. Return token + user profile

    Called by: routes/auth.py → POST /auth/google
    """
    claims          = _verify_google_token(raw_token)
    user, is_new    = await _find_or_create_user(claims)
    access_token    = create_access_token(str(user.id))

    return AuthResponse(
        access_token=access_token,
        user=user_to_out(user),
    )


async def get_profile(user: User) -> UserOut:
    """
    Returns the authenticated user's profile.
    Called by: routes/auth.py → GET /auth/me

    The user object is already fetched and validated by
    get_current_user() in middleware/auth_middleware.py.
    This function just converts it to the response schema.
    """
    return user_to_out(user)