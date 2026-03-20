# middleware/auth_middleware.py
"""
Authentication middleware and dependency.

Two tools provided here:

1. get_current_user — FastAPI dependency injected into protected routes.
   Validates the JWT from the Authorization header and returns the User document.

2. require_active_subscription — optional dependency for routes that need
   a paid plan (not just any authenticated user).

Usage in routes:
    from middleware.auth_middleware import get_current_user, require_active_subscription

    @router.get("/scan/text")
    async def scan(current_user: User = Depends(get_current_user)):
        ...

    @router.get("/premium-only")
    async def premium(current_user: User = Depends(require_active_subscription)):
        ...
"""
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from database.models import User
from utils.security import decode_access_token

logger = logging.getLogger("scam_detector.middleware")

# Tells FastAPI where the token comes from.
# tokenUrl is shown in Swagger UI — it's the endpoint the user calls to get a token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/google")


# ── Primary Auth Dependency ────────────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    FastAPI dependency — validates JWT and returns the authenticated User document.

    Flow:
      1. Extracts Bearer token from Authorization header
      2. Decodes and verifies JWT signature + expiry via utils/security.py
      3. Looks up the user in MongoDB by the user_id in the token's 'sub' claim
      4. Rejects if user not found or account is deactivated

    Raises:
      401 UNAUTHORIZED — if token is missing, invalid, expired, or user not found
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},   # required by OAuth2 spec
    )

    # Step 1: Decode token → get user_id
    user_id = decode_access_token(token)
    if not user_id:
        logger.warning("Auth failed: token invalid or expired.")
        raise unauthorized

    # Step 2: Fetch user from DB
    user = await User.get(user_id)
    if not user:
        logger.warning(f"Auth failed: user_id={user_id} not found in DB.")
        raise unauthorized

    # Step 3: Check account is active
    if not user.is_active:
        logger.warning(f"Auth failed: user_id={user_id} account is deactivated.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact support.",
        )

    return user


# ── Subscription Guard Dependency ─────────────────────────────────────────────

async def require_active_subscription(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Optional dependency — use on routes that require a paid plan.
    Chains on top of get_current_user, so JWT auth is still enforced.

    Raises:
      402 PAYMENT_REQUIRED — if user is on the free plan
    """
    if current_user.plan.value == "free":
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="This feature requires an active subscription. Please upgrade your plan.",
        )
    return current_user