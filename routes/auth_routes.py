# routes/auth_routes.py
"""
Auth routes — thin HTTP layer only.

Rule: No business logic here. Every route does exactly three things:
  1. Declare the endpoint (method, path, response model)
  2. Inject dependencies (auth middleware, request body)
  3. Call the controller and return its result

All logic lives in controllers/auth_controller.py.
"""
from fastapi import APIRouter, Depends, status

from schemas.user import GoogleTokenRequest, AuthResponse, UserOut
from controllers.auth_controller import google_sign_in, get_profile
from database.models import User
from middleware.auth_middleware import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/google",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Sign in with Google",
    description="""
Verifies a Google ID token sent from the frontend after Google Sign-In.

**Flow:**
1. User clicks *Sign in with Google* on the frontend
2. Google returns a Google ID token to the frontend
3. Frontend sends that token here
4. Backend verifies it with Google, finds or creates the user
5. Returns a JWT access token + user profile

**New users** are created automatically with `plan=free` and `scans_remaining=7`.

**Use the returned `access_token`** as a Bearer token on all protected routes:
```
Authorization: Bearer <access_token>
```
    """,
)
async def sign_in_with_google(body: GoogleTokenRequest):
    return await google_sign_in(body.id_token)


@router.get(
    "/me",
    response_model=UserOut,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
    description="""
Returns the authenticated user's profile.

Requires a valid JWT in the `Authorization: Bearer <token>` header.
Returns `401 Unauthorized` if the token is missing, invalid, or expired.
    """,
)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    return await get_profile(current_user)