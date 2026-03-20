# schemas/user.py
from pydantic import BaseModel, EmailStr, Field, field_validator, model_config
from typing import Optional
from datetime import datetime
from database.models import PlanType


# ── Request Schemas ────────────────────────────────────────────────────────────

class GoogleTokenRequest(BaseModel):
    """
    Sent by the frontend after the user completes Google Sign-In.
    The id_token is the JWT issued by Google Identity Services.
    """
    model_config = model_config(str_strip_whitespace=True)

    id_token: str = Field(
        ...,
        min_length=10,
        description="Google ID token returned by Google Identity Services on the frontend.",
    )

    @field_validator("id_token")
    @classmethod
    def token_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id_token must not be blank.")
        return v


# ── Response Schemas ───────────────────────────────────────────────────────────

class UserOut(BaseModel):
    """
    Public-safe user representation returned in API responses.
    Never exposes: google_id, stripe_customer_id, stripe_subscription_id, is_active.
    """
    model_config = model_config(from_attributes=True)

    id:               str
    email:            EmailStr
    name:             str
    avatar:           Optional[str]  = None
    plan:             PlanType                        # typed enum: free | monthly | biannual | yearly
    scans_remaining:  int            = Field(ge=0)   # ge=0 ensures non-negative in response
    created_at:       datetime


class AuthResponse(BaseModel):
    """
    Returned after a successful Google sign-in.
    The frontend stores access_token and attaches it as:
      Authorization: Bearer <access_token>
    """
    access_token:  str
    token_type:    str      = "bearer"
    user:          UserOut