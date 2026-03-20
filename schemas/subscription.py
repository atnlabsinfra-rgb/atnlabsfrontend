# schemas/subscription.py
from pydantic import BaseModel, AnyHttpUrl, Field, field_validator
from pydantic import model_config as pydantic_model_config
from typing import Optional
from datetime import datetime
from database.models import PlanType


# ── Request Schemas ────────────────────────────────────────────────────────────

class CreateCheckoutRequest(BaseModel):
    """
    Request body for POST /subscription/checkout.
    The plan must be one of the three paid tiers — free is not purchasable.
    """
    model_config = pydantic_model_config(str_strip_whitespace=True)

    plan: str = Field(
        ...,
        description="Subscription plan to purchase.",
        examples=["monthly"],
    )

    @field_validator("plan")
    @classmethod
    def plan_must_be_paid(cls, v: str) -> str:
        allowed = {"monthly", "biannual", "yearly"}
        if v.lower() not in allowed:
            raise ValueError(
                f"Invalid plan '{v}'. Must be one of: {sorted(allowed)}."
            )
        return v.lower()


# ── Response Schemas ───────────────────────────────────────────────────────────

class CheckoutResponse(BaseModel):
    """
    Returned after a Stripe Checkout session is created.
    The frontend redirects the user to checkout_url to complete payment.
    """
    checkout_url: AnyHttpUrl = Field(
        ...,
        description="Stripe-hosted checkout page URL. Redirect the user here.",
    )


class SubscriptionStatusResponse(BaseModel):
    """
    Returned by GET /subscription/status.
    Gives the frontend everything it needs to render the user's current plan state.
    """
    model_config = pydantic_model_config(from_attributes=True)

    plan:                       PlanType        # typed enum — never a raw string
    scans_remaining:            int = Field(ge=0)
    stripe_subscription_id:     Optional[str]   = None   # None if on free plan
    is_active:                  bool            = True


class WebhookResponse(BaseModel):
    """
    Returned to Stripe after a webhook event is processed.
    Stripe expects a 200 with any JSON body — this makes the contract explicit.
    """
    received:   bool  = True
    event_type: Optional[str] = None   # echoes back the Stripe event type for traceability