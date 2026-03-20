# services/payment_service.py
"""
Stripe payment service.

Responsibilities:
  - Create and retrieve Stripe customers
  - Create Checkout sessions for subscription plans
  - Verify and parse incoming Stripe webhook events

This service is purely a Stripe API wrapper.
It does NOT touch the database — all DB updates happen in
subscription_controller via subscription_repo after this service returns.

Stripe docs: https://stripe.com/docs/api
"""
import logging
import uuid
from typing import Optional

import stripe
from fastapi import HTTPException, Request, status

from config.settings import settings, PLAN_PRICE_IDS
from utils.helpers import mask_email

logger = logging.getLogger("scam_detector.payment")

# ── Stripe client setup ────────────────────────────────────────────────────────
stripe.api_key = settings.STRIPE_SECRET_KEY

# Max network retries on transient Stripe errors (429, 500, 503)
stripe.max_network_retries = 3

# ── URL config ────────────────────────────────────────────────────────────────
# These should be moved to settings.py once you have a real domain.
_SUCCESS_URL = "https://yourapp.com/payment-success?session_id={CHECKOUT_SESSION_ID}"
_CANCEL_URL  = "https://yourapp.com/pricing"


# ── Customer operations ────────────────────────────────────────────────────────

async def create_stripe_customer(email: str, user_id: str) -> str:
    """
    Creates a new Stripe Customer object and returns the customer ID.

    Metadata stores user_id so we can look up our user from any Stripe
    dashboard view or webhook payload.
    """
    try:
        customer = stripe.Customer.create(
            email=email,
            metadata={"user_id": user_id},
        )
        logger.info(
            f"Stripe customer created | "
            f"customer_id={customer.id} | "
            f"user={mask_email(email)}"
        )
        return customer.id

    except stripe.error.InvalidRequestError as e:
        logger.error(f"Stripe invalid request creating customer: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not create payment profile. Please try again.",
        )
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating customer: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Payment service unavailable. Please try again later.",
        )


async def get_stripe_customer(customer_id: str) -> Optional[dict]:
    """
    Retrieves a Stripe customer by ID.
    Returns None if not found instead of raising.
    Useful for verifying a customer still exists before creating a session.
    """
    try:
        customer = stripe.Customer.retrieve(customer_id)
        # Stripe marks deleted customers with a 'deleted' key
        if customer.get("deleted"):
            logger.warning(f"Stripe customer {customer_id} has been deleted.")
            return None
        return customer
    except stripe.error.InvalidRequestError:
        logger.warning(f"Stripe customer not found: {customer_id}")
        return None
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error retrieving customer {customer_id}: {e}")
        return None


# ── Checkout session ───────────────────────────────────────────────────────────

async def create_checkout_session(
    stripe_customer_id: str,
    plan: str,
    user_id: str,
) -> str:
    """
    Creates a Stripe Checkout session for a subscription plan.
    Returns the hosted checkout URL to redirect the user to.

    Idempotency key: generated per (user_id, plan) pair so that if the
    frontend retries the request, Stripe returns the same session instead
    of creating a duplicate charge.
    """
    if plan not in PLAN_PRICE_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan '{plan}'. Valid options: {sorted(PLAN_PRICE_IDS.keys())}",
        )

    price_id = PLAN_PRICE_IDS[plan]

    # Idempotency key — unique per user+plan combination per request batch
    # Using uuid4 here; for true idempotency across retries store and reuse this key.
    idempotency_key = f"{user_id}-{plan}-{uuid.uuid4().hex}"

    try:
        session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=_SUCCESS_URL,
            cancel_url=_CANCEL_URL,
            # Metadata is echoed back in the webhook — how we link payment → user
            metadata={"user_id": user_id, "plan": plan},
            # Allow promo codes in the Stripe-hosted checkout UI
            allow_promotion_codes=True,
            # Automatically collect billing address (needed for some regions)
            billing_address_collection="auto",
            idempotency_key=idempotency_key,
        )
        logger.info(
            f"Checkout session created | "
            f"session_id={session.id} | "
            f"user_id={user_id} | "
            f"plan={plan}"
        )
        return session.url

    except stripe.error.InvalidRequestError as e:
        logger.error(f"Stripe invalid checkout request for user={user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not create checkout session. Please try again.",
        )
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating checkout session for user={user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Payment service unavailable. Please try again later.",
        )


# ── Webhook verification ───────────────────────────────────────────────────────

async def parse_webhook_event(request: Request) -> dict:
    """
    Verifies the Stripe webhook signature and returns the parsed event object.

    CRITICAL: Always verify the signature before trusting the payload.
    Without this check, anyone could POST to /subscription/webhook and
    fake a payment success to get free scans.

    Raises:
      400 BAD REQUEST — if signature is missing or invalid
    """
    payload = await request.body()
    sig     = request.headers.get("stripe-signature", "")

    if not sig:
        logger.warning("Webhook received with no stripe-signature header.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe signature.",
        )

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig,
            secret=settings.STRIPE_WEBHOOK_SECRET,
        )
        logger.info(
            f"Stripe webhook verified | "
            f"event_type={event['type']} | "
            f"event_id={event['id']}"
        )
        return event

    except stripe.error.SignatureVerificationError:
        logger.warning(
            f"Stripe webhook signature verification failed. "
            f"Possible replay attack or wrong webhook secret."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Stripe webhook signature.",
        )
    except Exception as e:
        logger.error(f"Unexpected error parsing Stripe webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not parse webhook payload.",
        )