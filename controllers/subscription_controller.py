# controllers/subscription_controller.py
"""
Subscription business logic.

Responsibilities:
  - Orchestrate Stripe checkout creation
  - Route and handle Stripe webhook events
  - Provide subscription status to authenticated users
  - Allow users to cancel their subscription

Layer contract:
  - Calls payment_service for all Stripe API operations
  - Calls subscription_repo for all DB writes related to plans
  - Never calls user_repo directly for subscription operations
  - Never calls stripe library directly — that lives in payment_service
"""
import logging
from fastapi import HTTPException, Request, status

from config.settings import PLAN_PRICE_IDS
from database.models import User, PlanType
from repositories import subscription_repo, user_repo
from schemas.subscription import CheckoutResponse, SubscriptionStatusResponse, WebhookResponse
from services import payment_service
from utils.helpers import mask_email

logger = logging.getLogger("scam_detector.subscription")


# ── Checkout ───────────────────────────────────────────────────────────────────

async def create_checkout(plan: str, user: User) -> CheckoutResponse:
    """
    Creates a Stripe Checkout session for the selected plan.

    Guards:
      - Plan must be a valid paid plan (validated in schema, double-checked here)
      - User must not already be on the same plan
      - Stripe customer is created on first checkout if not already present
      - Verifies existing Stripe customer hasn't been deleted in Stripe dashboard

    Returns a CheckoutResponse with the hosted Stripe checkout URL.
    """
    # Guard: plan must be a purchasable paid plan
    if plan not in PLAN_PRICE_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan '{plan}'. Valid options: {sorted(PLAN_PRICE_IDS.keys())}",
        )

    # Guard: don't allow re-purchasing the same active plan
    if user.plan.value == plan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"You are already on the '{plan}' plan.",
        )

    # Ensure a valid Stripe customer exists
    if not user.stripe_customer_id:
        # First checkout — create a new Stripe customer
        customer_id = await payment_service.create_stripe_customer(
            email=user.email,
            user_id=str(user.id),
        )
        user = await subscription_repo.set_stripe_customer(user, customer_id)
    else:
        # Returning user — verify their Stripe customer still exists
        customer = await payment_service.get_stripe_customer(user.stripe_customer_id)
        if not customer:
            # Customer was deleted in Stripe dashboard — recreate
            logger.warning(
                f"Stripe customer {user.stripe_customer_id} not found — "
                f"recreating for user={user.id}"
            )
            customer_id = await payment_service.create_stripe_customer(
                email=user.email,
                user_id=str(user.id),
            )
            user = await subscription_repo.set_stripe_customer(user, customer_id)

    checkout_url = await payment_service.create_checkout_session(
        stripe_customer_id=user.stripe_customer_id,
        plan=plan,
        user_id=str(user.id),
    )

    logger.info(
        f"Checkout initiated | user={user.id} | "
        f"plan={plan} | email={mask_email(user.email)}"
    )
    return CheckoutResponse(checkout_url=checkout_url)


# ── Webhook ────────────────────────────────────────────────────────────────────

async def handle_webhook(request: Request) -> WebhookResponse:
    """
    Receives, verifies, and routes Stripe webhook events.

    Handled events:
      checkout.session.completed  — new subscription purchased
      customer.subscription.deleted — subscription cancelled or expired
      invoice.paid                — subscription renewed (monthly top-up)

    Unhandled events are silently acknowledged (Stripe requires 200 response).
    All events are logged with their event_id for traceability.
    """
    event      = await payment_service.parse_webhook_event(request)
    event_type = event["type"]
    event_id   = event.get("id", "unknown")

    logger.info(f"Webhook received | event_type={event_type} | event_id={event_id}")

    if event_type == "checkout.session.completed":
        await _on_payment_success(event["data"]["object"], event_id)

    elif event_type == "customer.subscription.deleted":
        await _on_subscription_cancelled(event["data"]["object"], event_id)

    elif event_type == "invoice.paid":
        await _on_invoice_paid(event["data"]["object"], event_id)

    else:
        # Unhandled event — log and acknowledge
        # Add more handlers here as needed (e.g. payment_failed, trial_will_end)
        logger.debug(f"Unhandled Stripe event: {event_type} | event_id={event_id}")

    return WebhookResponse(received=True, event_type=event_type)


# ── Status & cancellation ──────────────────────────────────────────────────────

async def get_status(user: User) -> SubscriptionStatusResponse:
    """
    Returns the user's current subscription state.
    Called by: routes/subscription.py → GET /subscription/status
    """
    state = await subscription_repo.get_subscription_state(user)
    return SubscriptionStatusResponse(
        plan=state["plan"],
        scans_remaining=state["scans_remaining"],
        stripe_subscription_id=state["stripe_subscription_id"],
        is_active=state["is_active"],
    )


async def cancel_subscription(user: User) -> SubscriptionStatusResponse:
    """
    Cancels the user's active Stripe subscription and reverts them to free plan.

    Guards:
      - User must be on a paid plan to cancel
      - User must have a Stripe subscription ID on record

    The cancellation is applied immediately (not at period end).
    For 'cancel at period end' behaviour, use stripe.Subscription.modify()
    with cancel_at_period_end=True in payment_service instead.

    Called by: routes/subscription.py → DELETE /subscription/cancel
    """
    if user.plan == PlanType.FREE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You do not have an active paid subscription to cancel.",
        )

    if not user.stripe_subscription_id:
        logger.error(
            f"cancel_subscription: user={user.id} is on plan={user.plan.value} "
            f"but has no stripe_subscription_id — deactivating locally."
        )
        # Data inconsistency — deactivate locally even without a Stripe ID
        user = await subscription_repo.deactivate_plan(user)
        return await get_status(user)

    # Cancel in Stripe — this will trigger a 'customer.subscription.deleted'
    # webhook which also calls _on_subscription_cancelled().
    # We deactivate locally here as well for immediate UI feedback.
    try:
        import stripe
        stripe.Subscription.delete(user.stripe_subscription_id)
        logger.info(
            f"Stripe subscription cancelled | "
            f"sub_id={user.stripe_subscription_id} | user={user.id}"
        )
    except Exception as e:
        logger.error(f"Stripe cancellation failed for user={user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not cancel subscription with payment provider. Please try again.",
        )

    user = await subscription_repo.deactivate_plan(user)
    logger.info(f"Subscription cancelled locally | user={user.id}")
    return await get_status(user)


# ── Internal webhook handlers ──────────────────────────────────────────────────

async def _on_payment_success(session: dict, event_id: str) -> None:
    """
    Activates the purchased plan after Stripe confirms payment.
    Triggered by: checkout.session.completed
    """
    user_id  = session.get("metadata", {}).get("user_id")
    plan_str = session.get("metadata", {}).get("plan")

    if not user_id or not plan_str:
        logger.error(
            f"_on_payment_success: missing metadata | "
            f"event_id={event_id} | "
            f"user_id={user_id} | plan={plan_str}"
        )
        return

    try:
        plan = PlanType(plan_str)
    except ValueError:
        logger.error(
            f"_on_payment_success: invalid plan '{plan_str}' | event_id={event_id}"
        )
        return

    user = await user_repo.get_by_id(user_id)
    if not user:
        logger.error(
            f"_on_payment_success: user_id={user_id} not found | event_id={event_id}"
        )
        return

    await subscription_repo.activate_plan(
        user=user,
        plan=plan,
        subscription_id=session.get("subscription"),
    )
    logger.info(
        f"Plan activated | user={user_id} | "
        f"plan={plan.value} | event_id={event_id}"
    )


async def _on_subscription_cancelled(subscription: dict, event_id: str) -> None:
    """
    Reverts user to free plan when their Stripe subscription is cancelled/deleted.
    Triggered by: customer.subscription.deleted
    """
    customer_id = subscription.get("customer")
    if not customer_id:
        logger.warning(
            f"_on_subscription_cancelled: no customer_id in payload | event_id={event_id}"
        )
        return

    user = await subscription_repo.get_user_by_stripe_customer(customer_id)
    if not user:
        logger.warning(
            f"_on_subscription_cancelled: no user found for "
            f"customer_id={customer_id} | event_id={event_id}"
        )
        return

    await subscription_repo.deactivate_plan(user)
    logger.info(
        f"Plan deactivated | user={user.id} | "
        f"customer={customer_id} | event_id={event_id}"
    )


async def _on_invoice_paid(invoice: dict, event_id: str) -> None:
    """
    Refreshes scan count at the start of each new billing period.
    Only acts on subscription renewals — skips the initial purchase invoice
    which is already handled by _on_payment_success.
    Triggered by: invoice.paid
    """
    # billing_reason == "subscription_cycle" means renewal, not initial purchase
    billing_reason = invoice.get("billing_reason")
    if billing_reason != "subscription_cycle":
        logger.debug(
            f"_on_invoice_paid: skipping billing_reason='{billing_reason}' | "
            f"event_id={event_id}"
        )
        return

    customer_id = invoice.get("customer")
    if not customer_id:
        return

    user = await subscription_repo.get_user_by_stripe_customer(customer_id)
    if not user:
        return

    await subscription_repo.refresh_scans(user)
    logger.info(
        f"Scans refreshed on renewal | user={user.id} | "
        f"plan={user.plan.value} | event_id={event_id}"
    )