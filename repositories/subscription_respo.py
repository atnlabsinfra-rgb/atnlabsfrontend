# repositories/subscription_repo.py
"""
All database operations scoped to the subscription domain.

Responsibility:
  - Owns every state transition related to a user's plan and billing info.
  - Wraps user_repo with subscription-specific guards, logging, and validation.
  - The subscription_controller calls this repo — never user_repo directly
    for subscription operations.

State machine:
    free ──► monthly  ──► free (cancelled)
         ──► biannual ──► free (cancelled)
         ──► yearly   ──► free (cancelled)
    Any paid plan can also upgrade/downgrade to another paid plan.
"""
import logging
from typing import Optional

from database.models import User, PlanType
from config.settings import PLAN_SCAN_LIMITS
from repositories import user_repo

logger = logging.getLogger("scam_detector.subscription_repo")


# ── Reads ──────────────────────────────────────────────────────────────────────

async def get_user_by_stripe_customer(customer_id: str) -> Optional[User]:
    """
    Looks up a user by their Stripe customer ID.
    Called in webhook handlers where we only have the Stripe customer ID,
    not the internal user_id.
    """
    user = await user_repo.get_by_stripe_customer_id(customer_id)
    if not user:
        logger.warning(f"No user found for stripe_customer_id={customer_id}")
    return user


async def get_subscription_state(user: User) -> dict:
    """
    Returns a snapshot of the user's current subscription state.
    Used by the controller to build SubscriptionStatusResponse.
    """
    return {
        "plan":                     user.plan,
        "scans_remaining":          user.scans_remaining,
        "stripe_subscription_id":   user.stripe_subscription_id,
        "is_active":                user.is_active,
    }


# ── Writes ─────────────────────────────────────────────────────────────────────

async def set_stripe_customer(user: User, customer_id: str) -> User:
    """
    Stores the Stripe customer ID on the user after first checkout.
    Only sets it if not already present — prevents accidental overwrites.
    """
    if user.stripe_customer_id:
        logger.warning(
            f"set_stripe_customer called but user_id={user.id} "
            f"already has stripe_customer_id={user.stripe_customer_id}. Skipped."
        )
        return user

    user = await user_repo.update_stripe_customer(user, customer_id)
    logger.info(f"Stripe customer linked | user_id={user.id} | customer={customer_id}")
    return user


async def activate_plan(
    user: User,
    plan: PlanType,
    subscription_id: Optional[str],
) -> User:
    """
    Activates a paid plan after a successful Stripe payment.

    Scan count is derived from PLAN_SCAN_LIMITS — never passed in directly.
    This ensures the controller can't accidentally set an arbitrary scan count.

    Handles both:
      - New subscription (free → paid)
      - Plan change (paid → different paid)
    """
    scans = PLAN_SCAN_LIMITS.get(plan.value)
    if scans is None:
        logger.error(f"activate_plan: unknown plan={plan.value} for user_id={user.id}")
        raise ValueError(f"Unknown plan: {plan.value}")

    previous_plan = user.plan.value
    user = await user_repo.update_plan(
        user=user,
        plan=plan,
        scans_remaining=scans,
        subscription_id=subscription_id,
    )
    logger.info(
        f"Plan activated | user_id={user.id} | "
        f"{previous_plan} → {plan.value} | scans={scans}"
    )
    return user


async def deactivate_plan(user: User) -> User:
    """
    Reverts user to free plan on subscription cancellation or non-renewal.
    Sets scans_remaining to 0 — user must re-subscribe for more scans.

    Guard: if already on free plan, skip the write to avoid a pointless DB call.
    """
    if user.plan == PlanType.FREE:
        logger.info(f"deactivate_plan skipped — user_id={user.id} already on free plan.")
        return user

    previous_plan = user.plan.value
    user = await user_repo.cancel_subscription(user)
    logger.info(
        f"Plan deactivated | user_id={user.id} | "
        f"{previous_plan} → free | scans set to 0"
    )
    return user


async def refresh_scans(user: User) -> User:
    """
    Resets the user's scans_remaining to the full limit for their current plan.
    Called at the start of a new billing period (e.g. monthly renewal).

    Note: Stripe handles billing renewals automatically. This can be triggered
    by a 'invoice.paid' webhook event for monthly top-ups.
    """
    scans = PLAN_SCAN_LIMITS.get(user.plan.value, 0)
    user = await user_repo.update_plan(
        user=user,
        plan=user.plan,
        scans_remaining=scans,
        subscription_id=user.stripe_subscription_id,
    )
    logger.info(
        f"Scans refreshed | user_id={user.id} | "
        f"plan={user.plan.value} | scans reset to {scans}"
    )
    return user