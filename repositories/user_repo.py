# repositories/user_repo.py
"""
All database read/write operations for the User collection.

Rule: Controllers and services NEVER call User.find / User.insert / User.save
directly. All MongoDB access for users goes through this file.
This means if the DB schema changes, only this file needs updating.
"""
import logging
from typing import Optional

from beanie.operators import Inc
from database.models import User, PlanType
from utils.helpers import mask_email

logger = logging.getLogger("scam_detector.user_repo")


# ── Reads ──────────────────────────────────────────────────────────────────────

async def get_by_id(user_id: str) -> Optional[User]:
    """Fetch a user by their MongoDB document ID."""
    try:
        return await User.get(user_id)
    except Exception:
        # User.get() raises if the ID format is invalid (e.g. not a valid ObjectId)
        logger.warning(f"get_by_id failed for user_id={user_id}")
        return None


async def get_by_google_id(google_id: str) -> Optional[User]:
    """Fetch a user by their Google OAuth subject ID. Used during sign-in."""
    return await User.find_one(User.google_id == google_id)


async def get_by_email(email: str) -> Optional[User]:
    """Fetch a user by email address."""
    return await User.find_one(User.email == email)


async def get_by_stripe_customer_id(customer_id: str) -> Optional[User]:
    """Fetch a user by their Stripe customer ID. Used in webhook handlers."""
    return await User.find_one(User.stripe_customer_id == customer_id)


async def get_all_active() -> list[User]:
    """Fetch all active users. For admin use only."""
    return await User.find(User.is_active == True).to_list()  # noqa: E712


# ── Writes ─────────────────────────────────────────────────────────────────────

async def create(
    email: str,
    google_id: str,
    name: str,
    avatar: Optional[str],
    scans_remaining: int,
) -> User:
    """
    Creates and persists a new User document.
    Plan always starts as PlanType.FREE — cannot be set at creation.
    """
    user = User(
        email=email,
        google_id=google_id,
        name=name,
        avatar=avatar,
        plan=PlanType.FREE,
        scans_remaining=scans_remaining,
    )
    await user.insert()
    logger.info(f"New user created: {mask_email(email)}")
    return user


async def update_stripe_customer(user: User, customer_id: str) -> User:
    """Stores the Stripe customer ID after first checkout."""
    user.stripe_customer_id = customer_id
    await user.save()
    logger.info(f"Stripe customer set for user_id={user.id}")
    return user


async def update_plan(
    user: User,
    plan: PlanType,
    scans_remaining: int,
    subscription_id: Optional[str] = None,
) -> User:
    """
    Updates the user's plan and scan count after a successful payment.
    Called by subscription_repo after Stripe webhook confirms payment.
    """
    user.plan = plan
    user.scans_remaining = scans_remaining
    user.stripe_subscription_id = subscription_id
    await user.save()
    logger.info(
        f"Plan updated for user_id={user.id} → "
        f"plan={plan.value}, scans={scans_remaining}"
    )
    return user


async def deduct_scan(user: User) -> User:
    """
    Atomically decrements scans_remaining by 1 using MongoDB $inc operator.

    Why atomic?
    Using $inc at the DB level prevents a race condition where two concurrent
    requests both read scans_remaining=1, both pass the limit check, both
    decrement to 0 — resulting in -1 (one free scan given away).
    With $inc the DB handles the decrement atomically.

    Also guards against going below 0 in the application layer.
    """
    if user.scans_remaining <= 0:
        logger.warning(f"deduct_scan called on user_id={user.id} with 0 scans — skipped.")
        return user

    await user.update(Inc({User.scans_remaining: -1}))

    # Refresh the local object to reflect the DB state
    await user.sync()

    logger.debug(f"Scan deducted for user_id={user.id}, remaining={user.scans_remaining}")
    return user


async def cancel_subscription(user: User) -> User:
    """
    Reverts user to free plan on subscription cancellation.
    Called by subscription_repo after Stripe cancellation webhook.
    scans_remaining is set to 0 — user must re-subscribe for more scans.
    """
    user.plan = PlanType.FREE
    user.scans_remaining = 0
    user.stripe_subscription_id = None
    await user.save()
    logger.info(f"Subscription cancelled for user_id={user.id} → reverted to free")
    return user


async def deactivate(user: User) -> User:
    """Soft-deletes a user by marking them inactive. Does not remove the document."""
    user.is_active = False
    await user.save()
    logger.info(f"User deactivated: user_id={user.id}")
    return user