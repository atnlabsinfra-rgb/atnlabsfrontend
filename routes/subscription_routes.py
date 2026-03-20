# routes/subscription_routes.py
"""
Subscription routes — thin HTTP layer only.

Rule: No business logic here. Every route does exactly three things:
  1. Declare the endpoint (method, path, response model, status code)
  2. Inject dependencies (auth middleware, request body)
  3. Call the controller and return its result

All logic lives in controllers/subscription_controller.py.

Endpoints:
  POST   /subscription/checkout   — create Stripe checkout session
  POST   /subscription/webhook    — receive Stripe payment events (no auth)
  GET    /subscription/status     — get current plan and scan count
  DELETE /subscription/cancel     — cancel active subscription
"""
from fastapi import APIRouter, Depends, Request, status

from schemas.subscription import (
    CreateCheckoutRequest,
    CheckoutResponse,
    SubscriptionStatusResponse,
    WebhookResponse,
)
from controllers.subscription_controller import (
    create_checkout,
    handle_webhook,
    get_status,
    cancel_subscription,
)
from database.models import User
from middleware.auth_middleware import get_current_user

router = APIRouter(prefix="/subscription", tags=["Subscription"])


# ── POST /subscription/checkout ────────────────────────────────────────────────

@router.post(
    "/checkout",
    response_model=CheckoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Create Stripe checkout session",
    description="""
Creates a Stripe Checkout session for the selected subscription plan.

Returns a `checkout_url` — redirect the user to this URL to complete payment
on Stripe's hosted checkout page.

**Available plans:**

| Plan | Scans | Description |
|------|-------|-------------|
| `monthly` | 90 | Billed monthly |
| `biannual` | 600 | Billed every 6 months |
| `yearly` | 1200 | Billed annually |

After successful payment, Stripe calls `POST /subscription/webhook`
which automatically updates the user's plan and scan count.

**Returns 409** if the user is already on the selected plan.
**Returns 400** if an invalid plan name is provided.
    """,
    responses={
        200: {"description": "Checkout session created — redirect user to checkout_url"},
        400: {"description": "Invalid plan name"},
        409: {"description": "User is already on this plan"},
        502: {"description": "Stripe API unavailable"},
    },
)
async def create_checkout_session(
    body: CreateCheckoutRequest,
    current_user: User = Depends(get_current_user),
):
    return await create_checkout(plan=body.plan, user=current_user)


# ── POST /subscription/webhook ─────────────────────────────────────────────────

@router.post(
    "/webhook",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Stripe webhook receiver",
    description="""
Receives and processes Stripe payment lifecycle events.

**⚠️ No JWT authentication on this route — Stripe calls it directly.**

Security is enforced via **Stripe webhook signature verification** using
`STRIPE_WEBHOOK_SECRET`. Any request with an invalid or missing signature
is rejected with `400 Bad Request`.

**Handled events:**

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Activates purchased plan + grants scans |
| `customer.subscription.deleted` | Reverts user to free plan |
| `invoice.paid` | Refreshes scan count on monthly renewal |

All other events are acknowledged and ignored.

**Stripe setup:**
Register this URL in your Stripe Dashboard → Webhooks:
`https://yourapp.com/subscription/webhook`
    """,
    responses={
        200: {"description": "Event received and processed"},
        400: {"description": "Invalid or missing Stripe webhook signature"},
    },
)
async def stripe_webhook(request: Request):
    # ⚠️ Intentionally no Depends(get_current_user) — Stripe calls this directly
    return await handle_webhook(request)


# ── GET /subscription/status ───────────────────────────────────────────────────

@router.get(
    "/status",
    response_model=SubscriptionStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get subscription status",
    description="""
Returns the authenticated user's current subscription state.

Use this to display the user's plan, remaining scans, and subscription ID
in your frontend dashboard.

**Response example:**
```json
{
  "plan": "monthly",
  "scans_remaining": 73,
  "stripe_subscription_id": "sub_1ABC...",
  "is_active": true
}
```

`stripe_subscription_id` is `null` for free plan users.
    """,
)
async def get_subscription_status(
    current_user: User = Depends(get_current_user),
):
    return await get_status(current_user)


# ── DELETE /subscription/cancel ────────────────────────────────────────────────

@router.delete(
    "/cancel",
    response_model=SubscriptionStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Cancel active subscription",
    description="""
Cancels the authenticated user's active Stripe subscription immediately
and reverts their account to the free plan with 0 scans remaining.

**⚠️ Cancellation is immediate** — the user loses access to their remaining
scans right away. There is no grace period or refund handled by this endpoint.

**Returns 409** if the user is already on the free plan (nothing to cancel).
**Returns 502** if the Stripe API is unavailable.

After cancellation, the response shows the updated plan state:
```json
{
  "plan": "free",
  "scans_remaining": 0,
  "stripe_subscription_id": null,
  "is_active": true
}
```
    """,
    responses={
        200: {"description": "Subscription cancelled — user reverted to free plan"},
        409: {"description": "No active subscription to cancel"},
        502: {"description": "Could not cancel with Stripe — try again"},
    },
)
async def cancel_active_subscription(
    current_user: User = Depends(get_current_user),
):
    return await cancel_subscription(current_user)