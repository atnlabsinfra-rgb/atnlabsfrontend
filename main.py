# main.py
"""
ScamDetectorAPI — Application entry point.

Responsibilities:
  - Create the FastAPI app instance with metadata
  - Register startup / shutdown lifecycle (DB connect/disconnect)
  - Mount middleware (CORS, request logging)
  - Register global error handlers
  - Include all routers
  - Expose health check endpoint

Nothing else lives here. All logic is in routes → controllers → services/repos.
"""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import settings
from database.db import connect_db, disconnect_db, ping_db
from routes.auth_routes import router as auth_router
from routes.scan_routes import router as scan_router
from routes.subscription_routes import router as subscription_router
from utils.helpers import setup_logging


# ── Startup & Shutdown ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs setup before the app starts serving requests,
    and teardown after the last request is served.
    """
    setup_logging("DEBUG" if settings.DEBUG else "INFO")
    await connect_db()
    yield                   # app is live and serving here
    await disconnect_db()   # called on SIGTERM / Ctrl+C


# ── App Instance ───────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-powered scam detection API.\n\n"
        "Supports text message and URL scanning using rule-based detection "
        "and Claude AI analysis. Includes Google OAuth2 authentication "
        "and Stripe subscription management.\n\n"
        "**Authentication:** All protected routes require a Bearer token.\n"
        "Obtain one via `POST /auth/google`."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc",     # ReDoc UI
    openapi_url="/openapi.json",
    contact={
        "name":  "ScamDetector Support",
        "email": "support@yourapp.com",
        "url":   "https://yourapp.com",
    },
    license_info={
        "name": "Private — All rights reserved",
    },
    servers=[
        {"url": "http://localhost:8000",    "description": "Local development"},
        {"url": "https://api.yourapp.com",  "description": "Production"},
    ],
)


# ── CORS ───────────────────────────────────────────────────────────────────────
# Update allow_origins before going to production.
# Never use ["*"] in production — always specify exact frontend origins.

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",    # React dev server
        "http://localhost:5173",    # Vite dev server
        "https://yourapp.com",      # Production frontend
    ],
    allow_credentials=True,         # Required for cookies / auth headers
    allow_methods=["*"],            # GET, POST, PUT, DELETE, OPTIONS, etc.
    allow_headers=["*"],            # Authorization, Content-Type, etc.
)


# ── Request Logging ────────────────────────────────────────────────────────────

access_logger = logging.getLogger("scam_detector.access")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Logs every request with method, path, status code, and response time.
    Skips health check endpoint to keep logs clean under monitoring pings.
    """
    start    = time.perf_counter()
    response = await call_next(request)
    ms       = (time.perf_counter() - start) * 1000

    # Skip logging for health check — monitoring tools ping this every 30s
    if request.url.path != "/":
        access_logger.info(
            f"{request.method} {request.url.path} "
            f"→ {response.status_code} ({ms:.1f}ms)"
        )

    return response


# ── Error Handlers ─────────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """
    Handles Pydantic validation errors (422).
    Returns a clean, readable list of field errors instead of FastAPI's
    default verbose format.

    Example response:
    {
      "detail": "Validation error",
      "errors": [
        { "field": "body → message", "message": "field required" }
      ]
    }
    """
    errors = [
        {
            "field":   " → ".join(str(loc) for loc in e["loc"]),
            "message": e["msg"],
        }
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Validation error", "errors": errors},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Handles all FastAPI HTTPExceptions (401, 402, 403, 404, 409, etc.).
    Returns a consistent JSON shape matching our validation error format.

    Without this handler, HTTPExceptions return FastAPI's default shape
    which differs from our validation error shape — inconsistent for clients.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    """
    Catch-all for any unhandled exception.
    Logs the full traceback server-side but returns a safe generic message
    to the client — no stack traces exposed in production.
    """
    logging.getLogger("scam_detector.errors").exception(
        f"Unhandled error | {request.method} {request.url.path} | {type(exc).__name__}: {exc}"
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again."},
    )


# ── Routers ────────────────────────────────────────────────────────────────────

app.include_router(auth_router)           # /auth/*
app.include_router(scan_router)           # /scan/*
app.include_router(subscription_router)   # /subscription/*


# ── Health Check ───────────────────────────────────────────────────────────────

@app.get(
    "/",
    tags=["Health"],
    summary="Health check",
    description=(
        "Returns the current status of the API and its database connection.\n\n"
        "- `status: ok` — everything is healthy\n"
        "- `status: degraded` — API is running but MongoDB is unreachable\n\n"
        "Use this endpoint for uptime monitoring and deployment health checks."
    ),
)
async def health_check():
    db_ok = await ping_db()
    return {
        "status":   "ok" if db_ok else "degraded",
        "app":      settings.APP_NAME,
        "version":  "1.0.0",
        "database": "connected" if db_ok else "unreachable",
    }




# # main.py
# from contextlib import asynccontextmanager
# from fastapi import FastAPI, Request, status
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import JSONResponse
# from fastapi.exceptions import RequestValidationError
# import logging
# import time

# from config.settings import settings
# from database.db import connect_db
# from routes.auth_routes import router as auth_router
# from routes.scan_routes import router as scan_router
# from routes.subscription_routes import router as subscription_router
# from utils.helpers import setup_logging


# # ── Startup / Shutdown ─────────────────────────────────────────────────────────

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     setup_logging("DEBUG" if settings.DEBUG else "INFO")
#     await connect_db()
#     yield


# # ── App ────────────────────────────────────────────────────────────────────────

# app = FastAPI(
#     title=settings.APP_NAME,
#     description="AI-powered scam detection — text & URL scanning, Google OAuth2, Stripe subscriptions.",
#     version="1.0.0",
#     lifespan=lifespan,
#     docs_url="/docs",
#     redoc_url="/redoc",
# )


# # ── CORS ───────────────────────────────────────────────────────────────────────

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:3000", "https://yourapp.com"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# # ── Request logging ────────────────────────────────────────────────────────────

# logger = logging.getLogger("scam_detector.access")

# @app.middleware("http")
# async def log_requests(request: Request, call_next):
#     start = time.perf_counter()
#     response = await call_next(request)
#     ms = (time.perf_counter() - start) * 1000
#     logger.info(f"{request.method} {request.url.path} → {response.status_code} ({ms:.1f}ms)")
#     return response


# # ── Error handlers ─────────────────────────────────────────────────────────────

# @app.exception_handler(RequestValidationError)
# async def validation_error_handler(request: Request, exc: RequestValidationError):
#     errors = [
#         {"field": " → ".join(str(loc) for loc in e["loc"]), "message": e["msg"]}
#         for e in exc.errors()
#     ]
#     return JSONResponse(
#         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
#         content={"detail": "Validation error", "errors": errors},
#     )

# @app.exception_handler(Exception)
# async def unhandled_error_handler(request: Request, exc: Exception):
#     logging.getLogger("scam_detector.errors").exception(
#         f"Unhandled error [{request.method} {request.url.path}]: {exc}"
#     )
#     return JSONResponse(
#         status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#         content={"detail": "An unexpected error occurred. Please try again."},
#     )


# # ── Routers ────────────────────────────────────────────────────────────────────

# app.include_router(auth_router)
# app.include_router(scan_router)
# app.include_router(subscription_router)


# # ── Health check ───────────────────────────────────────────────────────────────

# @app.get("/", tags=["Health"], summary="Health check")
# async def health():
#     return {"status": "ok", "app": settings.APP_NAME, "version": "1.0.0"}