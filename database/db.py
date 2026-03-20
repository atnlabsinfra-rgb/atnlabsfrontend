# database/db.py
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from config.settings import settings
from database.models import User, ScanRecord
import logging

logger = logging.getLogger("scam_detector.db")

# ── Module-level client reference ──────────────────────────────────────────────
# Stored here so disconnect_db() can close the same instance that was opened.
_client: AsyncIOMotorClient | None = None


async def connect_db() -> None:
    """
    Opens a MongoDB connection and initialises Beanie ODM.
    Called once at app startup via lifespan in main.py.
    """
    global _client

    _client = AsyncIOMotorClient(
        settings.MONGO_URI,

        # How long (ms) to wait for a server to be found in the replica set.
        # Keeps startup fast and fails loudly if Mongo is unreachable.
        serverSelectionTimeoutMS=5_000,

        # How long (ms) a socket can stay idle before being closed.
        socketTimeoutMS=10_000,

        # Connection pool — min keeps a few warm connections alive,
        # max prevents overwhelming the DB under traffic spikes.
        minPoolSize=2,
        maxPoolSize=20,
    )

    db = _client[settings.MONGO_DB_NAME]

    # Beanie registers all document models and creates indexes defined
    # via Indexed(...) in models.py.
    await init_beanie(
        database=db,
        document_models=[User, ScanRecord],
    )

    logger.info(f"✅ MongoDB connected → {settings.MONGO_DB_NAME}")


async def disconnect_db() -> None:
    """
    Closes the MongoDB connection pool.
    Called on app shutdown via lifespan in main.py.
    """
    global _client
    if _client is not None:
        _client.close()
        _client = None
        logger.info("MongoDB connection closed.")


async def ping_db() -> bool:
    """
    Health check — returns True if MongoDB is reachable, False otherwise.
    Can be called from a /health endpoint to monitor DB connectivity.
    """
    global _client
    if _client is None:
        return False
    try:
        await _client.admin.command("ping")
        return True
    except Exception as e:
        logger.warning(f"MongoDB ping failed: {e}")
        return False