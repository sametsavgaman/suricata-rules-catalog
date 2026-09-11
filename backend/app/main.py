import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import classification, rules, stats, model_lab, catalog, catalog_assistant, families, mitre, audit
from app.config import get_settings
from app.database.session import Base, engine, ensure_schema_extensions
from app.api.catalog import warm_catalog_facets
from app.services.detection_families import warm_family_cache

logger = logging.getLogger(__name__)


async def _warm_read_models() -> None:
    try:
        await asyncio.gather(
            asyncio.to_thread(warm_family_cache),
            asyncio.to_thread(warm_catalog_facets),
        )
    except Exception:
        # Read-model warming is an optimization; a failed warm-up must never
        # prevent the API from starting or serving the catalogue.
        logger.exception("Detection family read-model warm-up failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_schema_extensions()
    warm_task = asyncio.create_task(_warm_read_models())
    try:
        yield
    finally:
        warm_task.cancel()
        with suppress(asyncio.CancelledError):
            await warm_task


settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(rules.router, prefix="/api")
app.include_router(classification.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(model_lab.router, prefix="/api")
app.include_router(catalog.router, prefix="/api")
app.include_router(catalog_assistant.router, prefix="/api")
app.include_router(families.router, prefix="/api")
app.include_router(mitre.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
