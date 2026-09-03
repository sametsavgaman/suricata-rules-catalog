from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import classification, rules, stats, model_lab, catalog
from app.config import get_settings
from app.database.session import Base, engine, ensure_schema_extensions


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_schema_extensions()
    yield


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


@app.get("/health")
def health():
    return {"status": "ok"}
