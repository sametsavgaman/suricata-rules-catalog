from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine_kwargs = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def ensure_schema_extensions() -> None:
    """Minimal additive migration for existing V1 SQLite databases."""
    if not settings.database_url.startswith("sqlite"): return
    if "classification_runs" not in inspect(engine).get_table_names():
        from app.database.models import Base
        Base.metadata.create_all(engine, tables=[Base.metadata.tables["classification_runs"]])
    if "classifications" not in inspect(engine).get_table_names(): return
    columns={c["name"] for c in inspect(engine).get_columns("classifications")}
    with engine.begin() as conn:
        if "classifier_version" not in columns: conn.execute(text("ALTER TABLE classifications ADD COLUMN classifier_version VARCHAR(16) DEFAULT 'v1'"))
        if "agent_activity" not in columns: conn.execute(text("ALTER TABLE classifications ADD COLUMN agent_activity JSON DEFAULT '{}'"))
        if "inspection_batch" not in columns: conn.execute(text("ALTER TABLE classifications ADD COLUMN inspection_batch VARCHAR(64)"))
        for name, sql_type in {"source_mitre_mapping":"JSON","final_mitre_mapping":"JSON","mitre_mapping_method":"VARCHAR(32)","mapping_reason":"TEXT","mitre_retrieval_score":"FLOAT","evidence_strength":"VARCHAR(16)","model_confidence":"FLOAT","validator_mitre_status":"VARCHAR(32)"}.items():
            if name not in columns: conn.execute(text(f"ALTER TABLE classifications ADD COLUMN {name} {sql_type}"))
        for name, sql_type in {"run_id":"VARCHAR(128)","classification_run_id":"INTEGER","model_display_name":"VARCHAR(160)","inference_mode":"VARCHAR(16)","model_config_json":"JSON","inference_duration_ms":"FLOAT"}.items():
            if name not in columns: conn.execute(text(f"ALTER TABLE classifications ADD COLUMN {name} {sql_type}"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
