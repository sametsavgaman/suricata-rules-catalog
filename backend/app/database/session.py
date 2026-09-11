from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine_kwargs = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def ensure_schema_extensions() -> None:
    """Minimal additive migration for existing V1 SQLite databases."""
    from app.database.models import Base
    # New standalone tables are safe additive migrations on both SQLite and
    # PostgreSQL; existing deployments do not need a destructive migration.
    Base.metadata.create_all(
        engine,
        tables=[
            Base.metadata.tables["cloud_batches"],
            Base.metadata.tables["cloud_batch_reservations"],
            Base.metadata.tables["local_classification_claims"],
            Base.metadata.tables["product_ruleset_import_batches"],
            Base.metadata.tables["product_ruleset_import_items"],
            Base.metadata.tables["forced_mitre_mappings"],
        ],
    )
    if "classifications" in inspect(engine).get_table_names():
        # create_all does not reliably add newly declared indexes to an
        # already-existing table on every SQLAlchemy/backend combination.
        # Keep the migration additive and idempotent for existing catalogs.
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_classifications_status_rule_id_id "
                "ON classifications (classification_status, rule_id, id)"
            ))
    if not settings.database_url.startswith("sqlite"): return
    if "classification_runs" not in inspect(engine).get_table_names():
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
    if "cloud_batches" in inspect(engine).get_table_names():
        cloud_columns = {c["name"] for c in inspect(engine).get_columns("cloud_batches")}
        if "target_model_digest" not in cloud_columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cloud_batches ADD COLUMN target_model_digest VARCHAR(128)"))
    if "local_classification_claims" in inspect(engine).get_table_names():
        claim_columns = {c["name"] for c in inspect(engine).get_columns("local_classification_claims")}
        with engine.begin() as conn:
            if "owner_pid" not in claim_columns:
                conn.execute(text("ALTER TABLE local_classification_claims ADD COLUMN owner_pid INTEGER"))
            if "owner_host" not in claim_columns:
                conn.execute(text("ALTER TABLE local_classification_claims ADD COLUMN owner_host VARCHAR(255)"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
