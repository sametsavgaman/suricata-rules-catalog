"""Allowlisted runtime settings. Secrets are kept in an ignored local file and never returned."""
import json, os
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from app.database.models import ApplicationSetting

ROOT = Path(__file__).resolve().parents[3]
SECRET_FILE = ROOT / ".runtime-secrets.json"
ALLOWLIST = {"AI_PROVIDER": False, "GEMINI_MODEL": False, "OLLAMA_BASE_URL": False, "OLLAMA_MODEL": False, "GEMINI_API_KEY": True}

def _secrets() -> dict:
    try: return json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    except Exception: return {}

def save_setting(db: Session, key: str, value: str | None):
    if ALLOWLIST[key]:
        data = _secrets(); data[key] = value or ""; SECRET_FILE.write_text(json.dumps(data), encoding="utf-8")
        return
    try:
        row = db.scalar(select(ApplicationSetting).where(ApplicationSetting.key == key))
    except SQLAlchemyError:
        row = None
    if not row: row = ApplicationSetting(key=key, is_secret=False); db.add(row)
    row.value = value
    db.commit()

def get_value(db: Session, key: str) -> str | None:
    if ALLOWLIST[key]: return _secrets().get(key) or os.getenv(key)
    try:
        row = db.scalar(select(ApplicationSetting).where(ApplicationSetting.key == key))
    except SQLAlchemyError:
        row = None
    return (row.value if row and row.value else os.getenv(key))

def effective_settings(db: Session, settings):
    updates = {}
    for key, attr in (("AI_PROVIDER","ai_provider"),("GEMINI_MODEL","gemini_model"),("OLLAMA_BASE_URL","ollama_base_url"),("OLLAMA_MODEL","ollama_model"),("GEMINI_API_KEY","gemini_api_key")):
        value = get_value(db, key)
        if value: updates[attr] = value
    return settings.model_copy(update=updates) if updates else settings
