import asyncio, time
from typing import Literal
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.config import get_settings
from app.database.models import Rule, ComparisonReview
from app.database.repository import RuleRepository
from app.database.session import get_db, SessionLocal
from app.api.schemas import classification_to_read
from app.agent.factory import create_classification_provider, provider_config_error
from app.agent.schemas import ClassificationContext
from app.api.dependencies import get_classification_service
from app.services.runtime_config import ALLOWLIST, get_value, save_setting, effective_settings
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService

router = APIRouter(prefix="/model-lab", tags=["model-lab"])

class ConfigUpdate(BaseModel):
    gemini_model: str | None = Field(None, max_length=128)
    gemini_api_key: str | None = Field(None, max_length=512)
    ollama_base_url: str | None = Field(None, max_length=256)
    ollama_model: str | None = Field(None, max_length=128)
    ai_provider: Literal["gemini", "ollama"] | None = None

class CompareRequest(BaseModel):
    sid: int
    rev: int | None = None
    models: list[Literal["gemini", "ollama"]] = ["gemini", "ollama"]

class CompareReviewRequest(BaseModel):
    classification_a_id: int | None = None
    classification_b_id: int | None = None
    preference: Literal["GEMINI", "QWEN", "BOTH_ACCEPTABLE", "NEITHER", "UNSURE"]
    note: str | None = Field(None, max_length=2000)

def _safe_error(exc: Exception) -> str:
    text = str(exc).lower()
    if "401" in text or "api key" in text or "auth" in text: return "Authentication failed"
    if "404" in text or "model" in text and "not" in text: return "Model unavailable"
    if "429" in text or "quota" in text: return "Quota exceeded"
    if "connection" in text or "timeout" in text: return "Network error"
    return "Connection test failed"

@router.get("/config")
def config(db: Session = Depends(get_db)):
    settings = effective_settings(db, get_settings())
    return {"gemini": {"api_key_configured": bool(settings.gemini_api_key), "model": settings.gemini_model or "", "provider": "gemini", "inference_mode": "API"},
            "ollama": {"base_url": settings.ollama_base_url, "model": settings.ollama_model, "provider": "ollama", "inference_mode": "LOCAL"},
            "default_provider": settings.ai_provider, "classifier_version": settings.classifier_version}

@router.put("/config")
def update_config(payload: ConfigUpdate, db: Session = Depends(get_db)):
    values = {"GEMINI_MODEL": payload.gemini_model, "OLLAMA_BASE_URL": payload.ollama_base_url, "OLLAMA_MODEL": payload.ollama_model, "AI_PROVIDER": payload.ai_provider}
    if payload.ollama_base_url and not (payload.ollama_base_url.startswith("http://localhost") or payload.ollama_base_url.startswith("http://127.0.0.1")):
        raise HTTPException(400, "Ollama URL must use localhost or 127.0.0.1")
    for key, value in values.items():
        if value is not None and value != "": save_setting(db, key, value)
    if payload.gemini_api_key is not None: save_setting(db, "GEMINI_API_KEY", payload.gemini_api_key)
    return config(db)

async def _test(provider_name: str, db: Session):
    settings = effective_settings(db, get_settings()).model_copy(update={"ai_provider": provider_name, "classifier_version": "v2.1"})
    error = provider_config_error(settings)
    if error: return {"ok": False, "error": error}
    provider = create_classification_provider(settings)
    context = ClassificationContext(sid=0, msg="Return a minimal valid classification.", protocol="tcp", classtype=None, metadata=[], references=[], flow=[], flowbits=[], content=[], pcre=[], app_layer=[], entity_hint=None, category_hint=None, mitre_candidates=[], classifier_version="v2.1")
    started = time.perf_counter()
    try:
        result = await provider.classify(context)
        return {"ok": True, "provider": provider_name, "model": provider.model_name, "latency_ms": round((time.perf_counter()-started)*1000)}
    except Exception as exc: return {"ok": False, "provider": provider_name, "model": provider.model_name, "error": _safe_error(exc), "technical_detail": str(exc)[:300]}

@router.post("/test/{provider_name}")
async def test_provider(provider_name: Literal["gemini", "ollama"], db: Session = Depends(get_db)):
    return await _test(provider_name, db)

@router.get("/ollama/models")
async def ollama_models(db: Session = Depends(get_db)):
    settings = effective_settings(db, get_settings())
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            response = await client.get(settings.ollama_base_url.rstrip("/") + "/api/tags"); response.raise_for_status()
            return {"models": [x.get("name") for x in response.json().get("models", [])]}
    except Exception: return {"models": [], "error": "Ollama server is not reachable"}

@router.post("/compare")
async def compare(payload: CompareRequest, db: Session = Depends(get_db)):
    rule = db.scalar(select(Rule).where(Rule.sid == payload.sid, *( [Rule.rev == payload.rev] if payload.rev is not None else [])))
    if not rule: raise HTTPException(404, "Rule not found")
    results = []
    # Isolated sessions prevent one provider failure/transaction from masking the other.
    for name in dict.fromkeys(payload.models):
        local = SessionLocal()
        try:
            settings = effective_settings(local, get_settings()).model_copy(update={"ai_provider": name, "classifier_version": "v2.1"})
            service = ClassificationService(local, create_classification_provider(settings), settings, MitreRepository())
            item = await service.classify(local.get(Rule, rule.id), force=False)
            results.append(classification_to_read(item, []).model_dump(mode="json"))
        finally: local.close()
    return {"sid": rule.sid, "rev": rule.rev, "raw_rule": rule.raw_rule, "msg": rule.msg, "results": results}

@router.post("/{sid}/review")
def comparison_review(sid: int, payload: CompareReviewRequest, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    row = ComparisonReview(rule_id=rule.id, **payload.model_dump()); db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "preference": row.preference, "note": row.note, "created_at": row.created_at}

@router.get("/{sid}/reviews")
def comparison_reviews(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    rows = db.scalars(select(ComparisonReview).where(ComparisonReview.rule_id == rule.id).order_by(ComparisonReview.created_at.desc())).all()
    return {"items": [{"id": r.id, "preference": r.preference, "note": r.note, "created_at": r.created_at} for r in rows]}
