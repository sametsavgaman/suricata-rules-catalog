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
    openai_base_url: str | None = Field(None, max_length=256)
    openai_model: str | None = Field(None, max_length=128)
    openai_api_key: str | None = Field(None, max_length=512)
    claude_base_url: str | None = Field(None, max_length=256)
    claude_model: str | None = Field(None, max_length=128)
    claude_api_key: str | None = Field(None, max_length=512)
    gemini_model: str | None = Field(None, max_length=128)
    gemini_api_key: str | None = Field(None, max_length=512)
    ollama_base_url: str | None = Field(None, max_length=256)
    ollama_model: str | None = Field(None, max_length=128)
    ai_provider: Literal["openai", "gemini", "claude", "ollama"] | None = None

class CompareRequest(BaseModel):
    sid: int
    rev: int | None = None
    models: list[Literal["openai", "gemini", "claude", "ollama"]] = ["gemini", "ollama"]

class CompareReviewRequest(BaseModel):
    classification_a_id: int | None = None
    classification_b_id: int | None = None
    preference: Literal["OPENAI", "GEMINI", "CLAUDE", "QWEN", "BOTH_ACCEPTABLE", "NEITHER", "UNSURE"]
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
    return {"openai": {"api_key_configured": bool(settings.openai_api_key), "model": settings.openai_model or "", "base_url": settings.openai_base_url or "https://api.openai.com/v1", "provider": "openai", "inference_mode": "API_COMPATIBLE"}, "claude": {"api_key_configured": bool(settings.claude_api_key), "model": settings.claude_model or "", "base_url": settings.claude_base_url, "provider": "claude", "inference_mode": "API"}, "gemini": {"api_key_configured": bool(settings.gemini_api_key), "model": settings.gemini_model or "", "provider": "gemini", "inference_mode": "API"},
            "ollama": {"base_url": settings.ollama_base_url, "model": settings.ollama_model, "provider": "ollama", "inference_mode": "LOCAL"},
            "default_provider": settings.ai_provider, "classifier_version": settings.classifier_version}

@router.put("/config")
def update_config(payload: ConfigUpdate, db: Session = Depends(get_db)):
    if payload.ollama_model not in (None, "", "qwen3:8b"):
        raise HTTPException(400, "Qwen reference model is fixed to qwen3:8b")
    values = {"OPENAI_BASE_URL": payload.openai_base_url, "OPENAI_MODEL": payload.openai_model, "CLAUDE_BASE_URL": payload.claude_base_url, "CLAUDE_MODEL": payload.claude_model, "GEMINI_MODEL": payload.gemini_model, "OLLAMA_BASE_URL": payload.ollama_base_url, "OLLAMA_MODEL": payload.ollama_model, "AI_PROVIDER": payload.ai_provider}
    if payload.ollama_base_url and not (payload.ollama_base_url.startswith("http://localhost") or payload.ollama_base_url.startswith("http://127.0.0.1")):
        raise HTTPException(400, "Ollama URL must use localhost or 127.0.0.1")
    prospective = effective_settings(db, get_settings())
    prospective_updates = {
        attr: value for attr, value in {
            "openai_base_url": payload.openai_base_url, "openai_model": payload.openai_model,
            "claude_base_url": payload.claude_base_url, "claude_model": payload.claude_model,
            "gemini_model": payload.gemini_model, "ollama_base_url": payload.ollama_base_url,
            "ollama_model": payload.ollama_model, "ai_provider": payload.ai_provider,
        }.items() if value is not None and value != ""
    }
    for attr, value in (("openai_api_key", payload.openai_api_key),
                        ("claude_api_key", payload.claude_api_key),
                        ("gemini_api_key", payload.gemini_api_key)):
        if value is not None:
            prospective_updates[attr] = value
    prospective = prospective.model_copy(update=prospective_updates)
    if payload.ai_provider:
        error = provider_config_error(prospective)
        if error:
            raise HTTPException(400, error)
    for key, value in values.items():
        if value is not None and value != "": save_setting(db, key, value)
    if payload.gemini_api_key is not None: save_setting(db, "GEMINI_API_KEY", payload.gemini_api_key)
    if payload.openai_api_key is not None: save_setting(db, "OPENAI_API_KEY", payload.openai_api_key)
    if payload.claude_api_key is not None: save_setting(db, "CLAUDE_API_KEY", payload.claude_api_key)
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
async def test_provider(provider_name: Literal["openai", "gemini", "claude", "ollama"], db: Session = Depends(get_db)):
    return await _test(provider_name, db)

@router.get("/status")
async def provider_status(db: Session = Depends(get_db)):
    """Run a lightweight live check for every provider used by the UI.

    Unconfigured providers return a deterministic unavailable state from
    ``_test``; configured providers are verified with the same minimal
    classification request as the manual Test Connection action.
    """
    names = ("openai", "claude", "gemini", "ollama")
    checks = await asyncio.gather(*(_test(name, db) for name in names), return_exceptions=True)
    providers = {}
    for name, result in zip(names, checks):
        if isinstance(result, Exception):
            providers[name] = {"ok": False, "provider": name, "error": _safe_error(result)}
            continue
        providers[name] = {key: value for key, value in result.items() if key != "technical_detail"}
    return {"providers": providers, "checked_at": time.time()}

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
    names = [name for name in dict.fromkeys(payload.models) if name != "ollama"]
    names.append("ollama")
    for name in names:
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
