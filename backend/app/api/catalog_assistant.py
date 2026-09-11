"""Local, read-only catalogue assistant; no arbitrary SQL or model tools."""
import asyncio
import ipaddress
import json
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database.session import get_db
from app.services.runtime_config import effective_settings
from app.agent.factory import provider_config_error
from app.services.catalog_assistant import (
    CatalogAnswer, CatalogQuestion, CatalogSearch, EXPLANATIONS,
    plan_question, query_catalog, query_family_catalog, validate_filters,
)
from app.services.scenario_analysis import ScenarioAnalysis, ScenarioQuestion, evaluate_scenario, plan_scenario
from app.services.helper_model import generate_structured, helper_config_error, helper_model_name, selected_helper_provider

router = APIRouter(prefix="/catalog/assistant", tags=["catalog assistant"])
_requests = {"ask": deque(), "search": deque(), "translate": deque(), "scenario": deque()}
_inference = asyncio.Semaphore(1)

class TranslationRequest(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=20)
    locale: str = "tr"


class TranslationResult(BaseModel):
    translations: list[str] = Field(min_length=1, max_length=20)


async def guarded_payload(request: Request):
    # This app has no user authentication. Do not expose a paid-model endpoint
    # on the LAN/public internet just because uvicorn binds to 0.0.0.0.
    try:
        local = ipaddress.ip_address(request.client.host).is_loopback
    except (ValueError, AttributeError):
        local = False
    if not local or request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(403, "Katalog asistanı yalnızca yerel bağlantılara açıktır.")
    allowed_origins = {get_settings().frontend_origin.rstrip("/"), "http://localhost:5173", "http://127.0.0.1:5173"}
    origin = request.headers.get("origin")
    if origin and origin not in allowed_origins:
        raise HTTPException(403, "Bu kaynaktan asistan isteğine izin verilmiyor.")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "JSON istek gövdesi gerekli.")
    kind = request.url.path.rsplit("/", 1)[-1]
    if kind == "scenario":
        kind = "scenario"
    queue = _requests[kind]
    now = time.monotonic()
    while queue and queue[0] < now - 60:
        queue.popleft()
    if len(queue) >= (4 if kind == "scenario" else 6 if kind == "ask" else 60):
        raise HTTPException(429, "İstek sınırına ulaşıldı. Bir dakika sonra tekrar deneyin.", headers={"Retry-After": "60"})
    queue.append(now)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(413, "İstek çok büyük.")
    try:
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(422, "Geçerli bir JSON nesnesi gerekli.") from None


def execute_search(db: Session, query: CatalogSearch):
    # Bound SQLite VM work, including COUNT, rather than relying only on LIMIT.
    connection = db.connection().connection.driver_connection
    sqlite = db.bind.dialect.name == "sqlite"
    deadline = time.monotonic() + 5
    if sqlite:
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        return query_family_catalog(db, query) if query.resource == "FAMILIES" else query_catalog(db, query)
    except ValueError:
        raise HTTPException(422, "Filtreler canonical katalog değerleriyle uyuşmuyor.") from None
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(503, "Katalog sorgusu tamamlanamadı. Daha dar filtrelerle tekrar deneyin.") from None
    finally:
        if sqlite:
            connection.set_progress_handler(None, 0)


@router.post("/ask", response_model=CatalogAnswer)
async def ask(response: Response, payload=Depends(guarded_payload), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    try:
        question = CatalogQuestion.model_validate(payload)
    except ValidationError:
        raise HTTPException(422, "Soru 3–1000 karakter olmalı; yalnızca question alanı kabul edilir.") from None
    settings = effective_settings(db, get_settings())
    helper_provider = selected_helper_provider(settings)
    if helper_config_error(settings, helper_provider):
        raise HTTPException(503, "Seçili yardımcı model yapılandırılmamış. Model Lab üzerinden bağlantıyı ayarlayın.")
    if _inference.locked():
        raise HTTPException(429, "Asistan başka bir soruyu işliyor. Kısa süre sonra tekrar deneyin.", headers={"Retry-After": "10"})
    async with _inference:
        try:
            plan = await plan_question(question.question, settings, helper_provider)
            validate_filters(plan.filters)
        except (ValidationError, ValueError):
            return CatalogAnswer(status="CLARIFY", answer="Bu isteği güvenilir filtrelere çeviremedim. Kategori, MITRE ID, protokol veya ürün durumunu açıkça belirterek tekrar sorun.")
        except Exception:
            # Do not return provider exception strings (URLs, credentials, prompts).
            raise HTTPException(502, "Yardımcı model isteği tamamlanamadı. Model Lab bağlantısını kontrol edip tekrar deneyin.") from None
    planner_model = helper_model_name(settings, helper_provider)
    if plan.intent == "OUT_OF_SCOPE":
        return CatalogAnswer(status="OUT_OF_SCOPE", answer="Katalogdaki Suricata kurallarını arama ve platformun işleyişini açıklama konusunda yardımcı olabilirim.", planner_model=planner_model, planner_provider=helper_provider)
    if plan.intent == "CLARIFY":
        return CatalogAnswer(status="CLARIFY", answer="Hangi ölçüte göre kayıt seçelim? Örneğin C2 kategorisi, DNS protokolü, bir MITRE ID veya APPROVED_FOR_PRODUCT ürün durumu belirtebilirsiniz. Birden fazla koşul birlikte uygulanır.", planner_model=planner_model, planner_provider=helper_provider)
    if plan.intent == "EXPLAIN_TOPIC":
        return CatalogAnswer(status="EXPLANATION", answer=EXPLANATIONS.get(plan.topic, EXPLANATIONS["product_selection"]), planner_model=planner_model, planner_provider=helper_provider, source="PLATFORM_GUIDE")
    if plan.intent in {"LIST_FAMILIES", "COUNT_FAMILIES"}:
        answer = await run_in_threadpool(execute_search, db, CatalogSearch(filters=plan.filters, resource="FAMILIES"))
        if plan.intent == "COUNT_FAMILIES":
            answer.families = []
    else:
        answer = await run_in_threadpool(execute_search, db, CatalogSearch(filters=plan.filters))
        if plan.intent == "COUNT_RULES":
            answer.items = []
    answer.planner_model = planner_model
    answer.planner_provider = helper_provider
    return answer


@router.post("/scenario", response_model=ScenarioAnalysis)
async def scenario(response: Response, payload=Depends(guarded_payload), db: Session = Depends(get_db)):
    """Map a customer narrative to verified local catalogue evidence."""
    response.headers["Cache-Control"] = "no-store"
    try:
        question = ScenarioQuestion.model_validate(payload)
    except ValidationError:
        raise HTTPException(422, "Senaryo 10–3000 karakter olmalı; yalnızca question alanı kabul edilir.") from None
    settings = effective_settings(db, get_settings())
    selected = settings.model_copy(update={"ai_provider": question.provider})
    config_error = provider_config_error(selected)
    if config_error:
        raise HTTPException(503, f"{question.provider.upper()} provider is not configured. Configure it in Model Lab first.")
    if _inference.locked():
        raise HTTPException(429, "Başka bir yardımcı model isteği işleniyor. Kısa süre sonra tekrar deneyin.", headers={"Retry-After": "10"})
    async with _inference:
        try:
            plan = await plan_scenario(question.question, selected, question.provider)
        except (ValidationError, ValueError):
            raise HTTPException(502, f"{question.provider.upper()} did not return a valid scenario plan. Try a more concrete scenario.") from None
        except Exception:
            raise HTTPException(502, f"{question.provider.upper()} scenario analysis failed. Check Model Lab configuration.") from None
    model_name = {"gemini": selected.gemini_model, "claude": selected.claude_model, "openai": selected.openai_model}[question.provider]
    return await run_in_threadpool(evaluate_scenario, db, plan, model_name or "NOT_CONFIGURED", question.provider)


@router.post("/search", response_model=CatalogAnswer)
async def search(response: Response, payload=Depends(guarded_payload), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    try:
        query = CatalogSearch.model_validate(payload)
    except ValidationError:
        raise HTTPException(422, "Geçersiz filtre veya sayfa sınırı.") from None
    if query.resource == "FAMILIES":
        return await run_in_threadpool(execute_search, db, query)
    return await run_in_threadpool(execute_search, db, query)

@router.post("/translate")
async def translate_texts(response: Response, raw_payload=Depends(guarded_payload), db: Session = Depends(get_db)):
    """Translate user-visible model prose without mutating the canonical classification record."""
    payload = TranslationRequest.model_validate(raw_payload)
    if payload.locale != "tr":
        return {"translations": payload.texts}
    settings = effective_settings(db, get_settings())
    helper_provider = selected_helper_provider(settings)
    if helper_config_error(settings, helper_provider):
        return {"translations": payload.texts, "fallback": True}
    try:
        result, provider, model = await generate_structured(
            settings,
            provider=helper_provider,
            instruction="Translate each item into precise Turkish for a cybersecurity analyst. Preserve IDs, product names and technical tokens. Return the translations in exactly the same order.",
            payload=json.dumps({"texts": payload.texts}, ensure_ascii=False),
            schema=TranslationResult,
            max_output_tokens=1800,
            timeout_seconds=30,
        )
        if len(result.translations) != len(payload.texts):
            raise ValueError("invalid translation response")
        return {"translations": [str(x) for x in result.translations], "provider": provider, "model": model}
    except Exception:
        return {"translations": payload.texts, "fallback": True}
