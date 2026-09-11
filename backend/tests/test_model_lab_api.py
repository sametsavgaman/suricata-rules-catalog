import os
import asyncio
import pytest
from fastapi.testclient import TestClient

from app.api import dependencies, model_lab
from app.config import Settings

def test_model_lab_config_never_returns_api_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "do-not-return")
    from app.main import app
    response = TestClient(app).get("/api/model-lab/config")
    assert response.status_code == 200
    body = response.json()
    assert body["gemini"]["api_key_configured"] is True
    assert "do-not-return" not in response.text
    assert "api_key" not in body["gemini"]

def test_ollama_url_is_local_only():
    from app.main import app
    response = TestClient(app).put("/api/model-lab/config", json={"ollama_base_url":"http://169.254.169.254"})
    assert response.status_code == 400


@pytest.mark.parametrize("provider", ["openai", "gemini", "claude", "ollama"])
def test_model_lab_accepts_every_supported_default_provider(provider):
    assert model_lab.ConfigUpdate(ai_provider=provider).ai_provider == provider


@pytest.mark.parametrize("provider", ["openai", "gemini", "claude"])
def test_model_lab_accepts_every_supported_helper_provider(provider):
    assert model_lab.ConfigUpdate(helper_provider=provider).helper_provider == provider


def test_configured_helper_provider_can_be_selected(monkeypatch):
    saved = []
    settings = Settings(claude_api_key="secret", claude_model="claude-test")
    monkeypatch.setattr(model_lab, "get_settings", lambda: settings)
    monkeypatch.setattr(model_lab, "effective_settings", lambda db, value: value)
    monkeypatch.setattr(model_lab, "save_setting", lambda db, key, value: saved.append((key, value)))
    monkeypatch.setattr(model_lab, "config", lambda db: {"helper_provider": "claude"})
    result = model_lab.update_config(model_lab.ConfigUpdate(helper_provider="claude"), object())
    assert result["helper_provider"] == "claude"
    assert ("HELPER_PROVIDER", "claude") in saved


def test_unconfigured_helper_provider_cannot_be_selected(monkeypatch):
    saved = []
    settings = Settings(openai_api_key=None, openai_model="gpt-test")
    monkeypatch.setattr(model_lab, "get_settings", lambda: settings)
    monkeypatch.setattr(model_lab, "effective_settings", lambda db, value: value)
    monkeypatch.setattr(model_lab, "save_setting", lambda db, key, value: saved.append((key, value)))
    with pytest.raises(model_lab.HTTPException) as exc:
        model_lab.update_config(model_lab.ConfigUpdate(helper_provider="openai"), object())
    assert exc.value.status_code == 400
    assert exc.value.detail == "OPENAI_API_KEY_NOT_CONFIGURED"
    assert saved == []


def test_claude_config_can_be_saved_and_selected(monkeypatch):
    saved = []
    monkeypatch.setattr(model_lab, "effective_settings", lambda db, value: value)
    monkeypatch.setattr(model_lab, "save_setting", lambda db, key, value: saved.append((key, value)))
    monkeypatch.setattr(model_lab, "config", lambda db: {"default_provider": "claude"})
    result = model_lab.update_config(
        model_lab.ConfigUpdate(ai_provider="claude", claude_model="claude-test", claude_api_key="secret"),
        object(),
    )
    assert result["default_provider"] == "claude"
    assert ("AI_PROVIDER", "claude") in saved
    assert ("CLAUDE_MODEL", "claude-test") in saved
    assert ("CLAUDE_API_KEY", "secret") in saved


def test_unconfigured_provider_cannot_be_activated(monkeypatch):
    saved = []
    settings = Settings(ai_provider="ollama", openai_api_key=None, openai_model=None)
    monkeypatch.setattr(model_lab, "get_settings", lambda: settings)
    monkeypatch.setattr(model_lab, "effective_settings", lambda db, value: value)
    monkeypatch.setattr(model_lab, "save_setting", lambda db, key, value: saved.append((key, value)))
    with pytest.raises(model_lab.HTTPException) as exc:
        model_lab.update_config(model_lab.ConfigUpdate(ai_provider="openai"), object())
    assert exc.value.status_code == 400
    assert exc.value.detail == "OPENAI_API_KEY_NOT_CONFIGURED"
    assert saved == []


@pytest.mark.parametrize(
    ("provider", "model"),
    [("openai", "gpt-test"), ("gemini", "gemini-test"), ("claude", "claude-test"), ("ollama", "qwen3:8b")],
)
def test_rule_classification_dependency_routes_all_provider_variants(monkeypatch, provider, model):
    settings = Settings(
        ai_provider="ollama",
        openai_api_key="openai-key", openai_model="gpt-test",
        gemini_api_key="gemini-key", gemini_model="gemini-test",
        claude_api_key="claude-key", claude_model="claude-test",
        ollama_model="qwen3:8b",
    )
    monkeypatch.setattr(dependencies, "get_settings", lambda: settings)
    monkeypatch.setattr(dependencies, "effective_settings", lambda db, value: value)
    service = dependencies.get_classification_service(db=object(), execution_provider=provider)
    assert service.settings.ai_provider == provider
    assert service.settings.classifier_version == "v2.1"
    assert service.provider.model_name == model


def test_rule_classification_openapi_lists_all_provider_overrides():
    from app.main import app
    parameters = app.openapi()["paths"]["/api/rules/{sid}/classify"]["post"]["parameters"]
    schema = next(item["schema"] for item in parameters if item["name"] == "execution_provider")
    enum_values = set()
    for branch in schema.get("anyOf", [schema]):
        enum_values.update(branch.get("enum", []))
    assert enum_values == {"openai", "gemini", "claude", "ollama"}


def test_provider_status_checks_every_provider_without_exposing_diagnostics(monkeypatch):
    async def fake_test(provider, db):
        return {"ok": provider == "gemini", "provider": provider, "technical_detail": "secret"}

    monkeypatch.setattr(model_lab, "_test", fake_test)
    body = asyncio.run(model_lab.provider_status(object()))
    assert set(body["providers"]) == {"openai", "claude", "gemini", "ollama"}
    assert body["providers"]["gemini"]["ok"] is True
    assert "technical_detail" not in body["providers"]["openai"]
