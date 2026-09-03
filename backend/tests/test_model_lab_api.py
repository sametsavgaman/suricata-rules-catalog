import os
from fastapi.testclient import TestClient

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
