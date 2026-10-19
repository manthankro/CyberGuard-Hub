from fastapi.testclient import TestClient
from app.main import app
import os

client=TestClient(app)
def test_health_and_home():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/health").json()["providers"]["local_rules"] is True
    assert "CyberGuard Hub" in client.get("/").text

def test_text_endpoint():
    response=client.post("/api/analyze/text",json={"text":"Your account is blocked, send OTP now"})
    assert response.status_code == 200
    assert response.json()["risk_score"] > 0

def test_code_endpoint():
    response=client.post("/api/analyze/code",json={"code":"cursor.execute(\"SELECT * FROM x WHERE id=\" + user_id)"})
    assert response.status_code == 200
    assert response.json()["findings"]

def test_validation():
    assert client.post("/api/analyze/url",json={"url":""}).status_code == 422

def test_module_catalog_and_triage():
    modules=client.get("/api/modules").json()["modules"]
    assert {item["id"] for item in modules} >= {"triage","text","url","media","code"}
    result=client.post("/api/analyze/triage",json={"content":"URGENT: send OTP at http://example.com"})
    assert result.status_code == 200
    assert result.json()["url_analyses"]

def test_rules_catalog():
    rules_resp = client.get("/api/rules")
    assert rules_resp.status_code == 200
    rules = rules_resp.json()["rules"]
    assert len(rules) >= 15
    assert any(r["module"] == "text" for r in rules)
    assert any(r["module"] == "code" for r in rules)
    assert any(r["module"] == "url" for r in rules)



def test_vercel_upload_limit_is_safe(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    health = client.get("/health").json()
    assert health["max_upload_mb"] == 4
    assert health["groq_model"]


def test_local_upload_limit_uses_configuration(monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    assert client.get("/health").json()["max_upload_mb"] >= 1
