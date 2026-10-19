from fastapi.testclient import TestClient
from app.main import app

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
    response=client.post("/api/analyze/code",json={"code":"query = \"SELECT * FROM x WHERE id=\" + user_id"})
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
