from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)
def test_health_and_home():
    assert client.get("/health").json()["status"] == "ok"
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
