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



def test_malformed_png_returns_safe_finding():
    import base64

    # Corrupt IDAT checksum: a realistic truncated or damaged upload.
    malformed_png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jMxkAAAAASUVORK5CYII="
    )
    response = client.post(
        "/api/analyze/media",
        files={"file": ("damaged.png", malformed_png, "image/png")},
    )
    assert response.status_code == 200
    assert any(item["rule_id"] == "MEDIA-IMAGE-INVALID" for item in response.json()["signals"])



def test_valid_image_returns_metadata_and_fingerprint():
    import struct
    import zlib

    def chunk(kind, payload):
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    image = b"\x89PNG\r\n\x1a\n"
    image += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    image += chunk(b"IDAT", zlib.compress(b"\x00\x14\x50\x78"))
    image += chunk(b"IEND", b"")
    response = client.post(
        "/api/analyze/media",
        files={"file": ("sample.png", image, "image/png")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["format"] == "PNG"
    assert result["dimensions"] == {"width": 1, "height": 1}
    assert len(result["sha256"]) == 64
