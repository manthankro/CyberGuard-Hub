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


def test_url_endpoint_returns_independent_format_and_dns_status(monkeypatch):
    from app import main

    monkeypatch.setattr(
        main, "check_domain_status",
        lambda value: {"format_valid": True, "domain_status": "resolves", "domain_note": "test DNS response"},
    )
    response = client.post("/api/analyze/url", json={"url": "https://example.org/login"})
    assert response.status_code == 200
    result = response.json()
    assert result["url_validity"]["format_valid"] is True
    assert result["url_validity"]["domain_status"] == "resolves"
    assert result["risk_level"] == "low"


def test_video_review_requires_consent_and_uses_gemini_observations(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(
        main, "review_media_observations",
        lambda data, mime: ("A person walks through a room.", "Gemini"),
    )
    response = client.post(
        "/api/analyze/media",
        data={"ai_visual_review": "true"},
        files={"file": ("clip.mp4", b"test video bytes", "video/mp4")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["visual_review"]["provider"] == "Gemini"
    assert "not a deepfake/authenticity verdict" in result["visual_review"]["label"]


def test_email_exposure_requires_explicit_consent():
    response = client.post("/api/analyze/email-exposure", json={"email": "person@example.test", "consent": False})
    assert response.status_code == 400
    assert "consent" in response.json()["detail"].lower()


def test_email_exposure_returns_scoped_provider_result(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "hibp_api_key", "test-key")
    monkeypatch.setattr(
        main, "check_email_breaches",
        lambda email, key: {"found": False, "breaches": [], "source": "Have I Been Pwned", "note": "Known dataset only."},
    )
    response = client.post("/api/analyze/email-exposure", json={"email": "person@example.test", "consent": True})
    assert response.status_code == 200
    assert response.json()["found"] is False
    assert "email" not in response.json()



def test_media_report_has_consistent_explicit_unscored_fields():
    response = client.post(
        "/api/analyze/media",
        files={"file": ("clip.mp4", b"video bytes", "video/mp4")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] is None
    assert result["risk_level"] == "inconclusive"
    assert result["score_kind"] == "not_scored"
    assert "cannot establish" in result["score_explanation"]


def test_video_model_scan_requires_both_server_credentials(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "sightengine_api_user", "")
    monkeypatch.setattr(main.settings, "sightengine_api_secret", "")
    response = client.post(
        "/api/analyze/media",
        data={"ai_authenticity_scan": "true"},
        files={"file": ("clip.mp4", b"video bytes", "video/mp4")},
    )
    assert response.status_code == 503
    assert "SIGHTENGINE_API_USER" in response.json()["detail"]
    assert "SIGHTENGINE_API_SECRET" in response.json()["detail"]


def test_video_model_scan_runs_with_consent_and_credentials(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "sightengine_api_user", "test-user")
    monkeypatch.setattr(main.settings, "sightengine_api_secret", "test-secret")
    monkeypatch.setattr(
        main, "scan_video_authenticity",
        lambda data, filename, mime, user, secret: {
            "provider": "Sightengine",
            "status": "analyzed",
            "frames_analyzed": 1,
            "frames": [{"time": 0, "deepfake_probability": 0.12, "ai_generated_probability": 0.08}],
            "note": "Model signals only.",
        },
    )
    response = client.post(
        "/api/analyze/media",
        data={"ai_authenticity_scan": "true"},
        files={"file": ("clip.mp4", b"video bytes", "video/mp4")},
    )
    assert response.status_code == 200
    assert response.json()["authenticity_scan"]["provider"] == "Sightengine"
    assert response.json()["authenticity_scan"]["frames_analyzed"] == 1
