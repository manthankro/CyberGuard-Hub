import httpx
import pytest

from app.analyzers.external import check_email_breaches, inspect_c2pa, scan_video_authenticity


def test_email_breach_lookup_redacts_address_and_returns_provider_data(monkeypatch):
    captured = {}
    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return httpx.Response(200, json=[{
            "Name": "ExampleBreach", "Title": "Example Breach", "Domain": "example.test",
            "BreachDate": "2024-01-01", "DataClasses": ["Email addresses"], "IsVerified": True
        }], request=httpx.Request("GET", url))
    monkeypatch.setattr("app.analyzers.external.httpx.get", fake_get)

    result = check_email_breaches("person@example.test", "test-key")

    assert result["found"] is True
    assert result["breaches"][0]["title"] == "Example Breach"
    assert "person@example.test" not in str(result)
    assert captured["headers"]["hibp-api-key"] == "test-key"


def test_email_breach_lookup_not_found_is_scoped(monkeypatch):
    def fake_get(url, **kwargs):
        return httpx.Response(404, request=httpx.Request("GET", url))
    monkeypatch.setattr("app.analyzers.external.httpx.get", fake_get)
    result = check_email_breaches("person@example.test", "test-key")
    assert result["found"] is False
    assert "not a complete dark-web search" in result["note"]


def test_email_rejects_invalid_address():
    with pytest.raises(ValueError):
        check_email_breaches("not-an-email", "test-key")


def test_video_model_response_is_labeled_probabilistic(monkeypatch):
    def fake_post(url, **kwargs):
        return httpx.Response(200, json={
            "status": "success",
            "data": {"frames": [{"time": 1.25, "deepfake": {"score": 0.2}, "genai": {"score": 0.8, "matches": []}}]}
        }, request=httpx.Request("POST", url))
    monkeypatch.setattr("app.analyzers.external.httpx.post", fake_post)
    result = scan_video_authenticity(b"video", "clip.mp4", "video/mp4", "user", "secret")
    assert result["frames_analyzed"] == 1
    assert result["frames"][0]["ai_generated_probability"] == 0.8
    assert "not forensic proof" in result["note"]


def test_c2pa_absence_does_not_claim_authenticity():
    result = inspect_c2pa(b"not a video", "video/mp4")
    assert result["status"] in {"unavailable", "no_valid_manifest"}
    assert "does not prove" in result["note"]
