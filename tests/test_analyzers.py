from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media

def test_scam_text_exposes_matching_cues():
    result=analyze_text("URGENT: send your OTP now or account blocked. http://bad.test")
    assert result["risk_level"] == "high"
    assert {x["category"] for x in result["findings"]} >= {"Urgency or threat","Credential or OTP request","Suspicious link"}

def test_benign_text_is_not_declared_safe():
    result=analyze_text("Can we meet at 4pm?")
    assert result["risk_level"] == "low"
    assert "does not establish" in result["summary"]

def test_url_checks_suspicious_indicators_without_network():
    result=analyze_url("http://paypal.verify-account.example.com/login")
    assert result["risk_score"] > 0
    assert any("Brand-like" in f for f in result["findings"])
    assert "does not visit" in result["disclaimer"]

def test_malformed_url_returns_cautious_result():
    assert analyze_url("http://[broken") ["risk_level"] == "medium"

def test_code_audit_finds_sql_and_secret_patterns():
    result=analyze_code('cursor.execute("SELECT * FROM x WHERE id=" + value)\nAPI_KEY = "this_is_a_secret_value"')
    assert {f["title"] for f in result["findings"]} >= {"SQL injection risk","Hard-coded credential-like value"}

def test_media_does_not_claim_authenticity():
    result=inspect_media(b"not actually media", "sample.mp4", "video/mp4")
    assert result["assessment"] == "inconclusive"
    assert "does not detect deepfakes" in result["disclaimer"]
