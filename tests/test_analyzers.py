from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media

def test_scam_text_exposes_matching_cues():
    result=analyze_text("URGENT: send your OTP now or account blocked. http://bad.test")
    assert result["risk_level"] == "high"
    assert {x["category"] for x in result["findings"]} >= {"Urgency or threat","Credential or OTP request","Suspicious link"}
    assert all(x.get("why_it_matters") and x.get("recommendation") for x in result["findings"])

def test_regional_language_rules_include_hindi_and_gujarati():
    hindi=analyze_text("तुरंत OTP भेजें और इनाम पाएं")
    gujarati=analyze_text("તાત્કાલિક તમારો ઓટીપી મોકલો અને ઇનામ મેળવો")
    assert {x["category"] for x in hindi["findings"]} >= {"Urgency or threat","Credential or OTP request","Payment or prize lure"}
    assert {x["category"] for x in gujarati["findings"]} >= {"Urgency or threat","Credential or OTP request","Payment or prize lure"}

def test_benign_text_is_not_declared_safe():
    result=analyze_text("Can we meet at 4pm?")
    assert result["risk_level"] == "low"
    assert "does not establish" in result["summary"]

def test_url_checks_suspicious_indicators_without_network():
    result=analyze_url("http://paypal.verify-account.example.com/login")
    assert result["risk_score"] > 0
    assert result["findings"]
    assert "does not visit" in result["disclaimer"]
    assert any(item["rule_id"] == "URL-BRAND-SUBDOMAIN" for item in result["findings"])
    assert all(item.get("why_it_matters") and item.get("recommendation") for item in result["findings"])

def test_malformed_url_returns_cautious_result():
    assert analyze_url("http://[broken") ["risk_level"] == "medium"

def test_url_scanner_flags_typo_lookalike_domain():
    result=analyze_url("https://paypa1.com/login")
    assert any(item["rule_id"] == "URL-TYPOLOOKALIKE" for item in result["findings"])

def test_code_audit_finds_sql_and_secret_patterns():
    result=analyze_code('cursor.execute("SELECT * FROM x WHERE id=" + value)\nAPI_KEY = "this_is_a_secret_value"')
    assert {f["title"] for f in result["findings"]} >= {"SQL injection risk","Hard-coded credential-like value"}
    assert result["risk_level"] == "high"

def test_media_does_not_claim_authenticity():
    result=inspect_media(b"not actually media", "sample.mp4", "video/mp4")
    assert result["assessment"] == "inconclusive"
    assert "does not detect deepfakes" in result["disclaimer"]

def test_media_image_hash_and_signature_inspection():
    from PIL import Image
    import io
    output=io.BytesIO()
    Image.new("RGB",(4,3),(20,40,60)).save(output,format="PNG")
    result=inspect_media(output.getvalue(),"sample.jpg","image/jpeg")
    assert result["format"] == "PNG"
    assert result["dimensions"] == {"width":4,"height":3}
    assert len(result["sha256"]) == 64
    assert {item["rule_id"] for item in result["signals"]} >= {"MEDIA-MIME-MISMATCH","MEDIA-EXTENSION-MISMATCH"}
    assert result["assessment"] == "inconclusive"

def test_triage_correlates_embedded_link_without_fetching():
    from app.analyzers.triage import analyze_triage
    result=analyze_triage("URGENT: send OTP now at http://example.com/login")
    assert result["risk_level"] == "high"
    assert len(result["url_analyses"]) == 1
    assert "does not visit" in result["disclaimer"]

def test_code_audit_redacts_secret_evidence():
    secret="sk_test_private_value"
    result=analyze_code(f'API_KEY = "{secret}"')
    assert secret not in str(result)
    assert "redacted" in result["findings"][0]["evidence"]
