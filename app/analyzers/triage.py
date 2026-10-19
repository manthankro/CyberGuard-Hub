import re
from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url

URL_PATTERN = re.compile(r"""https?://[^\s<>"']+|www\.[^\s<>"']+|(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|co|in|io|ai|app|dev|xyz|info|biz|me|uk|us|ca|site|online|store|tech|edu|gov|link|live|shop)(?::\d+)?(?:/[^\s<>"']*)?""", re.I)

def analyze_triage(content: str) -> dict:
    """Correlate message cues with any embedded URL indicators without opening links."""
    text_result = analyze_text(content)
    urls = list(dict.fromkeys(match.group(0).rstrip(".,!?;:)") for match in URL_PATTERN.finditer(content)))[:10]
    url_results = [{"url": url, **analyze_url(url)} for url in urls]
    url_score = max((item["risk_score"] for item in url_results), default=0)
    text_score = text_result["risk_score"]
    combined = min(99, max(text_score, url_score) + (8 if text_score >= 40 and url_score >= 40 else 0))
    level = "high" if combined >= 55 else "medium" if combined >= 25 else "low"
    evidence = [f"Message: {item['category']} — {item['evidence']}" for item in text_result["findings"]]
    for result in url_results:
        evidence.extend(
            f"Link ({result['host']}): {finding.get('category', 'Indicator')} — {finding.get('evidence', '')}"
            if isinstance(finding, dict) else f"Link ({result['host']}): {finding}"
            for finding in result["findings"]
        )
    if not evidence:
        evidence.append("No configured high-signal patterns matched. Absence of a match does not establish safety.")
    return {
        "risk_score": combined,
        "risk_level": level,
        "summary": f"Correlated {len(text_result['findings'])} message signal(s) and inspected {len(url_results)} embedded link(s).",
        "evidence": evidence,
        "message_analysis": text_result,
        "url_analyses": url_results,
        "recommendations": [
            "Do not share passwords, OTPs, PINs, recovery codes, or payment details in response to an unexpected message.",
            "Verify the request with the organisation using contact details you already trust.",
            "Do not open embedded links until the sender and destination are independently verified.",
        ],
        "analysis_mode": "correlated local rules",
        "disclaimer": "An indicator score is not a probability or a verdict. CyberGuard inspects URL text only and does not visit links or query live reputation services.",
    }
