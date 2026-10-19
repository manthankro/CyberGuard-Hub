import re
from urllib.parse import urlparse

PATTERNS = {
    "Urgency or threat": re.compile(r"\b(urgent|immediately|act now|account suspended|blocked today|last chance|તાત્કાલિક|अभी|तुरंत)\b", re.I),
    "Credential or OTP request": re.compile(r"\b(otp|one.?time password|password|pin|cvv|verification code|બેંક વિગતો|ओटीपी)\b", re.I),
    "Payment or prize lure": re.compile(r"\b(prize|winner|claim|refund|lottery|gift card|transfer|payment|કેશબેક|इनाम)\b", re.I),
    "Suspicious link": re.compile(r"https?://\S+|\bwww\.\S+", re.I),
    "Impersonation cue": re.compile(r"\b(bank|government|police|courier|support team|tax department|બેંક|सरकार)\b", re.I),
}

def analyze_text(text: str) -> dict:
    findings = []
    for label, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({"category": label, "evidence": match.group(0)[:160]})
    score = min(95, len(findings) * 18 + (15 if len(findings) >= 3 else 0))
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"
    return {"risk_score": score, "risk_level": level, "findings": findings,
            "summary": "Signals found in the supplied text; verify the sender through an independent channel." if findings else "Few rule-based scam signals found. This does not establish that the message is safe.",
            "recommendations": ["Do not share OTPs, passwords, PINs, or recovery codes.", "Contact the organisation using a number or website you already trust.", "Avoid opening links or paying until independently verified."]}
