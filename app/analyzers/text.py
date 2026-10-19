import re

# Deliberately small, transparent phrase rules. This is not general-purpose
# Hindi/Gujarati translation or an ML classifier.
PATTERNS = [
    ("TEXT-URGENCY", "Urgency or threat", re.compile(r"urgent|immediately|act now|account suspended|blocked today|last chance|તાત્કાલિક|તરત|હમણાં જ|ખાતું બંધ|अभी|तुरंत|तत्काल|खाता बंद|अकाउंट बंद", re.I), "Pressure to act quickly can discourage independent verification.", "Pause and verify the request using contact details you already trust."),
    ("TEXT-CREDENTIAL", "Credential or OTP request", re.compile(r"\botp\b|one.?time password|password|\bpin\b|\bcvv\b|verification code|બેંક વિગતો|પાસવર્ડ|ઓટીપી|પિન|સીવીવી|ઓળખ કોડ|ओटीपी|पासवर्ड|पिन|सीवीवी|सत्यापन कोड|बैंक विवरण", re.I), "Legitimate services should not ask you to disclose a password, PIN, CVV, or OTP in a message.", "Never reply with a code or password; contact the organisation independently."),
    ("TEXT-PRIZE", "Payment or prize lure", re.compile(r"prize|winner|claim|refund|lottery|gift card|transfer|payment|cashback|કેશબેક|ઇનામ|લોટરી|રિફંડ|ચુકવણી|પૈસા મોકલો|इनाम|लॉटरी|रिफंड|कैशबैक|भुगतान|पैसे भेजें", re.I), "Unexpected prizes, refunds, or payment requests are common social-engineering hooks.", "Do not pay a fee or share financial details until the offer is verified through an official channel."),
    ("TEXT-LINK", "Link included", re.compile(r"https?://\S+|\bwww\.\S+", re.I), "A link in an unexpected message can lead to a lookalike sign-in page.", "Inspect the destination and navigate to the official site yourself."),
    ("TEXT-IMPERSONATION", "Authority or organisation claim", re.compile(r"bank|government|police|courier|support team|tax department|બેંક|સરકાર|પોલીસ|કુરિયર|સરકારી|बैंक|सरकार|पुलिस|कूरियर|आयकर विभाग", re.I), "A claimed organisation name does not prove who sent the message.", "Use a known phone number or official app to check the claim."),
]


def analyze_text(text: str) -> dict:
    findings = []
    for rule_id, label, pattern, why, recommendation in PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "rule_id": rule_id,
                "category": label,
                "severity": "high" if rule_id == "TEXT-CREDENTIAL" else "medium",
                "evidence": match.group(0)[:160],
                "why_it_matters": why,
                "recommendation": recommendation,
            })
    score = min(95, len(findings) * 18 + (15 if len(findings) >= 3 else 0))
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"
    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "summary": "Signals found in the supplied text; verify the sender through an independent channel." if findings else "Few rule-based scam signals found. This does not establish that the message is safe.",
        "recommendations": [
            "Do not share OTPs, passwords, PINs, or recovery codes.",
            "Contact the organisation using a number or website you already trust.",
            "Avoid opening links or paying until independently verified.",
        ],
        "coverage_note": "Phrase rules cover selected English, Hindi, and Gujarati cues. They can miss scams, misunderstand context, and produce false positives.",
    }
