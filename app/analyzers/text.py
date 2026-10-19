import re

# Deliberately transparent phrase rules covering selected English, Hindi, and Gujarati patterns.
PATTERNS = [
    ("TEXT-URGENCY", "Urgency or threat", re.compile(r"urgent|immediately|act now|account suspended|blocked today|last chance|within 24 hours|action required|disconnected tonight|electricity cut|તાત્કાલિક|તરત|હમણાં જ|ખાતું બંધ|વીજળી કપાઈ|૨૪ કલાક|અત્યારે જ|अभी|तुरंत|तत्काल|खाता बंद|बिजली कट|अकाउंट बंद|24 घंटे के अंदर|कार्रवाई जरूरी", re.I), "high", "Pressure to act quickly can discourage independent verification.", "Pause and verify the request using contact details you already trust."),
    ("TEXT-CREDENTIAL", "Credential or OTP request", re.compile(r"\botp\b|one.?time password|password|\bpin\b|\bcvv\b|verification code|share code|enter otp|verify kyc|update kyc|pan card link|aadhar link|બેંક વિગતો|પાસવર્ડ|ઓટીપી|પિન|સીવીવી|ઓળખ કોડ|કેવાયસી|પાન કાર્ડ|ઓટીપી શેર|ओटीपी|पासवर्ड|पिन|सीवीवी|सत्यापन कोड|बैंक विवरण|केवाईसी अपडेट|पैन कार्ड लिंक|आधार लिंक", re.I), "high", "Legitimate services should not ask you to disclose a password, PIN, CVV, or OTP in a message.", "Never reply with a code or password; contact the organisation independently."),
    ("TEXT-PRIZE", "Payment or prize lure", re.compile(r"prize|winner|claim|refund|lottery|gift card|transfer|payment|cashback|bonus|won \$?\d+|jackpot|free recharge|કેશબેક|ઇનામ|લોટરી|રિફંડ|ચુકવણી|પૈસા મોકલો|બોનસ|જીત્યા|મફત રિચાર્જ|इनाम|लॉटरी|रिफंड|कैशबैक|भुगतान|पैसे भेजें|बोनस|जीते|मुफ्त रिचार्ज", re.I), "medium", "Unexpected prizes, refunds, or payment requests are common social-engineering hooks.", "Do not pay a fee or share financial details until the offer is verified through an official channel."),
    ("TEXT-LINK", "Suspicious link", re.compile(r"https?://\S+|\bwww\.\S+", re.I), "medium", "A link in an unexpected message can lead to a lookalike sign-in page.", "Inspect the destination and navigate to the official site yourself."),
    ("TEXT-IMPERSONATION", "Authority or organisation claim", re.compile(r"bank|government|police|courier|support team|tax department|income tax|sbi|hdfc|icici|rbi|customs department|india post|બેંક|સરકાર|પોલીસ|કુરિયર|સરકારી|ઇન્કમ ટેક્સ|કસ્ટમ્સ|बैंक|सरकार|पुलिस|कूरियर|आयकर विभाग|आरबीआई|कस्टम विभाग|डाक विभाग", re.I), "medium", "A claimed organisation name does not prove who sent the message.", "Use a known phone number or official app to check the claim."),
    ("TEXT-JOB-SCAM", "Work-from-home or easy earning lure", re.compile(r"work from home|part.?time job|daily income|earn \d+ per day|telegram task|youtube like task|daily profit|घर बैठे कमाई|पार्ट टाइम जॉब|प्रतिदिन कमाई|ટેલિગ્રામ ટાસ્ક|ઘેર બેઠા કમાણી", re.I), "medium", "High guaranteed returns for simple online tasks are standard job recruitment scam hooks.", "Never pay deposits or registration fees for freelance assignments or part-time work."),
]


def analyze_text(text: str) -> dict:
    findings = []
    detected_languages = set()
    if re.search(r"[\u0900-\u097F]", text):
        detected_languages.add("Hindi (Devanagari)")
    if re.search(r"[\u0A80-\u0AFF]", text):
        detected_languages.add("Gujarati")
    if re.search(r"[a-zA-Z]", text):
        detected_languages.add("English")

    for rule_id, label, pattern, default_sev, why, recommendation in PATTERNS:
        for match in pattern.finditer(text):
            severity = "high" if rule_id in ("TEXT-CREDENTIAL", "TEXT-URGENCY") else default_sev
            findings.append({
                "rule_id": rule_id,
                "category": label,
                "severity": severity,
                "evidence": match.group(0)[:160],
                "start": match.start(),
                "end": match.end(),
                "why_it_matters": why,
                "recommendation": recommendation,
            })
    score = min(95, len(findings) * 18 + (15 if len(findings) >= 3 else 0))
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"
    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "languages_detected": sorted(detected_languages) or ["Unknown"],
        "analyzed_length": len(text),
        "summary": "Signals found in the supplied text; verify the sender through an independent channel." if findings else "Few rule-based scam signals found. This does not establish that the message is safe.",
        "recommendations": [
            "Do not share OTPs, passwords, PINs, or recovery codes.",
            "Contact the organisation using a number or website you already trust.",
            "Avoid opening links or paying until independently verified.",
        ],
        "coverage_note": "Phrase rules cover selected English, Hindi, and Gujarati cues. They can miss scams, misunderstand context, and produce false positives.",
    }
