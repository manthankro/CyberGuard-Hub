import re

# Contextual, explainable phrase rules. Generic words such as "claim" or
# "bank" are not enough by themselves to label an ordinary message a scam.
PATTERNS = [
    ("TEXT-URGENCY", "Urgency or threat", re.compile(
        r"\b(?:urgent(?:ly)?|immediately|act now|last chance|within 24 hours|action required|account (?:is )?(?:suspended|blocked)|blocked today|disconnected tonight|electricity (?:will be )?cut)\b|તાત્કાલિક|તરત|હમણાં જ|ખાતું બંધ|વીજળી કપાઈ|૨૪ કલાક|અત્યારે જ|अभी|तुरंत|तत्काल|खाता बंद|बिजली कट|अकाउंट बंद|24 घंटे के अंदर|कार्रवाई जरूरी",
        re.I), "medium", "Pressure or threats can discourage independent verification.",
        "Pause and verify the request using contact details you already trust."),
    ("TEXT-CREDENTIAL", "Credential or OTP request", re.compile(
        r"(?:\b(?:send|share|reply with|provide|enter|submit|tell me|give me)\b.{0,45}\b(?:otp|one.?time password|password|pin|cvv|verification code|recovery code)\b)|(?:\b(?:otp|one.?time password|password|pin|cvv|verification code|recovery code)\b.{0,45}\b(?:send|share|reply|provide|enter|submit|tell|give)\b)|(?:ઓટીપી.{0,35}(?:મોકલો|આપો|શેર)|(?:ઓટીપી|પાસવર્ડ|પિન).{0,35}(?:મોકલો|આપો|શેર))|(?:(?:ओटीपी|पासवर्ड|पिन|सत्यापन कोड).{0,35}(?:भेजें|बताएं|साझा|दर्ज करें))",
        re.I), "high", "A message asking you to disclose a password, PIN, CVV, OTP, or recovery code is a strong warning sign.",
        "Never reply with a code or password; contact the organisation independently."),
    ("TEXT-PRIZE", "Payment or prize lure", re.compile(
        r"(?:\b(?:pay|send|transfer)\b.{0,50}\b(?:fee|tax|deposit|processing charge|payment)\b)|(?:\b(?:prize|lottery|cashback|refund|bonus|gift card|winner)\b.{0,60}\b(?:claim|pay|fee|deposit|click|transfer|send|won)\b)|(?:\b(?:claim|pay|fee|deposit|transfer|send)\b.{0,60}\b(?:prize|lottery|cashback|refund|bonus|gift card|reward)\b)|(?:પૈસા મોકલો.{0,30}(?:ઇનામ|રિફંડ)|ઇનામ.{0,30}(?:મેળવવા|ફી|ચુકવો))|(?:इनाम.{0,30}(?:पाने|शुल्क|भुगतान)|(?:शुल्क|पैसे भेजें).{0,30}इनाम)",
        re.I), "medium", "Unexpected rewards tied to a fee, payment, or click are common social-engineering hooks.",
        "Do not pay or share financial details until the offer is verified through an official channel."),
    ("TEXT-LINK", "Link included", re.compile(r"https?://\S+|\bwww\.\S+", re.I), "low",
        "A link's presence alone does not make a message malicious, but unexpected links deserve a destination check.",
        "Check the destination independently and open the official site yourself if unsure."),
    ("TEXT-IMPERSONATION", "Organisation or authority claim", re.compile(
        r"\b(?:bank|government|police|courier|support team|tax department|income tax|sbi|hdfc|icici|rbi|customs department|india post)\b|બેંક|સરકાર|પોલીસ|કુરિયર|સરકારી|ઇન્કમ ટેક્સ|કસ્ટમ્સ|बैंक|सरकार|पुलिस|कूरियर|आयकर विभाग|आरबीआई|कस्टम विभाग|डाक विभाग",
        re.I), "low", "A claimed organisation name does not prove who sent the message.",
        "Use a known phone number or official app to check the claim."),
    ("TEXT-JOB-SCAM", "Work-from-home or easy earning lure", re.compile(
        r"\b(?:work from home|part.?time job|daily income|earn \d+ per day|telegram task|youtube like task|daily profit)\b|घर बैठे कमाई|पार्ट टाइम जॉब|प्रतिदिन कमाई|ટેલિગ્રામ ટાસ્ક|ઘેર બેઠા કમાણી",
        re.I), "medium", "Guaranteed returns for simple online tasks can be a job-recruitment scam hook.",
        "Never pay deposits or registration fees for freelance assignments or part-time work."),
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
        match = pattern.search(text)
        if not match:
            continue
        severity = "high" if rule_id == "TEXT-CREDENTIAL" else default_sev
        findings.append({
            "rule_id": rule_id, "category": label, "severity": severity,
            "evidence": match.group(0)[:160], "start": match.start(), "end": match.end(),
            "why_it_matters": why, "recommendation": recommendation,
        })

    # Count distinct signal types once, so repeated words cannot inflate a score.
    weights = {"TEXT-CREDENTIAL": 48, "TEXT-URGENCY": 24, "TEXT-PRIZE": 20,
               "TEXT-JOB-SCAM": 16, "TEXT-LINK": 7, "TEXT-IMPERSONATION": 5}
    score = min(95, sum(weights.get(item["rule_id"], 0) for item in findings))
    level = "high" if score >= 55 else "medium" if score >= 20 else "low"
    return {
        "risk_score": score, "risk_level": level, "findings": findings,
        "languages_detected": sorted(detected_languages) or ["Unknown"],
        "analyzed_length": len(text),
        "summary": "Contextual warning signals were found; verify the sender through an independent channel." if findings else "No configured high-signal phrases matched. This does not establish that the message is safe.",
        "recommendations": [
            "Do not share OTPs, passwords, PINs, or recovery codes.",
            "Contact the organisation using a number or website you already trust.",
            "Avoid opening links or paying until independently verified.",
        ],
        "coverage_note": "Contextual phrase rules cover selected English, Hindi, and Gujarati cues. They can miss scams, misunderstand context, and produce false positives.",
    }
