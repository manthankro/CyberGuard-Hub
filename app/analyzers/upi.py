"""UPI ID and payment-request heuristic analysis (India-focused, offline)."""
from __future__ import annotations

import re
from typing import Any

# VPA pattern: local-part@psp (common PSPs)
VPA_RE = re.compile(
    r"\b([a-zA-Z0-9._-]{2,60})@(ybl|okaxis|okhdfcbank|oksbi|okicici|paytm|"
    r"ibl|axl|apl|upi|okbizaxis|okyesbank|okkotak|okidfc|okpnb|okbob|"
    r"okunion|okcanara|oksbi|fbpe|freecharge|amazonpay|googlepay|gpay)\b",
    re.I,
)

# Generic @handle that looks like UPI
GENERIC_VPA_RE = re.compile(r"\b([a-zA-Z0-9._-]{3,50})@([a-zA-Z][a-zA-Z0-9]{1,20})\b")

PHONE_IN_PAYMENT_RE = re.compile(
    r"(?:\+?91[\s-]?)?([6-9]\d{9})\s*(?:@|\b(?:pay|send|upi)\b)",
    re.I,
)

SUSPICIOUS_LOCAL = re.compile(
    r"(?:refund|kyc|verify|secure|official|support| helpline|bank|sbi|hdfc|"
    r"icici|axis|lottery|prize|cashback|reward|claim|gst|income.?tax|"
    r"customs|delivery|courier|amazon|flipkart|meesho)",
    re.I,
)

RANDOM_LOOKING = re.compile(r"^[a-z0-9]{10,}$|^\d{8,}$", re.I)

KNOWN_SAFEISH_PSPS = {
    "ybl", "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ibl", "axl",
    "apl", "upi", "okbizaxis", "amazonpay", "gpay", "googlepay", "fbpe",
}


def _severity_score(findings: list[dict]) -> tuple[int, str]:
    score = 0
    for f in findings:
        sev = f.get("severity", "low")
        if sev == "high":
            score += 28
        elif sev == "medium":
            score += 14
        else:
            score += 6
    score = min(100, score)
    if score >= 55:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"
    return score, level


def analyze_upi(text: str) -> dict[str, Any]:
    """Analyze pasted UPI IDs, payment requests, or QR payload text."""
    raw = (text or "").strip()
    if len(raw) < 3:
        return {
            "module": "upi",
            "score": 0,
            "severity": "low",
            "summary": "Enter a UPI ID, payment request text, or decoded QR payload.",
            "findings": [],
            "vpas": [],
            "recommendation": "Paste the full UPI ID (name@psp) or payment message.",
        }

    findings: list[dict[str, Any]] = []
    vpas: list[dict[str, str]] = []
    seen: set[str] = set()

    for m in VPA_RE.finditer(raw):
        local, psp = m.group(1), m.group(2).lower()
        full = f"{local}@{psp}"
        if full.lower() in seen:
            continue
        seen.add(full.lower())
        vpas.append({"vpa": full, "local": local, "psp": psp})
        if SUSPICIOUS_LOCAL.search(local):
            findings.append({
                "rule_id": "UPI-SUSPICIOUS-LOCAL",
                "category": "Suspicious UPI handle",
                "severity": "high",
                "matched": full,
                "why_it_matters": (
                    "Handles that include words like refund, KYC, bank, or courier "
                    "are frequently used in social-engineering payment requests."
                ),
                "recommendation": (
                    "Do not pay. Confirm the merchant name inside your official bank/UPI app "
                    "and never trust a handle sent over chat alone."
                ),
            })
        if RANDOM_LOOKING.match(local):
            findings.append({
                "rule_id": "UPI-RANDOM-HANDLE",
                "category": "Random-looking UPI handle",
                "severity": "medium",
                "matched": full,
                "why_it_matters": "Long random alphanumeric handles are common for throwaway fraud accounts.",
                "recommendation": "Verify the recipient identity through a channel you already trust.",
            })
        if psp not in KNOWN_SAFEISH_PSPS:
            findings.append({
                "rule_id": "UPI-UNCOMMON-PSP",
                "category": "Uncommon PSP suffix",
                "severity": "low",
                "matched": full,
                "why_it_matters": "Most retail UPI traffic uses a small set of PSP suffixes; unusual ones deserve a closer look.",
                "recommendation": "Confirm the full VPA inside your bank app before sending money.",
            })

    # Catch generic @handles that might be VPAs
    for m in GENERIC_VPA_RE.finditer(raw):
        full = m.group(0)
        if full.lower() in seen:
            continue
        if "@" in full and full.split("@")[-1].lower() in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}:
            continue
        seen.add(full.lower())
        local, psp = m.group(1), m.group(2).lower()
        vpas.append({"vpa": full, "local": local, "psp": psp})
        if SUSPICIOUS_LOCAL.search(local):
            findings.append({
                "rule_id": "UPI-SUSPICIOUS-LOCAL",
                "category": "Suspicious payment handle",
                "severity": "high",
                "matched": full,
                "why_it_matters": "Payment handles embedding urgency or brand words are a classic fraud pattern.",
                "recommendation": "Do not pay this handle. Call the organisation on a number you already have.",
            })

    for m in PHONE_IN_PAYMENT_RE.finditer(raw):
        findings.append({
            "rule_id": "UPI-PHONE-PAY",
            "category": "Mobile number used as payment target",
            "severity": "medium",
            "matched": m.group(1),
            "why_it_matters": "Paying to a raw mobile number from a chat message increases impersonation risk.",
            "recommendation": "Confirm the person voice-to-voice on a known number before transferring.",
        })

    lower = raw.lower()
    if re.search(r"\b(?:send|pay|transfer)\b.{0,40}\b(?:rs\.?|inr|₹)\s*\d+", lower):
        findings.append({
            "rule_id": "UPI-AMOUNT-URGENCY",
            "category": "Payment amount with action language",
            "severity": "medium",
            "matched": "amount + send/pay language",
            "why_it_matters": "Unexpected payment requests in chat often pair an amount with urgency.",
            "recommendation": "Independently verify why the payment is needed before opening any UPI app.",
        })

    if re.search(r"(?:scan\s+(?:this\s+)?qr|pay\s+via\s+qr|upi://pay)", lower):
        findings.append({
            "rule_id": "UPI-QR-REQUEST",
            "category": "QR / deep-link payment request",
            "severity": "medium",
            "matched": "QR or upi:// request",
            "why_it_matters": "QR and deep-link payments can hide the true payee until after you open the app.",
            "recommendation": "Read the payee name carefully inside your official UPI app before confirming.",
        })

    score, severity = _severity_score(findings)
    if not vpas and not findings:
        summary = "No UPI ID or strong payment-request signals detected in this text."
        rec = "If you expected a UPI ID, paste the full handle (example@ybl) or the payment message."
    elif severity == "high":
        summary = f"Found {len(findings)} payment risk signal(s) across {len(vpas)} handle(s). Treat as high caution."
        rec = "Do not pay. Verify the recipient through an official app or phone number you already trust."
    elif severity == "medium":
        summary = f"Found {len(findings)} elevated payment signal(s). Verify independently before paying."
        rec = "Open your bank/UPI app only after confirming the merchant or person offline."
    else:
        summary = f"Parsed {len(vpas)} handle(s) with low signal weight. Still verify before paying."
        rec = "Always confirm payee name in your official UPI app."

    return {
        "module": "upi",
        "score": score,
        "severity": severity,
        "summary": summary,
        "findings": findings,
        "evidence": findings,
        "vpas": vpas,
        "recommendation": rec,
        "note": "Heuristic offline analysis only. A low score does not prove a payment is safe.",
    }
