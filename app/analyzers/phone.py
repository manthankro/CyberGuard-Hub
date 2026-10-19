"""Indian mobile number heuristic checks (offline, not a live reputation DB)."""
from __future__ import annotations

import re
from typing import Any

MOBILE_RE = re.compile(
    r"(?:\+?91[\s-]*)?([6-9]\d{9})\b"
)

SEQUENTIAL = re.compile(
    r"(?:0123456789|1234567890|9876543210|0987654321|"
    r"(?:0{5,}|1{5,}|2{5,}|3{5,}|4{5,}|5{5,}|6{5,}|7{5,}|8{5,}|9{5,}))"
)


def _is_sequential(digits: str) -> bool:
    if SEQUENTIAL.search(digits):
        return True
    asc = all(int(digits[i + 1]) - int(digits[i]) == 1 for i in range(len(digits) - 1))
    desc = all(int(digits[i]) - int(digits[i + 1]) == 1 for i in range(len(digits) - 1))
    return asc or desc


def _is_repeated_block(digits: str) -> bool:
    if len(set(digits)) <= 2:
        return True
    for size in (2, 3, 4, 5):
        if len(digits) % size == 0:
            block = digits[:size]
            if block * (len(digits) // size) == digits:
                return True
    return False


def analyze_phone(text: str) -> dict[str, Any]:
    """Extract and score Indian mobile numbers found in free text."""
    raw = (text or "").strip()
    findings: list[dict[str, Any]] = []
    numbers: list[str] = []
    seen: set[str] = set()

    for m in MOBILE_RE.finditer(raw):
        digits = m.group(1)
        if digits in seen:
            continue
        seen.add(digits)
        numbers.append(digits)

        if _is_sequential(digits):
            findings.append({
                "rule_id": "PHONE-SEQUENTIAL",
                "category": "Sequential or patterned number",
                "severity": "medium",
                "matched": digits,
                "why_it_matters": "Highly patterned numbers are sometimes used in bulk spam campaigns.",
                "recommendation": "Do not call back numbers from unexpected messages; use official published contacts.",
            })
        if _is_repeated_block(digits):
            findings.append({
                "rule_id": "PHONE-REPEATED",
                "category": "Repeated-digit pattern",
                "severity": "medium",
                "matched": digits,
                "why_it_matters": "Numbers with very low digit diversity are often non-personal or disposable.",
                "recommendation": "Verify the caller through a known channel before sharing OTPs or money.",
            })

    # Context cues around numbers
    lower = raw.lower()
    if numbers and re.search(
        r"(?:missed call|last warning|kyc|account (?:block|suspend)|otp|verify|"
        r"electricity|gas subsidy|income tax|customs|parcel|courier|delivery)",
        lower,
    ):
        findings.append({
            "rule_id": "PHONE-SCAM-CONTEXT",
            "category": "Scam-context language near number",
            "severity": "high",
            "matched": ", ".join(numbers[:3]),
            "why_it_matters": "Numbers paired with KYC, delivery, subsidy, or threat language are common in Indian SMS/WhatsApp fraud.",
            "recommendation": "Do not call or share OTP. Use the organisation's official app or published helpline.",
        })

    if re.search(r"(?:whatsapp|telegram|signal)\s+(?:me|only|number)", lower) and numbers:
        findings.append({
            "rule_id": "PHONE-CHAT-ONLY",
            "category": "Chat-only contact request",
            "severity": "medium",
            "matched": "chat-only contact",
            "why_it_matters": "Scammers often push victims onto private chat apps to avoid carrier filtering.",
            "recommendation": "Prefer official support channels over private chat numbers from strangers.",
        })

    score = 0
    for f in findings:
        score += {"high": 30, "medium": 16, "low": 6}.get(f["severity"], 6)
    score = min(100, score)
    if score >= 55:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "low"

    if not numbers:
        summary = "No Indian mobile number (6–9 start, 10 digits) detected."
        rec = "Paste a 10-digit mobile number or the full SMS/WhatsApp text containing it."
    elif severity == "high":
        summary = f"Analyzed {len(numbers)} number(s) with high-risk context signals."
        rec = "Do not call back or share codes. Use official helplines (e.g. 1930 for cyber fraud in India)."
    elif severity == "medium":
        summary = f"Analyzed {len(numbers)} number(s) with elevated pattern or context signals."
        rec = "Verify identity independently before engaging."
    else:
        summary = f"Parsed {len(numbers)} number(s) with low heuristic signal weight."
        rec = "Still treat unexpected callbacks with caution. This is not a live spam registry lookup."

    return {
        "module": "phone",
        "score": score,
        "severity": severity,
        "summary": summary,
        "findings": findings,
        "evidence": findings,
        "numbers": numbers,
        "recommendation": rec,
        "note": (
            "Offline heuristics only — not Truecaller or a carrier spam list. "
            "A low score does not mean the number is safe."
        ),
    }
