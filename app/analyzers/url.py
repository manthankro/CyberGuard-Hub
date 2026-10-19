import ipaddress
import re
from urllib.parse import urlsplit

BRANDS = ("google", "microsoft", "paypal", "amazon", "apple", "facebook", "instagram", "netflix")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "com.au", "net.au", "co.in", "com.br", "co.jp"}


def _within_one_edit(first: str, second: str) -> bool:
    if abs(len(first) - len(second)) > 1:
        return False
    left = right = edits = 0
    while left < len(first) and right < len(second):
        if first[left] == second[right]:
            left += 1
            right += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(first) >= len(second):
            left += 1
        if len(second) >= len(first):
            right += 1
    return edits + (left < len(first) or right < len(second)) <= 1


def _finding(rule_id: str, category: str, evidence: str, why: str, recommendation: str, severity: str = "medium") -> dict:
    return {"rule_id": rule_id, "category": category, "severity": severity, "evidence": evidence,
            "why_it_matters": why, "recommendation": recommendation}


def analyze_url(value: str) -> dict:
    raw = value.strip()
    candidate = raw if "://" in raw else "https://" + raw
    parsed = None
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        _ = parsed.port  # Accessing validates malformed ports.
    except ValueError:
        host = ""
    if not host or any(c.isspace() for c in raw):
        return {"risk_score": 60, "risk_level": "medium", "host": host, "findings": [
            _finding("URL-PARSE", "URL could not be parsed", "Malformed or incomplete URL", "The destination cannot be inspected reliably.", "Do not open it; copy the link again or verify through a trusted source.", "high")],
            "recommendations": ["Do not open this link until you verify it through a trusted source."],
            "disclaimer": "This checks URL text only; it does not visit the site or establish safety."}

    findings = []
    def add(rule, title, evidence, why, next_step, severity="medium"):
        findings.append(_finding(rule, title, evidence, why, next_step, severity))

    try:
        ipaddress.ip_address(host)
        add("URL-IP", "Raw IP address", host, "A numeric destination can obscure the organisation behind a link.", "Do not sign in; verify the destination through the organisation's official site.", "high")
    except ValueError:
        pass
    if "@" in parsed.netloc:
        add("URL-USERINFO", "User-info syntax", parsed.netloc[:180], "Text before @ can make a URL look as if it belongs to a different site.", "Read the actual hostname after @ and avoid unexpected sign-in links.", "high")
    if host.startswith("xn--") or ".xn--" in host:
        add("URL-PUNYCODE", "Internationalized / punycode domain", host, "Some Unicode domain names can visually resemble familiar Latin-script names.", "Open the official site from a bookmark or enter its known address yourself.")
    if host in SHORTENERS:
        add("URL-SHORTENER", "URL shortener", host, "The shortened link hides its final destination from this text-only check.", "Ask the sender for the full destination and verify it before opening.")
    if len(host.split(".")) >= 5:
        add("URL-SUBDOMAIN", "Deep subdomain structure", host, "The registered domain may be different from a familiar-looking subdomain.", "Identify the registrable domain before deciding whether to trust it.")
    if len(host) > 45:
        add("URL-LONG-HOST", "Unusually long hostname", host, "Long hostnames can make deceptive or throwaway domains harder to read.", "Check the domain carefully and avoid entering credentials if uncertain.")
    if parsed.scheme != "https":
        add("URL-NO-HTTPS", "No HTTPS", parsed.scheme, "The connection does not indicate HTTPS; this does not alone prove a malicious site.", "Do not submit sensitive information over this link.", "high")
    if re.search(r"-{2,}|\d{5,}", host):
        add("URL-ODD-HOST", "Unusual hostname pattern", host, "Repeated hyphens or long digit runs are sometimes used in disposable or deceptive domains.", "Verify the exact domain independently.")

    labels = host.split(".")
    suffix = ".".join(labels[-2:]) if len(labels) >= 2 else host
    root_index = -3 if suffix in MULTI_LABEL_SUFFIXES else -2
    root_label = labels[root_index] if len(labels) >= abs(root_index) else (labels[-1] if labels else "")
    subdomain_labels = labels[:root_index] if len(labels) >= abs(root_index) else []
    # Keep the registrable label separate from subdomains, so e.g.
    # paypal-login.com isn't mislabeled as a paypal.com subdomain.
    for brand in BRANDS:
        if any(brand in label for label in subdomain_labels):
            add("URL-BRAND-SUBDOMAIN", "Brand-like text in subdomain", brand, "A familiar brand name in a subdomain does not mean that brand controls the registered domain.", "Check the actual registered domain; open the brand's official site independently.", "high")
            break
        if root_label != brand and (brand in root_label or _within_one_edit(root_label, brand)):
            add("URL-TYPOLOOKALIKE", "Brand-like or typo-lookalike registered domain", root_label, f"The registered domain resembles the name {brand}; this heuristic may also match unrelated domains.", "Open the organisation's official domain from a bookmark or other trusted source.", "high")
            break

    score = min(95, sum(30 if item["severity"] == "high" else 18 for item in findings))
    return {
        "host": host,
        "scheme": parsed.scheme,
        "risk_score": score,
        "risk_level": "high" if score >= 55 else "medium" if score >= 20 else "low",
        "findings": findings,
        "summary": f"Found {len(findings)} URL indicator(s). A low score does not prove that the destination is safe.",
        "recommendations": [
            "Check the registered domain carefully before signing in.",
            "Open the organisation's official site from a bookmark or a source you trust.",
            "Do not enter credentials on a page reached from an unexpected message.",
        ],
        "disclaimer": "Heuristic URL inspection only. CyberGuard does not visit the URL, check live reputation, certificate validity, domain age, or prove that a site is safe.",
    }
