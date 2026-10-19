import ipaddress
import re
import socket
from urllib.parse import urlsplit

BRANDS = (
    "google", "microsoft", "paypal", "amazon", "apple", "facebook", "instagram",
    "netflix", "sbi", "hdfc", "icici", "paytm", "whatsapp", "telegram", "binance", "coinbase"
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl", "ow.ly"}
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "com.au", "net.au", "co.in", "com.br", "co.jp", "gov.in", "nic.in", "ac.in"}
HIGH_RISK_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work", "icu", "loan", "click", "vip", "fit"}
DECEPTIVE_KEYWORDS = re.compile(r"\b(login|verify|verification|signin|banking|account|update|recover|wallet|kyc|otp|secure|auth)\b", re.I)


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
            "components": None,
            "recommendations": ["Do not open this link until you verify it through a trusted source."],
            "disclaimer": "This checks URL text only; it does not visit the site or establish safety."}

    findings = []
    def add(rule, title, evidence, why, next_step, severity="medium"):
        findings.append(_finding(rule, title, evidence, why, next_step, severity))

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
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
    
    tld = labels[-1] if labels else ""
    if tld in HIGH_RISK_TLDS:
        add("URL-SUSPICIOUS-TLD", f"High-risk top-level domain (.{tld})", f".{tld}", f"Domains under .{tld} are frequently offered free or cheaply and abused in mass phishing campaigns.", "Exercise elevated caution with unfamiliar TLDs.", "medium")

    # Check for deceptive words in path or query
    full_path_query = (parsed.path or "") + " " + (parsed.query or "")
    keyword_matches = DECEPTIVE_KEYWORDS.findall(full_path_query)
    if keyword_matches and (host in SHORTENERS or root_label not in BRANDS):
        add("URL-DECEPTIVE-PATH", "Sensitive keyword in URL path", ", ".join(set(keyword_matches[:4])), "Phishing campaigns frequently append keywords like 'login' or 'verify' to unbranded domains.", "Verify if the primary domain truly belongs to the service claiming to need verification.", "medium")

    # Keep the registrable label separate from subdomains, so e.g.
    # paypal-login.com isn't mislabeled as a paypal.com subdomain.
    matched_brand = None
    for brand in BRANDS:
        if any(label == brand or label.startswith(brand + "-") or label.endswith("-" + brand) for label in subdomain_labels):
            matched_brand = brand
            add("URL-BRAND-SUBDOMAIN", "Brand-like text in subdomain", brand, "A familiar brand name in a subdomain does not mean that brand controls the registered domain.", "Check the actual registered domain; open the brand's official site independently.", "high")
            break
        if root_label != brand and (brand in root_label or _within_one_edit(root_label, brand)):
            matched_brand = brand
            add("URL-TYPOLOOKALIKE", "Brand-like or typo-lookalike registered domain", root_label, f"The registered domain resembles the name {brand}; this heuristic may also match unrelated domains.", "Open the organisation's official domain from a bookmark or other trusted source.", "high")
            break

    # Repeated or overlapping indicators should not inflate risk. A URL pattern
    # is a clue, never a verdict; low-impact clues contribute less.
    weights = {"URL-IP": 24, "URL-USERINFO": 30, "URL-PUNYCODE": 18,
               "URL-SHORTENER": 10, "URL-SUBDOMAIN": 7, "URL-LONG-HOST": 5,
               "URL-NO-HTTPS": 8, "URL-ODD-HOST": 7, "URL-SUSPICIOUS-TLD": 8,
               "URL-DECEPTIVE-PATH": 10, "URL-BRAND-SUBDOMAIN": 28,
               "URL-TYPOLOOKALIKE": 26}
    score = min(95, sum(weights.get(item["rule_id"], 0) for item in findings))
    return {
        "host": host,
        "scheme": parsed.scheme,
        "risk_score": score,
        "risk_level": "high" if score >= 50 else "medium" if score >= 20 else "low",
        "findings": findings,
        "components": {
            "scheme": parsed.scheme,
            "host": host,
            "subdomain": ".".join(subdomain_labels) if subdomain_labels else None,
            "domain": root_label,
            "suffix": suffix,
            "tld": tld,
            "path": parsed.path or "/",
            "query": parsed.query or None,
            "port": parsed.port,
            "is_ip": is_ip,
            "brand_match": matched_brand,
        },
        "summary": f"Found {len(findings)} URL indicator(s). A low score does not prove that the destination is safe.",
        "recommendations": [
            "Check the registered domain carefully before signing in.",
            "Open the organisation's official site from a bookmark or a source you trust.",
            "Do not enter credentials on a page reached from an unexpected message.",
        ],
        "disclaimer": "Heuristic URL inspection only. CyberGuard does not visit the URL, check live reputation, certificate validity, domain age, or prove that a site is safe.",
    }



def check_domain_status(value: str) -> dict:
    """Check URL syntax and public DNS only; never makes an HTTP request."""
    raw = value.strip()
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        _ = parsed.port
        syntactically_valid = bool(host and parsed.scheme in {"http", "https"} and not any(ch.isspace() for ch in raw))
    except ValueError:
        host = ""
        syntactically_valid = False
    if not syntactically_valid:
        return {"format_valid": False, "domain_status": "invalid", "domain_note": "The URL format is incomplete or malformed."}
    if not host or host == "localhost" or "." not in host or host.endswith((".local", ".internal", ".test", ".invalid", ".example")):
        return {"format_valid": True, "domain_status": "not_public", "domain_note": "Well-formed URL, but this is not a public internet hostname."}
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            return {"format_valid": True, "domain_status": "not_public", "domain_note": "Well-formed URL, but the address is not globally routable."}
        return {"format_valid": True, "domain_status": "resolves", "domain_note": "The public IP address is globally routable; this does not indicate safety."}
    except ValueError:
        pass
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = {item[4][0] for item in results}
        if not addresses:
            raise socket.gaierror()
        parsed_ips = [ipaddress.ip_address(address) for address in addresses]
        if not all(ip.is_global for ip in parsed_ips):
            return {"format_valid": True, "domain_status": "not_public", "domain_note": "The hostname resolves to a non-public address; the site was not contacted."}
        return {"format_valid": True, "domain_status": "resolves", "domain_note": "The hostname currently resolves in public DNS; this does not indicate safety."}
    except socket.gaierror:
        return {"format_valid": True, "domain_status": "not_resolved", "domain_note": "The hostname did not resolve from this server. It may be misspelled, offline, new, or blocked."}
    except OSError:
        return {"format_valid": True, "domain_status": "unknown", "domain_note": "A DNS status could not be obtained; URL-format analysis is still available."}
