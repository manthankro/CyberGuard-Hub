import ipaddress, re
from urllib.parse import urlsplit

BRANDS = ("google", "microsoft", "paypal", "amazon", "apple", "facebook", "instagram", "netflix", "bank")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}

def analyze_url(value: str) -> dict:
    raw=value.strip()
    candidate=raw if "://" in raw else "https://"+raw
    try:
        parsed=urlsplit(candidate)
        host=(parsed.hostname or "").rstrip(".").lower()
        _=parsed.port
    except ValueError:
        host=""
    if not host or any(c.isspace() for c in raw):
        return {"risk_score": 60,"risk_level":"medium","host":host,"findings":["URL could not be parsed reliably"],"recommendations":["Do not open this link until you verify it through a trusted source."],"disclaimer":"This checks URL text only; it does not visit the site or establish safety."}
    findings=[]
    try:
        ipaddress.ip_address(host); findings.append("Uses a raw IP address instead of a domain")
    except ValueError: pass
    if "@" in parsed.netloc: findings.append("Contains user-info syntax that can disguise the destination")
    if host.startswith("xn--") or ".xn--" in host: findings.append("Contains an internationalized/punycode domain")
    if host in SHORTENERS: findings.append("Uses a URL-shortening service that hides the destination")
    if len(host.split(".")) >= 5: findings.append("Has an unusually deep subdomain structure")
    if len(host) > 45: findings.append("Domain name is unusually long")
    if parsed.scheme != "https": findings.append("Does not use HTTPS")
    if re.search(r"-{2,}|\d{5,}",host): findings.append("Domain contains patterns sometimes used in throwaway domains")
    labels=host.split(".")
    for brand in BRANDS:
        if any(brand in label and label != brand for label in labels[:-1]):
            findings.append(f"Brand-like text appears in a subdomain ({brand})"); break
    score=min(90,len(findings)*20)
    return {"host":host,"scheme":parsed.scheme,"risk_score":score,"risk_level":"high" if score>=55 else "medium" if score>=20 else "low","findings":findings,"recommendations":["Check the registered domain carefully before signing in.","Open the organisation's official site from a bookmark or search result you trust.","Do not enter credentials on a page reached from an unexpected message."],"disclaimer":"Heuristic URL inspection only. CyberGuard does not visit the URL, check live reputation, certificate validity, domain age, or prove that a site is safe."}
