import re

RULES = [
    ("SQL injection risk", re.compile(r"(execute|query)\s*\(\s*[^\n]*(\+|%s|\.format\(|f['\"])", re.I), "high", "Use parameterized queries; never concatenate untrusted values into SQL."),
    ("Shell command injection risk", re.compile(r"(shell\s*=\s*True|os\.system\s*\(|subprocess\.(run|call|Popen)\s*\([^\n]*shell\s*=\s*True)", re.I), "high", "Pass an argument list to subprocess with shell=False and validate inputs."),
    ("Hard-coded credential-like value", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "medium", "Load secrets from a secret manager or environment variable; rotate any real exposed credential."),
    ("Solidity external call before state update", re.compile(r"\.call\s*\{[^}]*\}[^;]*;[\s\S]{0,240}(balances\s*\[[^]]+\]\s*=|\.transfer\s*\()", re.I), "high", "Apply checks-effects-interactions and consider a reentrancy guard."),
    ("Solidity tx.origin authorization", re.compile(r"require\s*\(\s*tx\.origin\s*==", re.I), "high", "Use msg.sender for authorization and add explicit access control."),
    ("Potential unsafe deserialization", re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)", re.I), "high", "Avoid deserializing untrusted data; use safe formats/loaders."),
    ("Dynamic code execution", re.compile(r"\b(eval|exec)\s*\(", re.I), "high", "Avoid evaluating user-controlled strings as code; use explicit parsers or allowlists."),
    ("Cross-site scripting risk", re.compile(r"innerHTML\s*=|dangerouslySetInnerHTML", re.I), "medium", "Escape untrusted content or render it as text; use a vetted sanitizer if rich HTML is required."),
    ("Disabled TLS verification", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", re.I), "high", "Keep certificate validation enabled and fix the trust configuration instead."),
]

def analyze_code(code: str) -> dict:
    findings=[]
    for title,pattern,severity,fix in RULES:
        for m in pattern.finditer(code):
            findings.append({"title":title,"line":code.count("\n",0,m.start())+1,"evidence":("credential assignment detected; value redacted" if title == "Hard-coded credential-like value" else m.group(0)[:200]),"recommendation":fix,"severity":severity})
    score=min(95,sum(35 if finding["severity"]=="high" else 18 for finding in findings))
    level="high" if score>=50 else "medium" if score>=20 else "low"
    return {"risk_score":score,"risk_level":level,"findings":findings,"summary":f"Found {len(findings)} rule-based issue(s)." if findings else "No configured patterns matched; this is not proof that the code is secure.","disclaimer":"Lightweight pattern checks can miss vulnerabilities and may flag safe code. Review findings and run a language-specific security scanner before deployment."}
