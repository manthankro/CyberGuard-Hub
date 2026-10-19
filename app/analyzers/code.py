import re

RULES = [
    ("CODE-SQL-CONCAT", "SQL injection risk", re.compile(r"(execute|query)\s*\(\s*[^\n]*(\+|%s|\.format\(|f['\"])", re.I), "high", "Use parameterized queries; never concatenate untrusted values into SQL.", "Concatenated query strings can let untrusted input change the database command."),
    ("CODE-SHELL", "Shell command injection risk", re.compile(r"(shell\s*=\s*True|os\.system\s*\(|subprocess\.(run|call|Popen)\s*\([^\n]*shell\s*=\s*True)", re.I), "high", "Pass an argument list to subprocess with shell=False and validate inputs.", "Shell metacharacters in untrusted input may execute additional commands."),
    ("CODE-SECRET", "Hard-coded credential-like value", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "medium", "Load secrets from a secret manager or environment variable; rotate any real exposed credential.", "Credentials in source can leak through repositories, logs, or copied code."),
    ("CODE-REENTRANCY", "Solidity external call before state update", re.compile(r"\.call\s*\{[^}]*\}[^;]*;[\s\S]{0,240}(balances\s*\[[^]]+\]\s*=|\.transfer\s*\()", re.I), "high", "Apply checks-effects-interactions and consider a reentrancy guard.", "An external contract call before state changes can permit re-entrant execution."),
    ("CODE-TXORIGIN", "Solidity tx.origin authorization", re.compile(r"require\s*\(\s*tx\.origin\s*==", re.I), "high", "Use msg.sender for authorization and add explicit access control.", "tx.origin can be abused through a malicious intermediary contract."),
    ("CODE-DESERIALIZE", "Potential unsafe deserialization", re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)", re.I), "high", "Avoid deserializing untrusted data; use safe formats/loaders.", "Some deserializers can instantiate objects or execute behavior from crafted input."),
    ("CODE-EVAL", "Dynamic code execution", re.compile(r"\b(eval|exec)\s*\(", re.I), "high", "Avoid evaluating user-controlled strings as code; use explicit parsers or allowlists.", "Dynamic execution can turn untrusted data into executable code."),
    ("CODE-XSS", "Cross-site scripting risk", re.compile(r"innerHTML\s*=|dangerouslySetInnerHTML", re.I), "medium", "Escape untrusted content or render it as text; use a vetted sanitizer if rich HTML is required.", "Rendering untrusted HTML can allow script injection in a user's browser."),
    ("CODE-TLS", "Disabled TLS verification", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", re.I), "high", "Keep certificate validation enabled and fix the trust configuration instead.", "Disabling certificate checks can expose connections to interception."),
]

def analyze_code(code: str) -> dict:
    findings=[]
    for rule_id,title,pattern,severity,fix,why in RULES:
        for m in pattern.finditer(code):
            findings.append({"rule_id":rule_id,"title":title,"line":code.count("\n",0,m.start())+1,"evidence":("credential assignment detected; value redacted" if title == "Hard-coded credential-like value" else m.group(0)[:200]),"why_it_matters":why,"recommendation":fix,"severity":severity})
    score=min(95,sum(35 if finding["severity"]=="high" else 18 for finding in findings))
    level="high" if score>=50 else "medium" if score>=20 else "low"
    return {"risk_score":score,"risk_level":level,"findings":findings,"summary":f"Found {len(findings)} rule-based issue(s)." if findings else "No configured patterns matched; this is not proof that the code is secure.","disclaimer":"Lightweight pattern checks can miss vulnerabilities and may flag safe code. Review findings and run a language-specific security scanner before deployment."}
