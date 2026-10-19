import re
RULES = [
 ("SQL injection risk", re.compile(r"(execute|query)\s*\(\s*[^\n]*(\+|%s|\.format\(|f['\"])", re.I), "Use parameterized queries; never concatenate untrusted values into SQL."),
 ("Shell command injection risk", re.compile(r"(shell\s*=\s*True|os\.system\s*\(|subprocess\.(run|call|Popen)\s*\([^\n]*shell\s*=\s*True)", re.I), "Pass an argument list to subprocess with shell=False and validate inputs."),
 ("Hard-coded credential-like value", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "Load secrets from a secret manager or environment variable; rotate exposed credentials."),
 ("Solidity external call before state update", re.compile(r"\.call\s*\{[^}]*\}[^;]*;[\s\S]{0,240}(balances\s*\[[^]]+\]\s*=|\.transfer\s*\()", re.I), "Apply checks-effects-interactions and consider a reentrancy guard."),
 ("Solidity tx.origin authorization", re.compile(r"require\s*\(\s*tx\.origin\s*==", re.I), "Use msg.sender for authorization and add explicit access control."),
 ("Potential unsafe deserialization", re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)", re.I), "Avoid deserializing untrusted data; use safe formats/loaders."),
]
def analyze_code(code: str) -> dict:
    findings=[]
    for title,pattern,fix in RULES:
        for m in pattern.finditer(code):
            findings.append({"title":title,"line":code.count("\n",0,m.start())+1,"evidence":m.group(0)[:200],"recommendation":fix,"severity":"high" if "injection" in title.lower() or "origin" in title.lower() else "medium"})
    return {"findings":findings,"summary":f"Found {len(findings)} rule-based issue(s)." if findings else "No configured patterns matched; this is not proof that the code is secure.","disclaimer":"Lightweight pattern checks can miss vulnerabilities and may flag safe code. Review findings and run a language-specific security scanner before deployment."}
