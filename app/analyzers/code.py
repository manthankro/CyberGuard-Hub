import re

RULES = [
    ("CODE-SQL-CONCAT", "SQL injection risk", re.compile(r"(execute|query)\s*\(\s*[^\n]*(\+|%s|\.format\(|f['\"])", re.I), "high", "Use parameterized queries; never concatenate untrusted values into SQL.", "Concatenated query strings can let untrusted input change the database command.", "cursor.execute('SELECT * FROM table WHERE id = %s', (safe_id,))"),
    ("CODE-SHELL", "Shell command injection risk", re.compile(r"(shell\s*=\s*True|os\.system\s*\(|subprocess\.(run|call|Popen)\s*\([^\n]*shell\s*=\s*True)", re.I), "high", "Pass an argument list to subprocess with shell=False and validate inputs.", "Shell metacharacters in untrusted input may execute additional commands.", "subprocess.run(['command', arg1, arg2], check=True)"),
    ("CODE-SECRET", "Hard-coded credential-like value", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "medium", "Load secrets from a secret manager or environment variable; rotate any real exposed credential.", "Credentials in source can leak through repositories, logs, or copied code.", "API_KEY = os.environ.get('API_KEY')"),
    ("CODE-REENTRANCY", "Solidity external call before state update", re.compile(r"\.call\s*\{[^}]*\}[^;]*;[\s\S]{0,240}(balances\s*\[[^]]+\]\s*=|\.transfer\s*\()", re.I), "high", "Apply checks-effects-interactions and consider a reentrancy guard.", "An external contract call before state changes can permit re-entrant execution.", "balances[msg.sender] = 0; (bool s, ) = msg.sender.call{value: amount}(''); require(s);"),
    ("CODE-TXORIGIN", "Solidity tx.origin authorization", re.compile(r"require\s*\(\s*tx\.origin\s*==", re.I), "high", "Use msg.sender for authorization and add explicit access control.", "tx.origin can be abused through a malicious intermediary contract.", "require(msg.sender == owner, 'Not authorized');"),
    ("CODE-DESERIALIZE", "Potential unsafe deserialization", re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)", re.I), "high", "Avoid deserializing untrusted data; use safe formats/loaders.", "Some deserializers can instantiate objects or execute behavior from crafted input.", "data = json.loads(payload)  # or yaml.safe_load(payload)"),
    ("CODE-EVAL", "Dynamic code execution", re.compile(r"\b(eval|exec)\s*\(", re.I), "high", "Avoid evaluating user-controlled strings as code; use explicit parsers or allowlists.", "Dynamic execution can turn untrusted data into executable code.", "parsed_val = ast.literal_eval(user_input)"),
    ("CODE-XSS", "Cross-site scripting risk", re.compile(r"innerHTML\s*=|dangerouslySetInnerHTML", re.I), "medium", "Escape untrusted content or render it as text; use a vetted sanitizer if rich HTML is required.", "Rendering untrusted HTML can allow script injection in a user's browser.", "element.textContent = sanitizedText;"),
    ("CODE-TLS", "Disabled TLS verification", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", re.I), "high", "Keep certificate validation enabled and fix the trust configuration instead.", "Disabling certificate checks can expose connections to interception.", "response = requests.get(url, verify=True)"),
    ("CODE-WEAK-HASH", "Weak cryptographic hash function", re.compile(r"hashlib\.(md5|sha1)\s*\(|crypto\.createHash\(['\"](md5|sha1)['\"]\)", re.I), "medium", "Use SHA-256/SHA-3 for integrity or bcrypt/argon2 for password hashing.", "MD5 and SHA-1 suffer from known collision vulnerabilities and should not be used for security.", "hasher = hashlib.sha256()"),
    ("CODE-CORS-WILDCARD", "Permissive wildcard CORS header", re.compile(r"Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*", re.I), "low", "Specify trusted explicit origins instead of allowing arbitrary domains.", "A wildcard Access-Control-Allow-Origin header allows any third-party website to make authenticated cross-origin requests.", "response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'"),
]

def analyze_code(code: str) -> dict:
    findings = []
    lines = code.split("\n")
    for rule_id, title, pattern, severity, fix, why, sample_fix in RULES:
        for m in pattern.finditer(code):
            line_no = code.count("\n", 0, m.start()) + 1
            raw_line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
            
            # Redact secrets from evidence AND line snippet to prevent leaking keys in reports
            if title == "Hard-coded credential-like value":
                evidence = "credential assignment detected; value redacted"
                snippet = re.sub(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]+['\"]", r"\1 = '[REDACTED]'", raw_line.strip())
            else:
                evidence = m.group(0)[:200]
                snippet = raw_line.strip()[:200]

            findings.append({
                "rule_id": rule_id,
                "title": title,
                "line": line_no,
                "snippet": snippet,
                "evidence": evidence,
                "why_it_matters": why,
                "recommendation": fix,
                "suggested_fix": sample_fix,
                "severity": severity,
            })
    score = min(95, sum(35 if finding["severity"] == "high" else (18 if finding["severity"] == "medium" else 10) for finding in findings))
    level = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "total_lines": len(lines),
        "summary": f"Found {len(findings)} rule-based issue(s)." if findings else "No configured patterns matched; this is not proof that the code is secure.",
        "disclaimer": "Lightweight pattern checks can miss vulnerabilities and may flag safe code. Review findings and run a language-specific security scanner before deployment."
    }
