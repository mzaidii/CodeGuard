import re

# Vulnerability patterns to detect in code
DANGER_PATTERNS = {
    "sql_injection": [
        r'execute\s*\(\s*[f"\'].*\{',
        r'SELECT.*\+\s*\w+',
        r'SELECT.*\%s',
        r'cursor\.execute\s*\(\s*[f"\']',
        r'\.query\s*\(\s*[`"\'].*\+',
        r'executeQuery\s*\(\s*["\'].*\+',
        r'SqlCommand\s*\(\s*["\'].*\+',
        r'SqlCommand\s*\(\s*\$',
    ],
    "command_injection": [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\([^,\]]*shell\s*=\s*True',
        r'subprocess\.run\s*\([^,\]]*shell\s*=\s*True',
        r'subprocess\.Popen\s*\([^,\]]*shell\s*=\s*True',
        r'Process\.Start\s*\(',
        r'Runtime\.getRuntime\(\)\.exec\s*\(',
        r'ProcessBuilder\s*\(',
    ],
    "code_injection": [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'compile\s*\(',
        r'new\s+Function\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
    ],
    "xss": [
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write\s*\(',
        r'\.html\s*\(\s*[^)]*\+',
        r'Html\.Raw\s*\(',
        r'dangerouslySetInnerHTML',
    ],
    "path_traversal": [
        r'open\s*\([^)]*\+',
        r'file_get_contents\s*\([^)]*\.',
        r'include\s*\(\s*\$',
        r'require\s*\(\s*\$',
        r'File\.Open\s*\(',
        r'FileStream\s*\(',
        r'StreamReader\s*\([^)]*\+',
        r'Path\.Combine\s*\([^)]*\+',
    ],
    "hardcoded_secrets": [
        r'[Pp]assword\s*=\s*["\'][^"\']{4,}["\']',
        r'[Aa]pi[_]?[Kk]ey\s*=\s*["\'][^"\']{4,}["\']',
        r'[Ss]ecret\s*=\s*["\'][^"\']{4,}["\']',
        r'[Tt]oken\s*=\s*["\'][^"\']{4,}["\']',
        r'[Pp]rivate[_]?[Kk]ey\s*=\s*["\']',
        r'connectionString\s*=\s*["\'].*[Pp]assword',
        r'DB_PASSWORD\s*=',
        r'API_KEY\s*=',
        r'JWT_SECRET\s*=',
    ],
    "weak_crypto": [
        r'\bmd5\s*\(',
        r'MD5\.Create',
        r'\bsha1\s*\(',
        r'SHA1\.Create',
        r'hashlib\.md5',
        r'hashlib\.sha1',
        r'MessageDigest\.getInstance\s*\(\s*["\']MD5',
        r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1',
    ],
    "insecure_deserialization": [
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\([^)]*\)',
        r'yaml\.unsafe_load',
        r'unserialize\s*\(',
        r'BinaryFormatter\s*\(',
        r'ObjectInputStream\s*\(',
        r'readObject\s*\(',
        r'Marshal\.load',
    ],
    "ssrf": [
        r'requests\.get\s*\([^)]*\+',
        r'urllib\.request\.urlopen\s*\(',
        r'file_get_contents\s*\(\s*\$.*http',
        r'curl_exec\s*\(',
        r'WebClient\s*\(\)',
        r'HttpClient\s*\(\)',
        r'fetch\s*\([^)]*\+',
    ],
    "open_redirect": [
        r'redirect\s*\(\s*\$',
        r'header\s*\(\s*["\']Location:.*\$',
        r'Response\.Redirect\s*\(',
        r'sendRedirect\s*\(',
        r'res\.redirect\s*\(',
    ],
    "xxe": [
        r'XmlDocument\s*\(\)',
        r'XmlTextReader',
        r'etree\.parse\s*\(',
        r'xml\.dom\.minidom',
        r'DocumentBuilder',
        r'SAXParser',
        r'XMLInputFactory',
        r'XmlReader\.Create',
    ],
    "auth_issues": [
        r'\[HttpPost\](?!.*\[Authorize\])',
        r'\[HttpGet\](?!.*\[Authorize\])',
    ],
    "insecure_random": [
        r'random\.random\s*\(',
        r'random\.randint\s*\(',
        r'Math\.random\s*\(',
        r'new\s+Random\s*\(',
        r'\brand\s*\(',
        r'mt_rand\s*\(',
    ],
    "csrf": [
        r'\[HttpPost\](?!.*ValidateAntiForgeryToken)',
    ],
}

SEVERITY_MAP = {
    "sql_injection": "CRITICAL",
    "command_injection": "CRITICAL",
    "code_injection": "CRITICAL",
    "insecure_deserialization": "CRITICAL",
    "xss": "HIGH",
    "path_traversal": "HIGH",
    "hardcoded_secrets": "HIGH",
    "ssrf": "HIGH",
    "xxe": "HIGH",
    "open_redirect": "MEDIUM",
    "auth_issues": "MEDIUM",
    "csrf": "MEDIUM",
    "weak_crypto": "MEDIUM",
    "insecure_random": "LOW",
}

VULN_DISPLAY_NAMES = {
    "sql_injection": "SQL Injection",
    "command_injection": "Command Injection",
    "code_injection": "Code Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "hardcoded_secrets": "Hardcoded Secrets",
    "weak_crypto": "Weak Cryptography",
    "insecure_deserialization": "Insecure Deserialization",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "open_redirect": "Open Redirect",
    "xxe": "XML External Entity (XXE)",
    "auth_issues": "Authentication/Authorization Issues",
    "insecure_random": "Insecure Random Number Generator",
    "csrf": "Cross-Site Request Forgery (CSRF)",
}

# Default fixes for each vulnerability type
DEFAULT_FIXES = {
    "sql_injection": {
        "fix": """// Use parameterized queries
string query = "SELECT * FROM Users WHERE UserId = @UserId";
cmd.Parameters.AddWithValue("@UserId", userId);""",
        "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use parameterized queries to separate code from data."
    },
    "command_injection": {
        "fix": """// Validate input with whitelist
if (!Regex.IsMatch(input, @"^[a-zA-Z0-9\\.\\-]+$"))
    return BadRequest("Invalid input");
// Use ProcessStartInfo with arguments array instead of string concatenation""",
        "explanation": "Command Injection allows attackers to execute arbitrary system commands. Validate input with whitelist and avoid shell=true."
    },
    "code_injection": {
        "fix": """// Remove eval/exec entirely
// Use JSON.parse() for JSON data
// Use safe alternatives like ast.literal_eval() for Python literals""",
        "explanation": "Code Injection allows attackers to execute arbitrary code. Never use eval() or exec() with user input."
    },
    "xss": {
        "fix": """// Encode all user output
// C#: HttpUtility.HtmlEncode(userInput)
// Use textContent instead of innerHTML in JavaScript""",
        "explanation": "Cross-Site Scripting allows attackers to inject malicious scripts. Always encode user output before rendering in HTML."
    },
    "path_traversal": {
        "fix": """// Use Path.GetFileName to remove directory components
string safeName = Path.GetFileName(userInput);
string fullPath = Path.Combine(basePath, safeName);
// Verify the path is within allowed directory""",
        "explanation": "Path Traversal allows attackers to access files outside the intended directory using ../ sequences."
    },
    "hardcoded_secrets": {
        "fix": """// Use environment variables
string password = Environment.GetEnvironmentVariable("DB_PASSWORD");
// Or use configuration manager/secret vault""",
        "explanation": "Hardcoded secrets can be extracted from source code or binaries. Store secrets in environment variables or secure vaults."
    },
    "weak_crypto": {
        "fix": """// Use strong cryptographic algorithms
// For passwords: bcrypt, Argon2, or PBKDF2
// For hashing: SHA256 or SHA512
using (var sha256 = SHA256.Create()) { ... }""",
        "explanation": "MD5 and SHA1 are cryptographically broken. Use SHA256+ for hashing and bcrypt/Argon2 for passwords."
    },
    "insecure_deserialization": {
        "fix": """// Use safe serialization formats
// C#: Use JsonSerializer instead of BinaryFormatter
// Python: Use json.loads() instead of pickle.loads()
var obj = JsonSerializer.Deserialize<MyType>(jsonString);""",
        "explanation": "Insecure deserialization can lead to remote code execution. Use JSON or XML with type validation instead of binary formats."
    },
    "ssrf": {
        "fix": """// Whitelist allowed domains
var allowedHosts = new[] { "api.example.com" };
var uri = new Uri(userUrl);
if (!allowedHosts.Contains(uri.Host))
    return BadRequest("URL not allowed");
// Also block private IPs: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x""",
        "explanation": "SSRF allows attackers to make requests to internal services. Whitelist allowed domains and block private IP ranges."
    },
    "open_redirect": {
        "fix": """// Validate redirect URL
if (!Url.IsLocalUrl(redirectUrl))
    return BadRequest("Invalid redirect");
// Or whitelist allowed redirect domains""",
        "explanation": "Open Redirect allows attackers to redirect users to malicious sites for phishing. Validate redirect URLs against a whitelist."
    },
    "xxe": {
        "fix": """// Disable external entity processing
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;""",
        "explanation": "XXE allows attackers to read local files or perform SSRF via XML external entities. Disable DTD processing."
    },
    "auth_issues": {
        "fix": """// Add authorization attribute
[Authorize]
[HttpGet]
public ActionResult SecureEndpoint() { ... }
// For role-based: [Authorize(Roles = "Admin")]""",
        "explanation": "Missing authentication allows unauthorized access to sensitive endpoints. Add [Authorize] attribute to protected actions."
    },
    "insecure_random": {
        "fix": """// Use cryptographically secure random
// C#: RandomNumberGenerator.GetBytes()
// Python: secrets.token_hex(32)
using var rng = RandomNumberGenerator.Create();
byte[] bytes = new byte[32];
rng.GetBytes(bytes);""",
        "explanation": "Math.random() and Random() are predictable. Use cryptographic random generators for security-sensitive values."
    },
    "csrf": {
        "fix": """// Add anti-forgery token validation
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult SubmitForm() { ... }
// Include @Html.AntiForgeryToken() in your form""",
        "explanation": "CSRF allows attackers to trick users into performing unwanted actions. Use anti-forgery tokens for state-changing requests."
    },
}

# Keywords to look for in LLM response
LLM_KEYWORDS = {
    "sql_injection": ["sql injection", "sql_injection", "sqli", "parameterized query", "prepared statement"],
    "command_injection": ["command injection", "os.system", "subprocess", "shell injection", "process.start", "runtime.exec"],
    "code_injection": ["code injection", "eval(", "exec(", "remote code execution", "function constructor"],
    "xss": ["xss", "cross-site scripting", "innerhtml", "html.raw", "script injection", "htmlencode"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "local file inclusion", "../", "getfilename"],
    "hardcoded_secrets": ["hardcoded", "hard-coded", "hardcode", "secret", "password", "api key", "credentials", "exposed"],
    "weak_crypto": ["weak crypto", "md5", "sha1", "weak hash", "insecure hash", "sha256"],
    "insecure_deserialization": ["deserialization", "pickle", "unserialize", "binaryformatter", "objectinputstream"],
    "ssrf": ["ssrf", "server-side request forgery", "internal network", "metadata", "169.254"],
    "open_redirect": ["open redirect", "url redirect", "unvalidated redirect", "islocalurl"],
    "xxe": ["xxe", "xml external entity", "xml injection", "dtd", "xmlresolver"],
    "auth_issues": ["authentication", "authorization", "missing auth", "[authorize]", "login_required", "unauthenticated"],
    "insecure_random": ["insecure random", "math.random", "random()", "predictable", "securerandom"],
    "csrf": ["csrf", "cross-site request forgery", "antiforgery", "csrf token", "validateantiforgerytoken"],
}


def detect_language(code):
    """Detect programming language from code content."""
    
    # Go detection (check FIRST - before Python)
    if any(kw in code for kw in ['package main', 'func ', 'import (', 'fmt.', ':= ', 'go func']):
        return "go"
    
    # PHP detection (check for <?php or $ variables)
    if '<?php' in code or (('$_GET' in code or '$_POST' in code or '$this->' in code) and '$' in code):
        return "php"
    
    # C# detection
    if any(kw in code for kw in ['using System', 'namespace ', 'public class', 'ActionResult', '[HttpGet]', '[HttpPost]']):
        return "csharp"
    
    # Java detection
    if any(kw in code for kw in ['import java.', 'public static void main', '@RestController', '@GetMapping']):
        return "java"
    
    # Python detection
    if any(kw in code for kw in ['def ', 'import ', 'from ', 'print(']):
        if 'def ' in code and ':' in code:
            return "python"
    
    # JavaScript/Node.js detection
    if any(kw in code for kw in ['const ', 'let ', 'var ', 'require(', 'module.exports', '=>']):
        return "javascript"
    
    # C++ detection
    if any(kw in code for kw in ['#include <', 'std::', 'cout <<', 'int main()']):
        return "cpp"
    
    return "unknown"


def parse_llm_response(raw_response, code):
    """Parse LLM response and extract vulnerability information."""
    
    language = detect_language(code)
    lines = code.split('\n')
    
    findings = []
    found_vulns = set()
    
    response_lower = raw_response.lower()
    
    # Method 1: Check LLM response for mentioned vulnerabilities
    for vuln_type, keywords in LLM_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in response_lower:
                if vuln_type not in found_vulns:
                    found_vulns.add(vuln_type)
                    
                    # Find vulnerable lines in code
                    vulnerable_lines = []
                    if vuln_type in DANGER_PATTERNS:
                        for i, line in enumerate(lines, 1):
                            for pattern in DANGER_PATTERNS[vuln_type]:
                                if re.search(pattern, line, re.IGNORECASE):
                                    vulnerable_lines.append({
                                        "line_number": i,
                                        "code": line.strip()
                                    })
                                    break
                    
                    # Get default fix and explanation for this vulnerability type
                    default_info = DEFAULT_FIXES.get(vuln_type, {})
                    
                    findings.append({
                        "vulnerability": VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                        "severity": SEVERITY_MAP.get(vuln_type, "MEDIUM"),
                        "vuln_type": vuln_type,
                        "vulnerable_lines": vulnerable_lines[:5],
                        "fixed_code": default_info.get("fix", ""),
                        "explanation": default_info.get("explanation", ""),
                    })
                break
    
    # Method 2: Direct pattern scanning on code (for vulnerabilities not mentioned by LLM)
    for vuln_type, patterns in DANGER_PATTERNS.items():
        if vuln_type not in found_vulns:
            vulnerable_lines = []
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerable_lines.append({
                            "line_number": i,
                            "code": line.strip()
                        })
                        break
            
            if vulnerable_lines:
                found_vulns.add(vuln_type)
                
                # Get default fix and explanation
                default_info = DEFAULT_FIXES.get(vuln_type, {})
                
                findings.append({
                    "vulnerability": VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                    "severity": SEVERITY_MAP.get(vuln_type, "MEDIUM"),
                    "vuln_type": vuln_type,
                    "vulnerable_lines": vulnerable_lines[:5],
                    "fixed_code": default_info.get("fix", ""),
                    "explanation": default_info.get("explanation", ""),
                })
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    has_vulns = len(findings) > 0
    
    return {
        "has_vulnerabilities": has_vulns,
        "findings": findings,
        "language_detected": language,
        "raw_response": raw_response
    }


def filter_findings(findings):
    """Filter findings to only include those with vulnerable lines."""
    return [f for f in findings if f.get('vulnerable_lines') and len(f['vulnerable_lines']) > 0]
