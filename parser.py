import re

# ============================================================================
# VULNERABILITY PATTERNS
# ============================================================================

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
        r'db\.Query\s*\([^,]*\+',
        r'db\.Exec\s*\([^,]*\+',
        r'fmt\.Sprintf\s*\(\s*".*SELECT',
        r'fmt\.Sprintf\s*\(\s*".*INSERT',
        r'fmt\.Sprintf\s*\(\s*".*UPDATE',
        r'fmt\.Sprintf\s*\(\s*".*DELETE',
        r'mysqli.*query\s*\([^)]*\.\s*\$',
        r'mysql_query\s*\([^)]*\.\s*\$',
    ],
    "command_injection": [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\([^,\]]*shell\s*=\s*True',
        r'subprocess\.run\s*\([^,\]]*shell\s*=\s*True',
        r'subprocess\.Popen\s*\([^,\]]*shell\s*=\s*True',
        r'Process\.Start\s*\(',
        r'Runtime\.getRuntime\(\)\.exec\s*\(',
        r'ProcessBuilder\s*\(',
        r'exec\.Command\s*\(\s*"(?:sh|bash|cmd)"',
        r'shell_exec\s*\(',
        r'passthru\s*\(',
        r'popen\s*\(',
        r'system\s*\(\s*["\'].*\.\s*\$',
        r'system\s*\(\s*["\'].*\+',
    ],
    "code_injection": [
        r'\beval\s*\(',
        r'\bnew\s+Function\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
    ],
    "xss": [
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write\s*\(',
        r'\.html\s*\(\s*[^)]*\+',
        r'dangerouslySetInnerHTML',
        r'Html\.Raw\s*\(',
        r'fmt\.Fprintf\s*\(\s*w\s*,\s*["`].*<',
        r'w\.Write\s*\(\s*\[\]byte\s*\(\s*"<',
        r'w\.Write\s*\(\s*\[\]byte\s*\(\s*".*\+',
        r'echo\s+["\']?<.*\.\s*\$',
        r'echo\s+\$_(?:GET|POST|REQUEST)',
        r'echo\s+["\'].*\$_(?:GET|POST|REQUEST)',
        r'print\s+\$_(?:GET|POST|REQUEST)',
    ],
    "path_traversal": [
        r'open\s*\([^)]*\+',
        r'file_get_contents\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$',
        r'include\s*\(\s*\$',
        r'require\s*\(\s*\$',
        r'File\.Open\s*\(',
        r'FileStream\s*\(',
        r'StreamReader\s*\([^)]*\+',
        r'Path\.Combine\s*\([^)]*,\s*\w+\s*\)',
        r'File\.ReadAllBytes\s*\([^)]*\+',
        r'ioutil\.ReadFile\s*\([^)]*\+',
        r'os\.Open\s*\([^)]*\+',
        r'filepath\.Join\s*\([^)]*,\s*\w+\s*\)',
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
        r'PRIVATE_KEY\s*=',
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
        r'crypto/md5',
        r'crypto/sha1',
        r'md5\.New\s*\(',
        r'sha1\.New\s*\(',
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
        r'gob\.NewDecoder\s*\(',
    ],
    "ssrf": [
        r'requests\.get\s*\([^)]*\+',
        r'urllib\.request\.urlopen\s*\(',
        r'file_get_contents\s*\(\s*\$',
        r'curl_init\s*\(\s*\$',
        r'curl_exec\s*\(',
        r'WebClient\s*\(\)',
        r'HttpClient\s*\(\)',
        r'fetch\s*\([^)]*\+',
        r'http\.Get\s*\(\s*\w',
        r'http\.NewRequest\s*\([^,]*,\s*\w+\s*,',
    ],
    "open_redirect": [
        r'header\s*\(\s*["\']Location:\s*["\']\s*\.\s*\$',
        r'header\s*\(\s*["\']Location:\s*.*\$_GET',
        r'Response\.Redirect\s*\(',
        r'sendRedirect\s*\(',
        r'res\.redirect\s*\(',
        r'http\.Redirect\s*\(\s*w\s*,\s*r\s*,\s*\w+',
    ],
    "xxe": [
        r'XmlDocument\s*\(\)',
        r'XmlTextReader',
        r'XmlReader\.Create',
        r'XmlUrlResolver',
        r'etree\.parse\s*\(',
        r'xml\.dom\.minidom',
        r'DocumentBuilder',
        r'SAXParser',
        r'XMLInputFactory',
        r'DOMDocument\s*\(\)',
        r'simplexml_load_string\s*\(',
        r'simplexml_load_file\s*\(',
    ],
    "auth_issues": [
        r'\[HttpPost\](?!.*\[Authorize\])',
        r'\[HttpGet\](?!.*\[Authorize\])',
        r'@RequestMapping(?!.*@PreAuthorize)',
        r'@GetMapping(?!.*@PreAuthorize)',
        r'@PostMapping(?!.*@PreAuthorize)',
    ],
    "insecure_random": [
        r'random\.random\s*\(',
        r'random\.randint\s*\(',
        r'Math\.random\s*\(',
        r'new\s+Random\s*\(',
        r'\brand\s*\(\s*\d',
        r'mt_rand\s*\(',
        r'math/rand',
        r'rand\.Seed\s*\(',
        r'rand\.Int',
    ],
    "csrf": [
        r'\[HttpPost\](?!.*ValidateAntiForgeryToken)',
    ],
    "file_upload": [
        r'move_uploaded_file\s*\(',
        r'\$_FILES\s*\[',
    ],
    "information_disclosure": [
        r'Environment\.StackTrace',
        r'fmt\.Fprintf\s*\(\s*w\s*,.*err\b',
        r'phpinfo\s*\(\)',
        r'var_dump\s*\(',
        r'print_r\s*\(',
    ],
}

# ============================================================================
# LANGUAGE-SPECIFIC SKIP RULES
# ============================================================================

SKIP_PATTERNS_BY_LANG = {
    "go": {
        "code_injection": True,
        "auth_issues": True,
        "csrf": True,
        "file_upload": True,
    },
    "php": {
        "code_injection": [r'\bexec\s*\('],
        "auth_issues": True,
        "csrf": True,
    },
    "python": {
        "auth_issues": True,
        "csrf": True,
        "file_upload": True,
    },
    "javascript": {
        "auth_issues": True,
        "csrf": True,
        "file_upload": True,
    },
    "java": {
        "csrf": True,
        "file_upload": True,
    },
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
    "file_upload": "HIGH",
    "open_redirect": "MEDIUM",
    "auth_issues": "MEDIUM",
    "csrf": "MEDIUM",
    "weak_crypto": "MEDIUM",
    "insecure_random": "LOW",
    "information_disclosure": "LOW",
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
    "file_upload": "Unrestricted File Upload",
    "information_disclosure": "Information Disclosure",
}

LLM_KEYWORDS = {
    "sql_injection": ["sql injection", "sql_injection", "sqli", "parameterized query", "prepared statement"],
    "command_injection": ["command injection", "os.system", "subprocess", "shell injection", "process.start", "runtime.exec", "shell_exec", "exec.command"],
    "code_injection": ["code injection", "remote code execution", "function constructor"],
    "xss": ["xss", "cross-site scripting", "innerhtml", "html.raw", "script injection", "htmlencode", "htmlspecialchars"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "local file inclusion", "../", "getfilename", "filepath.base"],
    "hardcoded_secrets": ["hardcoded", "hard-coded", "hardcode", "secret", "password", "api key", "credentials", "exposed"],
    "weak_crypto": ["weak crypto", "md5", "sha1", "weak hash", "insecure hash", "sha256", "password_hash"],
    "insecure_deserialization": ["deserialization", "pickle", "unserialize", "binaryformatter", "objectinputstream", "gob.newdecoder"],
    "ssrf": ["ssrf", "server-side request forgery", "internal network", "metadata", "169.254"],
    "open_redirect": ["open redirect", "url redirect", "unvalidated redirect", "islocalurl"],
    "xxe": ["xxe", "xml external entity", "xml injection", "dtd", "xmlresolver"],
    "auth_issues": ["authentication", "authorization", "missing auth", "[authorize]", "login_required", "unauthenticated", "middleware"],
    "insecure_random": ["insecure random", "math.random", "random()", "predictable", "securerandom", "crypto/rand", "random_bytes"],
    "csrf": ["csrf", "cross-site request forgery", "antiforgery", "csrf token", "validateantiforgerytoken"],
    "file_upload": ["file upload", "uploaded file", "move_uploaded_file", "multipart", "file validation", "unrestricted upload"],
    "information_disclosure": ["information disclosure", "stack trace", "error message", "debug", "verbose error", "phpinfo", "internal error"],
}


DEFAULT_FIXES = {
    "sql_injection": {
        "csharp": {
            "fix": "// Use parameterized queries\nstring query = \"SELECT * FROM Users WHERE UserId = @UserId\";\ncmd.Parameters.AddWithValue(\"@UserId\", userId);",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use parameterized queries to separate code from data."
        },
        "go": {
            "fix": "// Use parameterized queries with placeholders\nrows, err := db.Query(\"SELECT * FROM users WHERE id = ?\", id)\n// For LIKE queries:\nrows, err := db.Query(\"SELECT * FROM users WHERE name LIKE ?\", \"%\"+name+\"%\")\n// For Exec:\n_, err := db.Exec(\"DELETE FROM users WHERE id = ?\", id)",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use query placeholders (?) instead of string concatenation or fmt.Sprintf."
        },
        "php": {
            "fix": "// Use prepared statements with MySQLi\n$stmt = $conn->prepare(\"SELECT * FROM users WHERE id = ?\");\n$stmt->bind_param(\"i\", $id);\n$stmt->execute();",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use prepared statements with bound parameters."
        },
        "python": {
            "fix": "# Use parameterized queries\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use parameterized queries."
        },
        "java": {
            "fix": "// Use PreparedStatement\nPreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use PreparedStatement."
        },
        "javascript": {
            "fix": "// Use parameterized queries\nconst result = await db.query(\"SELECT * FROM users WHERE id = $1\", [userId]);",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use parameterized queries."
        },
        "_default": {
            "fix": "// Use parameterized queries instead of string concatenation",
            "explanation": "SQL Injection allows attackers to execute arbitrary SQL commands. Use parameterized queries."
        }
    },
    "command_injection": {
        "csharp": {
            "fix": "// Validate input with whitelist\nif (!Regex.IsMatch(input, @\"^[a-zA-Z0-9\\\\.\\\\-]+$\"))\n    return BadRequest(\"Invalid input\");",
            "explanation": "Command Injection allows attackers to execute arbitrary system commands. Validate and whitelist input."
        },
        "go": {
            "fix": "// Validate input — never pass user input to sh -c\nvalidHost := regexp.MustCompile(`^[a-zA-Z0-9.\\\\-]+$`)\nif !validHost.MatchString(host) {\n    http.Error(w, \"Invalid host\", http.StatusBadRequest)\n    return\n}\ncmd := exec.Command(\"ping\", \"-c\", \"4\", host)",
            "explanation": "Command Injection allows attackers to execute arbitrary system commands. Never use exec.Command(\"sh\", \"-c\", userInput). Pass arguments separately."
        },
        "php": {
            "fix": "// Use escapeshellarg() and validate input\nif (!preg_match('/^[a-zA-Z0-9.\\\\-]+$/', $host)) {\n    die(\"Invalid input\");\n}\n$output = shell_exec(\"ping -c 4 \" . escapeshellarg($host));",
            "explanation": "Command Injection allows attackers to execute arbitrary system commands. Use escapeshellarg() and input validation."
        },
        "python": {
            "fix": "# Use subprocess with list arguments, never shell=True\nimport subprocess\nsubprocess.run([\"ping\", \"-c\", \"4\", host], check=True)",
            "explanation": "Command Injection allows attackers to execute arbitrary system commands. Use subprocess with list args."
        },
        "_default": {
            "fix": "// Validate input with whitelist\n// Never pass user input directly to shell commands",
            "explanation": "Command Injection allows attackers to execute arbitrary system commands."
        }
    },
    "code_injection": {
        "php": {
            "fix": "// Remove eval() entirely\n$allowed = ['home', 'about', 'contact'];\nif (in_array($page, $allowed)) {\n    include($page . '.php');\n}",
            "explanation": "Code Injection allows attackers to execute arbitrary code. Never use eval() with user input."
        },
        "python": {
            "fix": "# Never use eval()/exec() with user input\nimport ast\nresult = ast.literal_eval(expression)  # Only allows literals",
            "explanation": "Code Injection allows attackers to execute arbitrary code. Use ast.literal_eval() for safe evaluation."
        },
        "javascript": {
            "fix": "// Never use eval() or new Function() with user input\n// For JSON: use JSON.parse()\nconst data = JSON.parse(input);",
            "explanation": "Code Injection allows attackers to execute arbitrary code. Use JSON.parse() for data."
        },
        "_default": {
            "fix": "// Remove eval/exec entirely\n// Use safe parsing alternatives",
            "explanation": "Code Injection allows attackers to execute arbitrary code. Never use eval() with user input."
        }
    },
    "xss": {
        "csharp": {
            "fix": "// Encode output — never use Html.Raw() with user input\nreturn Content(HttpUtility.HtmlEncode(userInput));",
            "explanation": "XSS allows attackers to inject malicious scripts. Always HTML-encode user output."
        },
        "go": {
            "fix": "// Use html/template (auto-escapes) instead of fmt.Fprintf\nimport \"html/template\"\ntmpl := template.Must(template.New(\"page\").Parse(\n    `<html><body><h1>{{.Message}}</h1></body></html>`))\ntmpl.Execute(w, data)\n// Or: fmt.Fprintf(w, \"<h1>%s</h1>\", html.EscapeString(message))",
            "explanation": "XSS allows attackers to inject malicious scripts. Use html/template or html.EscapeString()."
        },
        "php": {
            "fix": "// Always encode output with htmlspecialchars()\necho \"<div>\" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . \"</div>\";",
            "explanation": "XSS allows attackers to inject malicious scripts. Always use htmlspecialchars() for user output."
        },
        "javascript": {
            "fix": "// Use textContent instead of innerHTML\nelement.textContent = userInput;",
            "explanation": "XSS allows attackers to inject malicious scripts. Use textContent for text output."
        },
        "_default": {
            "fix": "// Encode all user output before rendering in HTML",
            "explanation": "XSS allows attackers to inject malicious scripts. Always encode user output."
        }
    },
    "path_traversal": {
        "csharp": {
            "fix": "// Strip directory components and verify path\nstring safeName = Path.GetFileName(userInput);\nstring fullPath = Path.Combine(basePath, safeName);\nif (!Path.GetFullPath(fullPath).StartsWith(basePath))\n    return BadRequest(\"Invalid path\");",
            "explanation": "Path Traversal allows attackers to access files outside the intended directory using ../ sequences."
        },
        "go": {
            "fix": "// Use filepath.Base() and verify resolved path\nimport \"path/filepath\"\nsafeName := filepath.Base(filename)\nfullPath := filepath.Join(basePath, safeName)\nabsPath, _ := filepath.Abs(fullPath)\nif !strings.HasPrefix(absPath, basePath) {\n    http.Error(w, \"Invalid path\", http.StatusBadRequest)\n    return\n}",
            "explanation": "Path Traversal allows attackers to access files outside the intended directory. Use filepath.Base() and verify the resolved path."
        },
        "php": {
            "fix": "// Use basename() and realpath() validation\n$safeName = basename($filename);\n$fullPath = '/var/www/files/' . $safeName;\nif (strpos(realpath($fullPath), '/var/www/files/') !== 0) {\n    die(\"Invalid path\");\n}\n// For include/require: use a whitelist\n$allowed = ['header', 'footer', 'sidebar'];\nif (in_array($template, $allowed)) include($template . '.php');",
            "explanation": "Path Traversal allows attackers to access files outside the intended directory. Use basename() and realpath()."
        },
        "_default": {
            "fix": "// Strip directory components from user input\n// Verify the resolved path stays within the intended directory",
            "explanation": "Path Traversal allows attackers to access files outside the intended directory."
        }
    },
    "hardcoded_secrets": {
        "csharp": {
            "fix": "// Use environment variables\nstring password = Environment.GetEnvironmentVariable(\"DB_PASSWORD\");",
            "explanation": "Hardcoded secrets can be extracted from source code. Use environment variables or Secret Manager."
        },
        "go": {
            "fix": "// Use environment variables\nimport \"os\"\ndbPassword := os.Getenv(\"DB_PASSWORD\")\napiKey := os.Getenv(\"API_KEY\")",
            "explanation": "Hardcoded secrets can be extracted from source code. Use os.Getenv()."
        },
        "php": {
            "fix": "// Use environment variables\n$db_password = getenv('DB_PASSWORD');\n// Or use .env file with vlucas/phpdotenv",
            "explanation": "Hardcoded secrets can be extracted from source code. Use environment variables or .env files."
        },
        "python": {
            "fix": "# Use environment variables\nimport os\ndb_password = os.environ.get('DB_PASSWORD')",
            "explanation": "Hardcoded secrets can be extracted from source code. Use os.environ."
        },
        "_default": {
            "fix": "// Use environment variables or a secrets management solution",
            "explanation": "Hardcoded secrets can be extracted from source code. Store secrets securely."
        }
    },
    "weak_crypto": {
        "csharp": {
            "fix": "// For passwords: use BCrypt. For hashing: SHA256\nusing (var sha256 = SHA256.Create()) { ... }",
            "explanation": "MD5 and SHA1 are cryptographically broken. Use SHA256+ for hashing and bcrypt for passwords."
        },
        "go": {
            "fix": "// For passwords: use bcrypt\nimport \"golang.org/x/crypto/bcrypt\"\nhash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)\n// For hashing: use SHA256\nimport \"crypto/sha256\"\nh := sha256.New()\nh.Write([]byte(data))",
            "explanation": "MD5 and SHA1 are broken. Use crypto/sha256 for hashing and bcrypt for passwords."
        },
        "php": {
            "fix": "// For passwords: use password_hash()\n$hash = password_hash($password, PASSWORD_DEFAULT);\n$valid = password_verify($input, $hash);\n// For hashing: use SHA256\n$hash = hash('sha256', $data);",
            "explanation": "MD5 and SHA1 are broken. Use password_hash()/password_verify() and hash('sha256', ...)."
        },
        "python": {
            "fix": "# For passwords: use bcrypt\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n# For hashing: use SHA256\nimport hashlib\nh = hashlib.sha256(data.encode()).hexdigest()",
            "explanation": "MD5 and SHA1 are broken. Use bcrypt for passwords and hashlib.sha256 for hashing."
        },
        "_default": {
            "fix": "// Use bcrypt/Argon2 for passwords, SHA-256+ for hashing",
            "explanation": "MD5 and SHA1 are cryptographically broken. Use modern algorithms."
        }
    },
    "insecure_deserialization": {
        "csharp": {
            "fix": "// Use JsonSerializer instead of BinaryFormatter\nvar obj = System.Text.Json.JsonSerializer.Deserialize<MyType>(jsonString);",
            "explanation": "BinaryFormatter can lead to RCE. Use JSON serialization with strong typing."
        },
        "go": {
            "fix": "// Use encoding/json instead of gob for untrusted input\nimport \"encoding/json\"\nvar session map[string]interface{}\nerr := json.NewDecoder(r.Body).Decode(&session)",
            "explanation": "Deserializing untrusted data with gob is dangerous. Use encoding/json with defined struct types."
        },
        "php": {
            "fix": "// Use json_decode() instead of unserialize()\n$data = json_decode($_POST['data'], true);\n// If needed: $obj = unserialize($data, ['allowed_classes' => false]);",
            "explanation": "unserialize() with untrusted data can lead to RCE. Use json_decode() instead."
        },
        "python": {
            "fix": "# Use json.loads() instead of pickle.loads()\nimport json\ndata = json.loads(user_input)",
            "explanation": "pickle.loads() with untrusted data can lead to RCE. Use json.loads()."
        },
        "_default": {
            "fix": "// Use JSON serialization instead of binary formats",
            "explanation": "Insecure deserialization can lead to RCE. Use safe formats like JSON."
        }
    },
    "ssrf": {
        "csharp": {
            "fix": "// Whitelist allowed domains\nvar allowedHosts = new[] { \"api.example.com\" };\nvar uri = new Uri(userUrl);\nif (!allowedHosts.Contains(uri.Host))\n    return BadRequest(\"URL not allowed\");",
            "explanation": "SSRF allows attackers to make requests to internal services. Whitelist allowed domains."
        },
        "go": {
            "fix": "// Whitelist allowed domains\nu, err := url.Parse(targetURL)\nif err != nil || !isAllowedHost(u.Hostname()) {\n    http.Error(w, \"URL not allowed\", http.StatusBadRequest)\n    return\n}",
            "explanation": "SSRF allows attackers to make requests to internal services. Whitelist allowed domains and block private IPs."
        },
        "php": {
            "fix": "// Whitelist allowed domains\n$allowed = ['api.example.com'];\n$parsed = parse_url($url);\nif (!in_array($parsed['host'], $allowed)) die(\"URL not allowed\");\n// Block private IPs\n$ip = gethostbyname($parsed['host']);\nif (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) die(\"Blocked\");",
            "explanation": "SSRF allows attackers to make requests to internal services. Whitelist domains and block private IPs."
        },
        "_default": {
            "fix": "// Whitelist allowed domains\n// Block private IP ranges",
            "explanation": "SSRF allows attackers to make requests to internal services."
        }
    },
    "open_redirect": {
        "csharp": {
            "fix": "// Validate redirect is local\nif (!Url.IsLocalUrl(redirectUrl))\n    return BadRequest(\"Invalid redirect\");",
            "explanation": "Open Redirect allows attackers to redirect users to malicious sites."
        },
        "go": {
            "fix": "// Validate redirect URL is relative\nu, err := url.Parse(redirectURL)\nif err != nil || u.IsAbs() {\n    http.Error(w, \"Invalid redirect\", http.StatusBadRequest)\n    return\n}\nhttp.Redirect(w, r, u.Path, http.StatusFound)",
            "explanation": "Open Redirect allows attackers to redirect to malicious sites. Validate URLs are relative."
        },
        "php": {
            "fix": "// Whitelist allowed redirect paths\n$allowed = ['/dashboard', '/profile', '/settings'];\nif (!in_array($url, $allowed)) die(\"Invalid redirect\");\n// Or check it's relative\nif (parse_url($url, PHP_URL_SCHEME) !== null) die(\"External redirect blocked\");",
            "explanation": "Open Redirect allows attackers to redirect to malicious sites. Validate against a whitelist."
        },
        "_default": {
            "fix": "// Validate redirect URL against a whitelist or ensure it's relative",
            "explanation": "Open Redirect allows attackers to redirect users to malicious sites."
        }
    },
    "xxe": {
        "csharp": {
            "fix": "// Disable external entity processing\nXmlReaderSettings settings = new XmlReaderSettings();\nsettings.DtdProcessing = DtdProcessing.Prohibit;\nsettings.XmlResolver = null;",
            "explanation": "XXE allows attackers to read local files or perform SSRF. Disable DTD processing."
        },
        "go": {
            "fix": "// Go encoding/xml is safe by default (no external entities)\nimport \"encoding/xml\"\nvar data MyStruct\nerr := xml.Unmarshal(body, &data)  // Safe by default",
            "explanation": "Go's encoding/xml is safe by default. Ensure third-party XML libraries are also configured safely."
        },
        "php": {
            "fix": "// Disable entity loading before parsing\nlibxml_disable_entity_loader(true);  // PHP < 8.0\n$doc = new DOMDocument();\n$doc->loadXML($xml, LIBXML_NONET);",
            "explanation": "XXE allows attackers to read local files. Disable entity loading and use LIBXML_NONET."
        },
        "_default": {
            "fix": "// Disable external entity processing in your XML parser",
            "explanation": "XXE allows attackers to read local files or perform SSRF."
        }
    },
    "auth_issues": {
        "csharp": {
            "fix": "// Add [Authorize] attribute\n[Authorize]\n[HttpGet]\npublic ActionResult SecureEndpoint() { ... }\n// Role-based: [Authorize(Roles = \"Admin\")]",
            "explanation": "Missing authentication allows unauthorized access. Add [Authorize] to protected actions."
        },
        "go": {
            "fix": "// Add authentication middleware\nfunc authMiddleware(next http.HandlerFunc) http.HandlerFunc {\n    return func(w http.ResponseWriter, r *http.Request) {\n        token := r.Header.Get(\"Authorization\")\n        if !isValidToken(token) {\n            http.Error(w, \"Unauthorized\", http.StatusUnauthorized)\n            return\n        }\n        next(w, r)\n    }\n}\n// Usage: http.HandleFunc(\"/admin\", authMiddleware(handler))",
            "explanation": "Missing authentication allows unauthorized access. Wrap handlers with auth middleware."
        },
        "php": {
            "fix": "// Check authentication at the start of protected functions\nif (!isset($_SESSION['user_id']) || !$this->isAdmin($_SESSION['user_id'])) {\n    http_response_code(403);\n    die(\"Unauthorized\");\n}",
            "explanation": "Missing authentication allows unauthorized access. Check session/auth before sensitive operations."
        },
        "java": {
            "fix": "// Add @PreAuthorize\n@PreAuthorize(\"hasRole('ADMIN')\")\n@GetMapping(\"/admin\")\npublic ResponseEntity<?> adminPanel() { ... }",
            "explanation": "Missing authentication allows unauthorized access. Add @PreAuthorize."
        },
        "_default": {
            "fix": "// Add authentication checks to all sensitive endpoints",
            "explanation": "Missing authentication allows unauthorized access."
        }
    },
    "insecure_random": {
        "csharp": {
            "fix": "// Use RandomNumberGenerator\nusing var rng = RandomNumberGenerator.Create();\nbyte[] bytes = new byte[32];\nrng.GetBytes(bytes);",
            "explanation": "System.Random is predictable. Use RandomNumberGenerator for security values."
        },
        "go": {
            "fix": "// Use crypto/rand instead of math/rand\nimport crypto_rand \"crypto/rand\"\nimport \"encoding/hex\"\nb := make([]byte, 32)\ncrypto_rand.Read(b)\ntoken := hex.EncodeToString(b)",
            "explanation": "math/rand is predictable. Use crypto/rand for security values."
        },
        "php": {
            "fix": "// Use random_bytes() or random_int() (PHP 7+)\n$token = bin2hex(random_bytes(32));\n$number = random_int(100000, 999999);",
            "explanation": "rand() and mt_rand() are predictable. Use random_bytes()/random_int()."
        },
        "python": {
            "fix": "# Use secrets module\nimport secrets\ntoken = secrets.token_hex(32)",
            "explanation": "random module is predictable. Use secrets module for security values."
        },
        "_default": {
            "fix": "// Use cryptographically secure random generators",
            "explanation": "Standard random is predictable. Use cryptographic random for security values."
        }
    },
    "csrf": {
        "csharp": {
            "fix": "// Add ValidateAntiForgeryToken\n[HttpPost]\n[ValidateAntiForgeryToken]\npublic ActionResult SubmitForm() { ... }",
            "explanation": "CSRF allows attackers to trick users into unwanted actions. Use anti-forgery tokens."
        },
        "php": {
            "fix": "// Generate and validate CSRF tokens\n$_SESSION['csrf_token'] = bin2hex(random_bytes(32));\n// Validate: hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')",
            "explanation": "CSRF allows attackers to trick users into unwanted actions. Use CSRF tokens."
        },
        "_default": {
            "fix": "// Implement CSRF token validation for state-changing requests",
            "explanation": "CSRF allows attackers to trick users into unwanted actions."
        }
    },
    "file_upload": {
        "php": {
            "fix": "// Validate file type, size, and use random filename\n$allowed = ['image/jpeg', 'image/png'];\n$finfo = finfo_open(FILEINFO_MIME_TYPE);\n$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);\nif (!in_array($mime, $allowed)) die(\"Invalid type\");\n$safeName = bin2hex(random_bytes(16)) . '.jpg';\nmove_uploaded_file($_FILES['file']['tmp_name'], '/uploads/' . $safeName);",
            "explanation": "Unrestricted upload allows malicious files. Validate MIME type, size, and use random filenames."
        },
        "_default": {
            "fix": "// Validate file type, size, and extension\n// Use random filenames",
            "explanation": "Unrestricted file upload allows attackers to upload malicious files."
        }
    },
    "information_disclosure": {
        "csharp": {
            "fix": "// Log internally, return generic messages\ntry { ... } catch (Exception ex) {\n    _logger.LogError(ex, \"Failed\");\n    return StatusCode(500, \"An error occurred\");\n}",
            "explanation": "Exposing stack traces helps attackers. Log internally, show generic messages."
        },
        "go": {
            "fix": "// Log errors internally, return generic messages\nlog.Printf(\"Internal error: %v\", err)\nhttp.Error(w, \"Internal server error\", http.StatusInternalServerError)",
            "explanation": "Exposing error details helps attackers. Use log.Printf internally."
        },
        "php": {
            "fix": "// Disable error display in production\nini_set('display_errors', '0');\nini_set('log_errors', '1');\n// Remove phpinfo(), var_dump(), print_r()",
            "explanation": "Exposing errors helps attackers. Disable display_errors in production."
        },
        "_default": {
            "fix": "// Log errors internally, never expose stack traces to users",
            "explanation": "Information disclosure helps attackers understand your application."
        }
    }
}


# ============================================================================
# LANGUAGE DETECTION
# ============================================================================

def detect_language(code):
    """Detect programming language from code content."""
    if any(kw in code for kw in ['package main', 'func ', 'import (', 'fmt.', ':= ', 'go func']):
        return "go"
    if '<?php' in code or (('$_GET' in code or '$_POST' in code or '$this->' in code) and '$' in code):
        return "php"
    if any(kw in code for kw in ['using System', 'namespace ', 'public class', 'ActionResult', '[HttpGet]', '[HttpPost]']):
        return "csharp"
    if any(kw in code for kw in ['import java.', 'public static void main', '@RestController', '@GetMapping']):
        return "java"
    if any(kw in code for kw in ['def ', 'import ', 'from ', 'print(']):
        if 'def ' in code and ':' in code:
            return "python"
    if any(kw in code for kw in ['const ', 'let ', 'var ', 'require(', 'module.exports', '=>']):
        return "javascript"
    if any(kw in code for kw in ['#include <', 'std::', 'cout <<', 'int main()']):
        return "cpp"
    return "unknown"


# ============================================================================
# LLM FIX EXTRACTION
# ============================================================================

def _is_valid_code_fix(text):
    """Check if extracted text looks like actual code, not LLM rambling."""
    # Reject if it contains obvious LLM meta-commentary phrases
    rambling_phrases = [
        'this solution', 'systematically', 'comprehensive', 'the structured approach',
        'transition statements', 'aligning with', 'the final output', 'character limit',
        'ensuring logical', 'easy comprehension', 'mitigation strategies', 'no critical issues',
        'vulnerability type in the provided', 'suggesting specific fixes',
        'the user can use', 'formatted to fit', 'maintaining clarity',
        'guide the reader', 'vulnerability category',
    ]
    text_lower = text.lower()
    for phrase in rambling_phrases:
        if phrase in text_lower:
            return False

    # Reject if it has too many long English sentences and too few code indicators
    code_indicators = ['//', '#', 'import ', 'func ', 'var ', 'const ', 'string ',
                       'if (', 'if !', 'return ', 'new ', 'using ', '$', '()',
                       '{', '}', ';', ':=', '=>', '->']
    code_score = sum(1 for ind in code_indicators if ind in text)

    # Count sentences (rough heuristic: periods followed by capital letters)
    sentence_count = len(re.findall(r'\.\s+[A-Z]', text))

    # If it reads more like prose than code, reject it
    if sentence_count > 3 and code_score < 3:
        return False

    return True


def extract_llm_fixes(raw_response):
    """Extract vulnerability-specific fixes from LLM response."""
    fixes = {}
    sections = re.split(r'##\s+', raw_response)
    for section in sections:
        if not section.strip():
            continue
        section_lower = section.lower()[:300]
        matched_vuln = None
        for vuln_type, keywords in LLM_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in section_lower:
                    matched_vuln = vuln_type
                    break
            if matched_vuln:
                break
        if not matched_vuln:
            continue
        fix_patterns = [
            r'\*\*Fixed Code:\*\*\s*```[\w]*\n(.*?)```',
            r'\*\*Recommended Fix:\*\*\s*```[\w]*\n(.*?)```',
            r'(?:Fix|Secure|Safe|Remediat).*?```[\w]*\n(.*?)```',
        ]
        for pattern in fix_patterns:
            match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
            if match:
                fix_text = match.group(1).strip()
                if len(fix_text) > 10 and _is_valid_code_fix(fix_text):
                    fixes[matched_vuln] = fix_text
                break
    return fixes


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_fix_for_language(vuln_type, language):
    """Get language-specific fix and explanation."""
    fix_data = DEFAULT_FIXES.get(vuln_type, {})
    return fix_data.get(language, fix_data.get("_default", {}))


def should_skip_vuln(vuln_type, language):
    """Check if a vuln type should be skipped for this language."""
    skip_rules = SKIP_PATTERNS_BY_LANG.get(language, {})
    if vuln_type in skip_rules:
        return skip_rules[vuln_type] is True
    return False


def get_filtered_patterns(vuln_type, language):
    """Get patterns filtered for language appropriateness."""
    patterns = DANGER_PATTERNS.get(vuln_type, [])
    skip_rules = SKIP_PATTERNS_BY_LANG.get(language, {})
    if vuln_type in skip_rules:
        skip = skip_rules[vuln_type]
        if skip is True:
            return []
        if isinstance(skip, list):
            patterns = [p for p in patterns if p not in skip]
    return patterns


# ============================================================================
# MAIN PARSER
# ============================================================================

def parse_llm_response(raw_response, code):
    """Parse LLM response and extract vulnerability information."""
    language = detect_language(code)
    lines = code.split('\n')
    findings = []
    found_vulns = set()
    response_lower = raw_response.lower()

    # Try to extract actual fixes from LLM response
    llm_fixes = extract_llm_fixes(raw_response)

    # Method 1: Check LLM response for mentioned vulnerabilities
    for vuln_type, keywords in LLM_KEYWORDS.items():
        if should_skip_vuln(vuln_type, language):
            continue
        for keyword in keywords:
            if keyword.lower() in response_lower:
                if vuln_type not in found_vulns:
                    found_vulns.add(vuln_type)
                    vulnerable_lines = []
                    patterns = get_filtered_patterns(vuln_type, language)
                    for i, line in enumerate(lines, 1):
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                vulnerable_lines.append({
                                    "line_number": i,
                                    "code": line.strip()
                                })
                                break
                    lang_fix = get_fix_for_language(vuln_type, language)
                    fix_code = llm_fixes.get(vuln_type, lang_fix.get("fix", ""))
                    explanation = lang_fix.get("explanation", "")
                    findings.append({
                        "vulnerability": VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                        "severity": SEVERITY_MAP.get(vuln_type, "MEDIUM"),
                        "vuln_type": vuln_type,
                        "vulnerable_lines": vulnerable_lines[:5],
                        "fixed_code": fix_code,
                        "explanation": explanation,
                    })
                break

    # Method 2: Direct pattern scanning (for vulns not mentioned by LLM)
    for vuln_type in DANGER_PATTERNS:
        if vuln_type in found_vulns:
            continue
        if should_skip_vuln(vuln_type, language):
            continue
        filtered_patterns = get_filtered_patterns(vuln_type, language)
        if not filtered_patterns:
            continue
        vulnerable_lines = []
        for i, line in enumerate(lines, 1):
            for pattern in filtered_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerable_lines.append({
                        "line_number": i,
                        "code": line.strip()
                    })
                    break
        if vulnerable_lines:
            found_vulns.add(vuln_type)
            lang_fix = get_fix_for_language(vuln_type, language)
            fix_code = llm_fixes.get(vuln_type, lang_fix.get("fix", ""))
            explanation = lang_fix.get("explanation", "")
            findings.append({
                "vulnerability": VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                "severity": SEVERITY_MAP.get(vuln_type, "MEDIUM"),
                "vuln_type": vuln_type,
                "vulnerable_lines": vulnerable_lines[:5],
                "fixed_code": fix_code,
                "explanation": explanation,
            })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "has_vulnerabilities": len(findings) > 0,
        "findings": findings,
        "language_detected": language,
        "raw_response": raw_response
    }


def filter_findings(findings):
    """Filter findings to only include those with vulnerable lines."""
    return [f for f in findings if f.get('vulnerable_lines') and len(f['vulnerable_lines']) > 0]
