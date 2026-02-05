# 🛡️ CodeGuard - AI-Powered Security Code Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Ollama-Local%20LLM-green.svg" alt="Ollama">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/VS%20Code-Continue%20Extension-purple.svg" alt="VS Code">
</p>

<p align="center">
  <b>Detect security vulnerabilities in your code using local AI - No data leaves your machine!</b>
</p>

---

## 🎯 Features
- **🔒 100% Private**
  - Runs completely locally using Ollama
  - No code sent to external servers
  - Works offline
    
- **🔍 14+ Vulnerability Types Detected**
  - SQL Injection, Command Injection, XSS, Path Traversal
  - Hardcoded Secrets, Insecure Deserialization, SSRF, XXE
  - Weak Cryptography, CSRF, Open Redirect, and more

- **🌐 Multi-Language Support**
  - C#, Java, Python, JavaScript/TypeScript, PHP, Go, Ruby, C/C++, Kotlin, Swift, Rust

- **🖥️ Two Ways to Scan**
  - **CLI Tool**: Scan entire projects, generate beautiful HTML reports
  - **VS Code Integration**: Real-time code review with `/sec` command

- **📊 Beautiful HTML Reports**
  - Clickable issue navigation
  - Severity-based color coding
  - Vulnerable code + Fixed code examples
  - Explanations for each vulnerability

---

## 📸 Screenshots

### CLI Scanner
```
════════════════════════════════════════════════════════════
                 PROJECT SCANNER
════════════════════════════════════════════════════════════
  📁 Directory: F:\my-project
────────────────────────────────────────────────────────────
  📊 Files Found:

     • C#.................. 5 files
     • JavaScript.......... 3 files
     • Python.............. 2 files
     ─────────────────────────
     📌 Total:          10 files
════════════════════════════════════════════════════════════

  ✅ [1/10] Completed: UserController.cs      | ⏱️ 49s
  ✅ [2/10] Completed: AuthService.js         | ⏱️ 37s
  ...

  📊 Quick Summary: 15 vulnerabilities found
     🔴 Critical: 3  🟠 High: 5  🟡 Medium: 4  🟢 Low: 3
```

### HTML Report
- Summary cards with vulnerability counts
- Files scanned with per-file statistics
- Clickable issues list
- Detailed findings with:
  - Vulnerable code (from your source)
  - Recommended fix
  - Explanation of why it's vulnerable

### VS Code Integration
- Select code → Run `/sec` command
- Instant security analysis
- Vulnerable code + Fixed code suggestions

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+**
2. **Ollama** - [Download here](https://ollama.ai)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/mzaidii/CodeGuard.git
cd CodeGuard

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Create the security model in Ollama
cd ollama
ollama create security-reviewer -f Modelfile
# ⏳ This will automatically download Qwen2.5-Coder (~4.5GB) on first run

# 4. Verify model is created
ollama list
```

> **Note:** The base model (Qwen2.5-Coder 7B) will be automatically downloaded when you create the security-reviewer model. This requires ~4.5GB of disk space and may take a few minutes depending on your internet connection.

### Usage

#### CLI Scanner

```bash
# Interactive mode - scan current directory
python cli.py

# Scan specific directory
python cli.py /path/to/project

# Scan single file
python cli.py vulnerable.py

# Quick summary (no detailed analysis)
python cli.py app.py --summary

# JSON output
python cli.py app.py --json
```

#### VS Code Integration

1. Install [Continue Extension](https://marketplace.visualstudio.com/items?itemName=Continue.continue)

2. Copy config to Continue:
   ```bash
   # Windows
   copy vscode-config\config.json %USERPROFILE%\.continue\config.json
   
   # Linux/Mac
   cp vscode-config/config.json ~/.continue/config.json
   ```

3. **Available Commands:**

   | Command | Description | Use Case |
   |---------|-------------|----------|
   | `/sec` | Full Security Review | Detailed analysis with fixes |
   | `/secfix` | Fix All Vulnerabilities | Get complete fixed code |
   | `/secquick` | Quick Summary | Fast vulnerability list |

4. **How to Use:**
   - Select code you want to review
   - Press `Ctrl+Shift+L` (or `Cmd+Shift+L` on Mac)
   - Type `/sec`, `/secfix`, or `/secquick`
   - Press Enter
   - Get instant security analysis!

---

## 📋 Detected Vulnerabilities

| Severity | Vulnerabilities |
|----------|----------------|
| 🔴 **CRITICAL** | SQL Injection, Command Injection, Code Injection, Insecure Deserialization |
| 🟠 **HIGH** | XSS, Path Traversal, Hardcoded Secrets, SSRF, XXE |
| 🟡 **MEDIUM** | Weak Cryptography, Missing Authentication, CSRF, Open Redirect |
| 🟢 **LOW** | Insecure Random, Missing Input Validation |

---

## ⚙️ Configuration

### Modelfile Parameters

Edit `ollama/Modelfile` to adjust:

```dockerfile
PARAMETER temperature 0.1      # Lower = more consistent results
PARAMETER num_ctx 3072         # Context window size
PARAMETER num_predict 1200     # Max output tokens
PARAMETER num_thread 8         # CPU threads (set to your core count)
# PARAMETER num_gpu 35         # Uncomment for GPU acceleration
```

### GPU Acceleration

If you have a GPU, enable it for 3-4x faster scanning:

```dockerfile
# In Modelfile, uncomment and adjust:
PARAMETER num_gpu 35  # Adjust based on your VRAM
```

| VRAM | Recommended Setting |
|------|---------------------|
| 4GB  | `num_gpu 20` |
| 6GB  | `num_gpu 28` |
| 8GB+ | `num_gpu 35` |

After editing, recreate the model:
```bash
ollama rm security-reviewer
ollama create security-reviewer -f Modelfile
```

---

## 📁 Project Structure

```
CodeGuard/
├── cli.py              # Main CLI scanner
├── agent.py            # Ollama API integration
├── parser.py           # Vulnerability detection & parsing
├── requirements.txt    # Python dependencies
├── ollama/
│   └── Modelfile       # Ollama model configuration
├── vscode-config/
│   └── config.json     # VS Code Continue extension config
└── test-files/         # Sample vulnerable files for testing
    ├── VulnController.cs
    ├── vuln_test.php
    └── vuln_test.go
```

---

## 🧪 Testing

Test the scanner with included vulnerable files:

```bash
# Scan test files
python cli.py test-files/

# Or scan individual file
python cli.py test-files/VulnController.cs
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Muhammad Zaid**

[![GitHub](https://img.shields.io/badge/GitHub-mzaidii-black?style=flat&logo=github)](https://github.com/mzaidii)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muhammad%20Zaid-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/muhammad-zaid-9650647b/)

---

## 🙏 Acknowledgments

- [Ollama](https://ollama.ai) - Local LLM runtime
- [Qwen2.5-Coder](https://huggingface.co/Qwen) - Base model for security analysis
- [Continue](https://continue.dev) - VS Code AI extension

---

<p align="center">
  <b>⭐ Star this repo if you find it useful! ⭐</b>
</p>
