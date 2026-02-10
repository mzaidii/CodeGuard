import requests
import json
import sys
import time
from parser import parse_llm_response, detect_language

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "codeguard"
TIMEOUT = 300

LANG_LABELS = {
    "go": "Go",
    "php": "PHP",
    "csharp": "C#",
    "python": "Python",
    "java": "Java",
    "javascript": "JavaScript",
    "cpp": "C++",
    "unknown": "Unknown",
}


def print_progress_bar(current, total, elapsed, bar_length=40):
    """Print a progress bar with elapsed time."""
    percent = min(current / total, 1.0) if total > 0 else 0
    filled = int(bar_length * percent)
    bar = "\u2588" * filled + "\u2591" * (bar_length - filled)
    sys.stdout.write(f"\r\U0001f50d Scanning: [{bar}] {percent*100:.1f}% ({elapsed:.1f}s)")
    sys.stdout.flush()


def review_code(code, filename="", show_progress=True):
    """Send code to Ollama for security review."""

    # Detect language before sending to LLM
    language = detect_language(code)
    lang_label = LANG_LABELS.get(language, "Unknown")

    # Build a language-aware prompt
    prompt = f"""Review this {lang_label} code for security vulnerabilities.

For each vulnerability found, provide:
1. The vulnerability name and severity (CRITICAL/HIGH/MEDIUM/LOW)
2. The exact vulnerable code snippet
3. A working {lang_label} fix (not another language)
4. Why the fix prevents the attack

Code to review:

```{language}
{code}
```"""

    # Better token estimation based on code size
    code_lines = len(code.split('\n'))
    estimated_tokens = max(code_lines * 100, 500)

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True
    }

    try:
        start_time = time.time()
        response = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT, stream=True)
        response.raise_for_status()

        raw_response = ""
        tokens_received = 0

        for line in response.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    raw_response += token
                    tokens_received += 1

                    elapsed = time.time() - start_time

                    if show_progress and tokens_received % 5 == 0:
                        print_progress_bar(tokens_received, estimated_tokens, elapsed)

                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue

        elapsed = time.time() - start_time

        if show_progress:
            filled_bar = "\u2588" * 40
            sys.stdout.write(f"\r\U0001f50d Scanning: [{filled_bar}] 100.0% \u2705 Complete ({elapsed:.1f}s)\n")
            sys.stdout.flush()

        # Check if we got a response
        if not raw_response.strip():
            return {
                "error": "Empty response from model",
                "has_vulnerabilities": False,
                "findings": [],
                "raw_response": ""
            }

        # Parse the response
        result = parse_llm_response(raw_response, code)
        result["scan_time"] = elapsed
        result["tokens"] = tokens_received
        return result

    except requests.exceptions.Timeout:
        if show_progress:
            print("\n")
        return {
            "error": f"Model timed out after {TIMEOUT} seconds.",
            "has_vulnerabilities": False,
            "findings": [],
            "raw_response": ""
        }
    except requests.exceptions.ConnectionError:
        if show_progress:
            print("\n")
        return {
            "error": "Cannot connect to Ollama. Run 'ollama serve' first.",
            "has_vulnerabilities": False,
            "findings": [],
            "raw_response": ""
        }
    except Exception as e:
        if show_progress:
            print("\n")
        return {
            "error": f"Error: {str(e)}",
            "has_vulnerabilities": False,
            "findings": [],
            "raw_response": ""
        }


if __name__ == "__main__":
    # Quick test
    test_code = """
password = 'admin123'
eval(user_input)
"""
    print("Testing agent...")
    result = review_code(test_code)
    print(f"\nFindings: {len(result.get('findings', []))}")
    print(f"Has vulnerabilities: {result.get('has_vulnerabilities')}")
    if result.get('error'):
        print(f"Error: {result['error']}")
    print(f"\nRaw response preview:\n{result.get('raw_response', '')[:500]}")
