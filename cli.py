#!/usr/bin/env python3
import sys
import os
import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from agent import review_code

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.jsx': 'React JSX',
    '.tsx': 'React TSX',
    '.cs': 'C#',
    '.java': 'Java',
    '.php': 'PHP',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.cpp': 'C++',
    '.c': 'C',
    '.h': 'C/C++ Header',
    '.hpp': 'C++ Header',
    '.kt': 'Kotlin',
    '.swift': 'Swift',
    '.rs': 'Rust',
}

# Directories to skip
SKIP_DIRS = {
    'node_modules', 'vendor', 'bin', 'obj', 'debug', 'release',
    '.git', '.svn', '.hg', '__pycache__', 'venv', 'env',
    'packages', 'dist', 'build', 'target', '.idea', '.vscode'
}


def find_code_files(directory):
    """Find all code files in directory."""
    code_files = {}
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                filepath = os.path.join(root, file)
                lang = SUPPORTED_EXTENSIONS[ext]
                
                if lang not in code_files:
                    code_files[lang] = []
                code_files[lang].append(filepath)
    
    return code_files


def display_project_summary(code_files, directory):
    """Display summary of code files found."""
    print("\n" + "═" * 60)
    print("                 PROJECT SCANNER")
    print("═" * 60)
    print(f"  📁 Directory: {directory}")
    print("─" * 60)
    print("  📊 Files Found:")
    print()
    
    total = 0
    for lang, files in sorted(code_files.items()):
        count = len(files)
        total += count
        print(f"     • {lang:.<20} {count:>3} files")
    
    print("     " + "─" * 25)
    print(f"     📌 Total: {total:>14} files")
    print("═" * 60)
    
    return total


def get_user_choice(code_files):
    """Get user's scanning choice."""
    print("\n  Select an option:")
    print("  ─────────────────────────────────────")
    print("  [1] Scan ALL files")
    print("  [2] Scan specific file (enter filename)")
    print("  [3] Scan specific language only")
    print("  [q] Quit")
    print()
    
    choice = input("  Enter choice (1/2/3/q): ").strip().lower()
    return choice


def search_file(code_files, filename):
    """Search for a file by name."""
    filename_lower = filename.lower()
    matches = []
    
    for lang, files in code_files.items():
        for filepath in files:
            if filename_lower in os.path.basename(filepath).lower():
                matches.append(filepath)
    
    return matches


def select_language(code_files):
    """Let user select a language to scan."""
    languages = list(code_files.keys())
    
    print("\n  Select language:")
    print("  ─────────────────────────────────────")
    for i, lang in enumerate(languages, 1):
        count = len(code_files[lang])
        print(f"  [{i}] {lang} ({count} files)")
    
    print()
    choice = input("  Enter number: ").strip()
    
    try:
        index = int(choice) - 1
        if 0 <= index < len(languages):
            return languages[index]
    except ValueError:
        pass
    
    return None


def read_file(filepath):
    """Read file contents."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"  ❌ Error reading {filepath}: {e}")
        return None


def print_progress_status(current, total, filename, elapsed=0):
    """Print progress status with elapsed time."""
    if len(filename) > 30:
        filename = filename[:27] + "..."
    
    sys.stdout.write(f"\r  🔍 [{current}/{total}] Scanning: {filename:<30} | ⏱️ {elapsed:>3.0f}s elapsed...")
    sys.stdout.flush()


def scan_file_with_progress(filepath, current, total):
    """Scan a single file with progress indication and elapsed time."""
    filename = os.path.basename(filepath)
    start_time = time.time()
    
    # Start progress display
    print_progress_status(current + 1, total, filename, 0)
    
    code = read_file(filepath)
    if code is None:
        return None
    
    # Use threading to show elapsed time while scanning
    import threading
    stop_timer = threading.Event()
    
    def update_elapsed():
        while not stop_timer.is_set():
            elapsed = time.time() - start_time
            print_progress_status(current + 1, total, filename, elapsed)
            time.sleep(1)
    
    timer_thread = threading.Thread(target=update_elapsed)
    timer_thread.start()
    
    try:
        result = review_code(code, show_progress=False)
        result['filepath'] = filepath
    finally:
        stop_timer.set()
        timer_thread.join()
    
    # Show completion
    elapsed = time.time() - start_time
    sys.stdout.write(f"\r  ✅ [{current + 1}/{total}] Completed: {filename:<30} | ⏱️ {elapsed:>3.0f}s          \n")
    sys.stdout.flush()
    
    return result


def generate_html_report(results, output_path):
    """Generate HTML report from scan results."""
    
    # Collect all findings with file info
    all_findings = []
    for result in results:
        filepath = result.get('filepath', 'Unknown')
        filename = os.path.basename(filepath)
        for finding in result.get('findings', []):
            finding_copy = finding.copy()
            finding_copy['filename'] = filename
            finding_copy['filepath'] = filepath
            all_findings.append(finding_copy)
    
    # Sort findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
    
    # Count totals
    total_files = len(results)
    total_vulns = len(all_findings)
    critical_count = sum(1 for f in all_findings if f.get('severity') == 'CRITICAL')
    high_count = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
    medium_count = sum(1 for f in all_findings if f.get('severity') == 'MEDIUM')
    low_count = sum(1 for f in all_findings if f.get('severity') == 'LOW')
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ CodeGuard - Security Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .header .date {{
            color: #888;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: rgba(255,255,255,0.05);
            padding: 20px 15px;
            border-radius: 10px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.2em;
            font-weight: bold;
        }}
        .summary-card .label {{
            color: #888;
            margin-top: 5px;
            font-size: 0.9em;
        }}
        .summary-card.critical .number {{ color: #ff4757; }}
        .summary-card.high .number {{ color: #ffa502; }}
        .summary-card.medium .number {{ color: #fffa65; }}
        .summary-card.low .number {{ color: #7bed9f; }}
        .summary-card.total .number {{ color: #70a1ff; }}
        .summary-card.files .number {{ color: #a29bfe; }}
        
        .issues-summary {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
        }}
        .issues-summary h2 {{
            margin-bottom: 20px;
            color: #70a1ff;
            font-size: 1.4em;
        }}
        .issue-list {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        .issue-item {{
            display: flex;
            align-items: center;
            padding: 12px 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            border-left: 4px solid;
            text-decoration: none;
            color: inherit;
        }}
        .issue-item:hover {{
            background: rgba(0,0,0,0.4);
            transform: translateX(5px);
        }}
        .issue-item.critical {{ border-color: #ff4757; }}
        .issue-item.high {{ border-color: #ffa502; }}
        .issue-item.medium {{ border-color: #fffa65; }}
        .issue-item.low {{ border-color: #7bed9f; }}
        .issue-severity {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: bold;
            margin-right: 15px;
            min-width: 70px;
            text-align: center;
        }}
        .issue-severity.critical {{ background: #ff4757; color: white; }}
        .issue-severity.high {{ background: #ffa502; color: white; }}
        .issue-severity.medium {{ background: #fffa65; color: black; }}
        .issue-severity.low {{ background: #7bed9f; color: black; }}
        .issue-name {{
            font-weight: 600;
            flex: 1;
        }}
        .issue-location {{
            color: #888;
            font-size: 0.9em;
        }}
        
        .findings-section {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
        }}
        .findings-section h2 {{
            margin-bottom: 20px;
            color: #70a1ff;
            font-size: 1.4em;
        }}
        .finding-detail {{
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid;
            scroll-margin-top: 20px;
        }}
        .finding-detail.critical {{ border-color: #ff4757; }}
        .finding-detail.high {{ border-color: #ffa502; }}
        .finding-detail.medium {{ border-color: #fffa65; }}
        .finding-detail.low {{ border-color: #7bed9f; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }}
        .finding-meta span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .finding-meta .label {{
            color: #888;
        }}
        .code-block {{
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        .code-block pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .code-block.vulnerable {{
            border: 1px solid #ff4757;
        }}
        .code-block.fixed {{
            border: 1px solid #7bed9f;
        }}
        .code-label {{
            font-size: 0.9em;
            font-weight: 600;
            margin-bottom: 5px;
            margin-top: 15px;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .code-label.vulnerable {{ color: #ff4757; }}
        .code-label.fixed {{ color: #7bed9f; }}
        .explanation {{
            background: rgba(112, 161, 255, 0.1);
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
            border-left: 3px solid #70a1ff;
        }}
        .explanation-title {{
            font-weight: 600;
            color: #70a1ff;
            margin-bottom: 8px;
        }}
        .explanation p {{
            line-height: 1.6;
        }}
        
        .files-section {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
        }}
        .files-section h2 {{
            margin-bottom: 20px;
            color: #70a1ff;
            font-size: 1.4em;
        }}
        .file-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            margin-bottom: 10px;
        }}
        .file-name {{
            font-weight: 500;
        }}
        .file-stats {{
            display: flex;
            gap: 10px;
        }}
        .file-stat {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        .file-stat.critical {{ background: rgba(255,71,87,0.3); color: #ff4757; }}
        .file-stat.high {{ background: rgba(255,165,2,0.3); color: #ffa502; }}
        .file-stat.medium {{ background: rgba(255,250,101,0.3); color: #fffa65; }}
        .file-stat.low {{ background: rgba(123,237,159,0.3); color: #7bed9f; }}
        .file-stat.clean {{ background: rgba(123,237,159,0.3); color: #7bed9f; }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 30px;
        }}
        
        .back-to-top {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #70a1ff;
            color: white;
            border: none;
            padding: 12px 15px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 1.2em;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            transition: all 0.2s ease;
        }}
        .back-to-top:hover {{
            background: #5a8dee;
            transform: translateY(-3px);
        }}
        
        .no-details {{
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 15px;
            margin-top: 10px;
            color: #888;
            font-style: italic;
        }}
        
        @media (max-width: 768px) {{
            .finding-header {{
                flex-direction: column;
            }}
            .issue-item {{
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }}
            .issue-severity {{
                margin-right: 0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CodeGuard - Security Scan Report</h1>
            <p class="date">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card files">
                <div class="number">{total_files}</div>
                <div class="label">Files Scanned</div>
            </div>
            <div class="summary-card total">
                <div class="number">{total_vulns}</div>
                <div class="label">Total Issues</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{critical_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{high_count}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{medium_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{low_count}</div>
                <div class="label">Low</div>
            </div>
        </div>
'''
    # Files Scanned Section
    html += '''
        <div class="files-section">
            <h2>📁 Files Scanned</h2>
'''
    
    for result in results:
        filepath = result.get('filepath', 'Unknown')
        filename = os.path.basename(filepath)
        findings = result.get('findings', [])
        language = result.get('language_detected', 'Unknown')
        scan_time = result.get('scan_time', 0)
        
        file_critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        file_high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        file_medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        file_low = sum(1 for f in findings if f.get('severity') == 'LOW')
        
        html += f'''
            <div class="file-item">
                <div>
                    <span class="file-name">📄 {filename}</span>
                    <span style="color:#888; margin-left:10px;">({language} • {scan_time:.1f}s)</span>
                </div>
                <div class="file-stats">
'''
        
        if len(findings) == 0:
            html += '                    <span class="file-stat clean">✅ Clean</span>\n'
        else:
            if file_critical > 0:
                html += f'                    <span class="file-stat critical">🔴 {file_critical}</span>\n'
            if file_high > 0:
                html += f'                    <span class="file-stat high">🟠 {file_high}</span>\n'
            if file_medium > 0:
                html += f'                    <span class="file-stat medium">🟡 {file_medium}</span>\n'
            if file_low > 0:
                html += f'                    <span class="file-stat low">🟢 {file_low}</span>\n'
        
        
        html += '''                </div>
            </div>
'''

    # Close files-section div
    html += '''
        </div>
'''
    
    # Issues Summary (Clickable)
    if all_findings:
        html += '''
        <div class="issues-summary">
            <h2>📋 Issues Summary (Click to View Details)</h2>
            <div class="issue-list">
'''
        
        for i, finding in enumerate(all_findings):
            vuln_name = finding.get('vulnerability', 'Unknown')
            severity = finding.get('severity', 'MEDIUM').lower()
            filename = finding.get('filename', 'Unknown')
            lines = finding.get('vulnerable_lines', [])
            line_nums = ', '.join([str(l.get('line_number', '?')) for l in lines[:3]])
            location = f"{filename}" + (f" (Lines: {line_nums})" if line_nums else "")
            
            html += f'''
                <a href="#finding-{i}" class="issue-item {severity}">
                    <span class="issue-severity {severity}">{severity.upper()}</span>
                    <span class="issue-name">{vuln_name}</span>
                    <span class="issue-location">📍 {location}</span>
                </a>
'''
        
        html += '''
            </div>
        </div>
'''
    
    # Detailed Findings
    if all_findings:
        html += '''
        <div class="findings-section">
            <h2>🔍 Detailed Findings</h2>
'''
        
        for i, finding in enumerate(all_findings):
            vuln_name = finding.get('vulnerability', 'Unknown')
            severity = finding.get('severity', 'MEDIUM').lower()
            filename = finding.get('filename', 'Unknown')
            filepath = finding.get('filepath', 'Unknown')
            lines = finding.get('vulnerable_lines', [])
            fixed_code = finding.get('fixed_code', '')
            explanation = finding.get('explanation', '')
            
            html += f'''
            <div id="finding-{i}" class="finding-detail {severity}">
                <div class="finding-header">
                    <span class="finding-title">{vuln_name}</span>
                    <span class="issue-severity {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-meta">
                    <span><span class="label">📁 File:</span> {filename}</span>
                    <span><span class="label">📍 Path:</span> {filepath}</span>
                </div>
'''
            
            # Vulnerable Lines from code
            if lines:
                html += '''
                <div class="code-label vulnerable">❌ Vulnerable Code:</div>
                <div class="code-block vulnerable">
'''
                for line_info in lines[:5]:
                    line_num = line_info.get('line_number', '?')
                    code = line_info.get('code', '').replace('<', '&lt;').replace('>', '&gt;')
                    html += f'<span style="color:#888;">Line {line_num}:</span> {code}\n'
                
                html += '</div>\n'
            
            # Fixed code
            if fixed_code:
                escaped_fixed = fixed_code.replace('<', '&lt;').replace('>', '&gt;')
                html += f'''
                <div class="code-label fixed">✅ Recommended Fix:</div>
                <div class="code-block fixed"><pre>{escaped_fixed}</pre></div>
'''
            
            # Explanation
            if explanation:
                html += f'''
                <div class="explanation">
                    <div class="explanation-title">💡 Why This is a Vulnerability:</div>
                    <p>{explanation}</p>
                </div>
'''
            
            # If no details available
            if not lines and not fixed_code and not explanation:
                html += '''
                <div class="no-details">
                    <p>ℹ️ Detailed code analysis not available. Please review the source file manually.</p>
                </div>
'''
            
            html += '''
            </div>
'''
        
        html += '''
        </div>
'''
    else:
        html += '''
        <div class="findings-section">
            <h2>🔍 Scan Results</h2>
            <div style="text-align: center; padding: 40px; color: #7bed9f;">
                <div style="font-size: 4em; margin-bottom: 20px;">✅</div>
                <div style="font-size: 1.5em; font-weight: bold;">No Security Vulnerabilities Detected!</div>
                <p style="color: #888; margin-top: 10px;">All scanned files passed the security checks.</p>
            </div>
        </div>
'''
    
 
    
    html += '''
        <div class="footer">
            <p><strong>CodeGuard</strong> - AI-Powered Security Code Scanner</p>
            <p style="margin-top: 10px;">
                <a href="https://github.com/mzaidii" target="_blank" style="color: #70a1ff; text-decoration: none; margin-right: 20px;">
                    <svg style="width:16px;height:16px;vertical-align:middle;margin-right:5px;" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                    GitHub
                </a>
                <a href="https://www.linkedin.com/in/muhammad-zaid-9650647b/" target="_blank" style="color: #70a1ff; text-decoration: none;">
                    <svg style="width:16px;height:16px;vertical-align:middle;margin-right:5px;" viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
                    LinkedIn
                </a>
            </p>
            <p style="margin-top: 10px; font-size: 0.85em;">Powered by Ollama + Qwen2.5-Coder</p>
        </div>
    </div>
    
    <button class="back-to-top" onclick="window.scrollTo({top: 0, behavior: 'smooth'})">⬆</button>
    
    <script>
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    target.style.boxShadow = '0 0 20px rgba(112, 161, 255, 0.5)';
                    setTimeout(() => {
                        target.style.boxShadow = '';
                    }, 2000);
                }
            });
        });
    </script>
</body>
</html>
'''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_path


def scan_project(directory):
    """Scan entire project directory."""
    
    code_files = find_code_files(directory)
    
    if not code_files:
        print("\n  ❌ No code files found in this directory!")
        return
    
    total = display_project_summary(code_files, directory)
    choice = get_user_choice(code_files)
    
    files_to_scan = []
    
    if choice == '1':
        for lang, files in code_files.items():
            files_to_scan.extend(files)
        print(f"\n  📊 Preparing to scan {len(files_to_scan)} files...")
        
    elif choice == '2':
        filename = input("\n  Enter filename to search: ").strip()
        if not filename:
            print("  ❌ No filename entered!")
            return
        
        matches = search_file(code_files, filename)
        
        if not matches:
            print(f"  ❌ No files found matching '{filename}'")
            return
        elif len(matches) == 1:
            files_to_scan = matches
            print(f"  ✅ Found: {matches[0]}")
        else:
            print(f"\n  📁 Found {len(matches)} matching files:")
            for i, match in enumerate(matches, 1):
                print(f"  [{i}] {match}")
            
            selection = input("\n  Enter number (or 'a' for all): ").strip().lower()
            
            if selection == 'a':
                files_to_scan = matches
            else:
                try:
                    index = int(selection) - 1
                    if 0 <= index < len(matches):
                        files_to_scan = [matches[index]]
                    else:
                        print("  ❌ Invalid selection!")
                        return
                except ValueError:
                    print("  ❌ Invalid input!")
                    return
        
    elif choice == '3':
        lang = select_language(code_files)
        if lang:
            files_to_scan = code_files[lang]
            print(f"\n  📊 Preparing to scan {len(files_to_scan)} {lang} files...")
        else:
            print("  ❌ Invalid language selection!")
            return
        
    elif choice == 'q':
        print("\n  👋 Goodbye!")
        return
    else:
        print("  ❌ Invalid choice!")
        return
    
    if not files_to_scan:
        print("  ❌ No files to scan!")
        return
    
    # Scan files with progress bar
    results = []
    total_files = len(files_to_scan)
    start_time = time.time()
    
    print("\n" + "═" * 60)
    print("                 SCANNING IN PROGRESS")
    print("═" * 60)
    print()
    
    for i, filepath in enumerate(files_to_scan):
        result = scan_file_with_progress(filepath, i, total_files)
        
        if result:
            results.append(result)
    
    # Show total time
    elapsed = time.time() - start_time
    print(f"\n  ⏱️  Total Time: {elapsed:.1f} seconds")
    
    # Show quick summary
    print("\n" + "─" * 60)
    total_vulns = sum(len(r.get('findings', [])) for r in results)
    critical = sum(1 for r in results for f in r.get('findings', []) if f.get('severity') == 'CRITICAL')
    high = sum(1 for r in results for f in r.get('findings', []) if f.get('severity') == 'HIGH')
    medium = sum(1 for r in results for f in r.get('findings', []) if f.get('severity') == 'MEDIUM')
    low = sum(1 for r in results for f in r.get('findings', []) if f.get('severity') == 'LOW')
    
    print(f"  📊 Quick Summary: {total_vulns} vulnerabilities found")
    print(f"     🔴 Critical: {critical}  🟠 High: {high}  🟡 Medium: {medium}  🟢 Low: {low}")
    
    # Generate HTML report
    print("\n" + "═" * 60)
    print("                 GENERATING REPORT")
    print("═" * 60)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"security_report_{timestamp}.html"
    report_path = os.path.join(directory, report_name)
    
    generate_html_report(results, report_path)
    
    print(f"\n  ✅ Report generated: {report_name}")
    
    # Open report in browser
    print("  🌐 Opening report in browser...")
    import webbrowser
    webbrowser.open(f'file://{os.path.abspath(report_path)}')
    
    print("\n" + "═" * 60)
    print("                 SCAN COMPLETE")
    print("═" * 60)
    print(f"\n  📁 Files Scanned:   {len(results)}")
    print(f"  🔍 Vulnerabilities: {total_vulns}")
    print(f"  ⏱️  Total Time:      {elapsed:.1f}s")
    print(f"  📄 Report:          {report_name}")
    print("\n" + "═" * 60)


def filter_findings(findings):
    """Filter out findings with no vulnerable lines identified."""
    return [f for f in findings if f.get('vulnerable_lines') and len(f['vulnerable_lines']) > 0]


def print_report(result, filepath="", show_all=False, show_details=True):
    """Print formatted security report for single file."""
    
    print("\n" + "═" * 60)
    print("                CodeGuard - SECURITY SCAN REPORT")
    print("═" * 60)
    
    if filepath:
        print(f"  📁 File:         {filepath}")
    
    if result.get("error"):
        print(f"  ❌ ERROR: {result['error']}")
        print("═" * 60)
        return
    
    print(f"  🔤 Language:     {result.get('language_detected', 'Unknown')}")
    print(f"  ⏱️  Scan Time:    {result.get('scan_time', 0):.1f}s")
    
    all_findings = result.get('findings', [])
    
    if show_all:
        findings = all_findings
    else:
        findings = filter_findings(all_findings)
    
    has_vulns = len(findings) > 0
    
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')
    
    print(f"\n  📊 RESULTS:")
    print(f"     Vulnerabilities: {'YES ⚠️' if has_vulns else 'NO ✅'}")
    print(f"     Total Findings:  {len(findings)}")
    
    if has_vulns:
        print(f"\n     🔴 Critical: {critical}  🟠 High: {high}  🟡 Medium: {medium}  🟢 Low: {low}")
    
    if len(all_findings) > len(findings):
        hidden = len(all_findings) - len(findings)
        print(f"\n     ℹ️  {hidden} additional findings hidden (no specific lines)")
        print(f"        Use --all flag to show all findings")
    
    print("\n" + "═" * 60)
    
    if not has_vulns:
        print("\n  ✅ No security vulnerabilities detected!")
        print("\n" + "═" * 60)
        return
    
    print("\n  📋 FINDINGS SUMMARY")
    print("  " + "-" * 56)
    
    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'UNKNOWN')
        vuln_name = finding.get('vulnerability', 'Unknown')
        
        if severity == "CRITICAL":
            indicator = "🔴"
        elif severity == "HIGH":
            indicator = "🟠"
        elif severity == "MEDIUM":
            indicator = "🟡"
        else:
            indicator = "🟢"
        
        print(f"\n  {indicator} #{i}: {vuln_name} [{severity}]")
        
        vulnerable_lines = finding.get('vulnerable_lines', [])
        if vulnerable_lines:
            for line_info in vulnerable_lines[:3]:
                line_num = line_info.get('line_number', '?')
                code = line_info.get('code', '')
                if len(code) > 50:
                    code = code[:47] + "..."
                print(f"      Line {line_num}: {code}")
    
    print("\n" + "═" * 60)
    
    if show_details:
        raw_response = result.get('raw_response', '')
        if raw_response:
            print("\n  📝 DETAILED ANALYSIS")
            print("═" * 60)
            print(raw_response)
            print("\n" + "═" * 60)


def print_summary(result, filepath=""):
    """Print compact summary for single file."""
    
    print("\n" + "═" * 60)
    print("                 SECURITY SCAN SUMMARY")
    print("═" * 60)
    
    if filepath:
        print(f"  📁 File:         {filepath}")
    
    if result.get("error"):
        print(f"  ❌ ERROR: {result['error']}")
        print("═" * 60)
        return
    
    print(f"  🔤 Language:     {result.get('language_detected', 'Unknown')}")
    print(f"  ⏱️  Scan Time:    {result.get('scan_time', 0):.1f}s")
    
    all_findings = result.get('findings', [])
    findings = filter_findings(all_findings)
    
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')
    
    print(f"\n  📊 SEVERITY BREAKDOWN")
    print("  " + "-" * 56)
    print(f"     🔴 Critical:  {critical}")
    print(f"     🟠 High:      {high}")
    print(f"     🟡 Medium:    {medium}")
    print(f"     🟢 Low:       {low}")
    print(f"     ─────────────────")
    print(f"     📌 Total:     {len(findings)}")
    
    if findings:
        print("\n  📋 VULNERABILITIES FOUND")
        print("  " + "-" * 56)
        
        for finding in findings:
            severity = finding.get('severity', '?')
            vuln_name = finding.get('vulnerability', 'Unknown')
            lines = finding.get('vulnerable_lines', [])
            line_nums = [str(l.get('line_number', '?')) for l in lines[:3]]
            
            if severity == "CRITICAL":
                icon = "🔴"
            elif severity == "HIGH":
                icon = "🟠"
            elif severity == "MEDIUM":
                icon = "🟡"
            else:
                icon = "🟢"
            
            line_str = f"(Lines: {', '.join(line_nums)})" if line_nums else ""
            print(f"     {icon} {vuln_name} {line_str}")
    
    print("\n" + "═" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="AI Security Code Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py                         # Interactive project scan
  python cli.py .                       # Scan current directory
  python cli.py /path/to/project        # Scan specific project
  python cli.py app.py                  # Scan single file
  python cli.py app.py --summary        # Quick summary
  python cli.py app.py --json           # JSON output
        """
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--summary", action="store_true", help="Show compact summary")
    parser.add_argument("--all", action="store_true", help="Show all findings")
    parser.add_argument("--no-details", action="store_true", help="Hide detailed analysis")
    
    args = parser.parse_args()
    path = args.path
    
    if os.path.isdir(path):
        scan_project(os.path.abspath(path))
    elif os.path.isfile(path):
        print(f"Scanning: {path}")
        
        code = read_file(path)
        if code is None:
            sys.exit(1)
        
        result = review_code(code)
        
        if args.json:
            if not args.all:
                result['findings'] = filter_findings(result.get('findings', []))
            output = {k: v for k, v in result.items() if k != 'raw_response'}
            print(json.dumps(output, indent=2))
        elif args.summary:
            print_summary(result, path)
        else:
            print_report(result, path, show_all=args.all, show_details=not args.no_details)
    else:
        print(f"❌ Path not found: {path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
