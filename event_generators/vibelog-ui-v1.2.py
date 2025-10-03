#!/usr/bin/env python3
"""
Roarin Vibelog UI - A Flask web service for executing and parsing log scripts
"""

import os
import sys
import json
import subprocess
import re
import traceback
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import configparser

app = Flask(__name__)
CONFIG_FILE = 'vibelog_config.ini'

class ConfigManager:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            self.config.read(CONFIG_FILE)
        else:
            self.config['DEFAULT'] = {
                'output_directory': os.path.join(os.getcwd(), 'logs')
            }
            self.save_config()
    
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)
    
    def get_output_dir(self):
        return self.config.get('DEFAULT', 'output_directory')
    
    def set_output_dir(self, directory):
        self.config['DEFAULT']['output_directory'] = directory
        self.save_config()

config_manager = ConfigManager()

def detect_log_format(output):
    """Detect if log output is JSON or RAW format"""
    json_pattern = r'\{[^{}]*\}'
    json_matches = re.findall(json_pattern, output, re.MULTILINE | re.DOTALL)
    
    # If we find multiple JSON-like structures, it's likely JSON
    if len(json_matches) > 2:
        return 'JSON'
    return 'RAW'

def clean_raw_logs(output, product_name):
    """Clean RAW log format by removing headers and decorative elements"""
    lines = output.split('\n')
    cleaned_lines = []
    
    # Patterns to skip
    skip_patterns = [
        r'^=+$',  # Lines with only equals signs
        r'^-+$',  # Lines with only dashes
        rf'^.*Sample.*Events.*:?$',  # Sample events header
        rf'^Sample.*logs:?$',  # Generic "Sample <product> logs:" header
        r'^Traffic logs:?$',  # Traffic logs header
        r'^Threat logs:?$',  # Threat logs header
        r'^Traffic log:?$',  # Traffic log header
        r'^Threat log:?$',  # Threat log header
        r'^Event \d+:?$',  # Event markers
        r'^\s*$'  # Empty lines
    ]
    
    for line in lines:
        # Check if line matches any skip pattern
        should_skip = False
        for pattern in skip_patterns:
            if re.match(pattern, line.strip(), re.IGNORECASE):
                should_skip = True
                break
        
        if not should_skip and line.strip():
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def clean_json_logs(output):
    """Extract and format JSON structures from output"""
    # Find all JSON objects (including multiline)
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    json_objects = re.findall(json_pattern, output, re.MULTILINE | re.DOTALL)
    
    formatted_logs = []
    for json_str in json_objects:
        try:
            # Parse and re-serialize to ensure valid JSON
            parsed = json.loads(json_str)
            # Convert to single line JSON
            formatted_logs.append(json.dumps(parsed, separators=(',', ':')))
        except json.JSONDecodeError:
            # If parsing fails, try to clean up the string
            cleaned = ' '.join(json_str.split())
            formatted_logs.append(cleaned)
    
    return '\n'.join(formatted_logs)

def scan_scripts():
    """Scan subdirectories for Python scripts"""
    scripts = {}
    base_path = Path(os.getcwd())
    
    # Directories to exclude
    exclude_dirs = {'shared', 'logs', '__pycache__', '.git', 'venv', 'env'}
    
    # Get the directory where this web service script is located
    web_service_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    
    # Scan current directory and subdirectories
    for path in base_path.rglob('*.py'):
        # Skip the web service itself
        if path.name == os.path.basename(__file__):
            continue
        
        # Skip if the script is in the same directory as the web service
        if path.parent == web_service_dir:
            continue
        
        # Get relative path for categorization
        relative_path = path.relative_to(base_path)
        
        # Check if any part of the path is in excluded directories
        path_parts = set(relative_path.parts[:-1])  # Exclude the filename itself
        if path_parts.intersection(exclude_dirs):
            continue
        
        category = relative_path.parent.as_posix() if relative_path.parent.as_posix() != '.' else 'root'
        
        if category not in scripts:
            scripts[category] = []
        
        scripts[category].append({
            'name': path.stem,
            'path': str(path),
            'display_name': path.stem.replace('_', ' ').title()
        })
    
    return scripts

def ensure_output_directory(directory):
    """Ensure the output directory exists and is writable"""
    try:
        os.makedirs(directory, exist_ok=True)
        # Test write permissions
        test_file = os.path.join(directory, '.test_write')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True, "Directory is writable"
    except PermissionError:
        return False, "Permission denied: Cannot write to directory"
    except Exception as e:
        return False, f"Error: {str(e)}"

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Roarin Vibelog UI</title>
    <style>
        :root {
            --primary-purple: #7B2CBF;
            --light-purple: #9D4EDD;
            --lighter-purple: #C77DFF;
            --lightest-purple: #E0AAFF;
            --dark-purple: #5A189A;
            --bg-gradient-start: #240046;
            --bg-gradient-end: #3C096C;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            min-height: 100vh;
            color: #fff;
            display: flex;
            flex-direction: column;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            flex: 1;
        }

        header {
            text-align: center;
            margin-bottom: 3rem;
        }

        h1 {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--lighter-purple) 0%, var(--lightest-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 40px rgba(157, 78, 221, 0.5);
        }

        .subtitle {
            color: var(--lightest-purple);
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .glass-panel {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
        }

        .form-group { margin-bottom: 1.5rem; }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--lightest-purple);
            font-weight: 500;
            font-size: 1.1rem;
        }

        select, input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.1);
            border: 2px solid var(--light-purple);
            border-radius: 10px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        select:focus, input[type="text"]:focus {
            outline: none;
            border-color: var(--lighter-purple);
            box-shadow: 0 0 20px rgba(199, 125, 255, 0.5);
        }

        select option { background: var(--dark-purple); }

        .button-group {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
            flex-wrap: wrap;
        }

        button {
            padding: 0.75rem 2rem;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-purple) 0%, var(--light-purple) 100%);
            color: white;
            box-shadow: 0 4px 20px rgba(123, 44, 191, 0.5);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 30px rgba(123, 44, 191, 0.7);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--lightest-purple);
            border: 2px solid var(--light-purple);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-2px);
        }

        #output {
            background: rgba(0, 0, 0, 0.3);
            padding: 1.5rem;
            border-radius: 10px;
            margin-top: 1rem;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            white-space: pre-wrap;
        }

        .status-message {
            padding: 1rem;
            border-radius: 10px;
            margin-top: 1rem;
            text-align: center;
            font-weight: 500;
        }

        .success {
            background: rgba(39, 174, 96, 0.2);
            border: 2px solid #27ae60;
            color: #2ecc71;
        }

        .error {
            background: rgba(231, 76, 60, 0.2);
            border: 2px solid #e74c3c;
            color: #e74c3c;
        }

        .info {
            background: rgba(52, 152, 219, 0.2);
            border: 2px solid #3498db;
            color: #5dade2;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.3);
            /* Removed backdrop-filter: blur(5px); to keep background visible */
        }

        .modal-content {
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            margin: 10% auto;
            padding: 2rem;
            border: 2px solid var(--light-purple);
            border-radius: 20px;
            width: 80%;
            max-width: 500px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
        }

        .modal-header {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: var(--lightest-purple);
        }

        .modal-body {
            margin-bottom: 1.5rem;
        }

        .modal-footer {
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }

        footer {
            text-align: center;
            padding: 2rem;
            color: var(--lightest-purple);
            font-size: 1rem;
        }

        .heart {
            color: var(--lighter-purple);
            font-size: 1.2rem;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: var(--lighter-purple);
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        ::-webkit-scrollbar {
            width: 10px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
        }

        ::-webkit-scrollbar-thumb {
            background: var(--light-purple);
            border-radius: 5px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--lighter-purple);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Roarin Vibelog UI</h1>
            <div class="subtitle">Log Processing Control Panel</div>
        </header>
        
        <div class="glass-panel">
            <div class="form-group">
                <label for="scriptSelect">Select Script</label>
                <select id="scriptSelect">
                    <option value="">-- Select a script --</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="outputDir">Output Directory</label>
                <input type="text" id="outputDir" value="{{ output_dir }}" placeholder="/path/to/output/directory">
            </div>
            
            <div class="button-group">
                <button class="btn-primary" onclick="executeScript()">Execute Script</button>
                <button class="btn-secondary" onclick="updateOutputDir()">Update Output Directory</button>
            </div>
        </div>
        
        <div id="statusArea"></div>
        
        <div class="glass-panel" id="outputPanel" style="display: none;">
            <h3 style="color: var(--lightest-purple); margin-bottom: 1rem;">Script Output</h3>
            <div id="output"></div>
        </div>
    </div>
    
    <footer>
        Crafted with <span class="heart">💜</span> by RoarinPenguin
    </footer>
    
    <!-- Format Selection Modal -->
    <div id="formatModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">Log Format Detected</div>
            <div class="modal-body">
                <p id="detectedFormat"></p>
                <p>Please confirm or select the correct format:</p>
            </div>
            <div class="modal-footer">
                <button class="btn-primary" onclick="processLogs('JSON')">JSON Format</button>
                <button class="btn-primary" onclick="processLogs('RAW')">RAW Format</button>
                <button class="btn-secondary" onclick="closeModal()">Cancel</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentScriptOutput = '';
        let currentScriptName = '';
        
        // Load scripts on page load
        window.onload = function() {
            loadScripts();
        };
        
        function loadScripts() {
            fetch('/api/scripts')
                .then(response => response.json())
                .then(data => {
                    const select = document.getElementById('scriptSelect');
                    select.innerHTML = '<option value="">-- Select a script --</option>';
                    
                    for (const [category, scripts] of Object.entries(data)) {
                        const optgroup = document.createElement('optgroup');
                        optgroup.label = category === 'root' ? 'Root Directory' : category;
                        
                        scripts.forEach(script => {
                            const option = document.createElement('option');
                            option.value = script.path;
                            option.textContent = script.display_name;
                            option.dataset.name = script.name;
                            optgroup.appendChild(option);
                        });
                        
                        select.appendChild(optgroup);
                    }
                })
                .catch(error => showStatus('Error loading scripts: ' + error, 'error'));
        }
        
        function executeScript() {
            const select = document.getElementById('scriptSelect');
            const scriptPath = select.value;
            
            if (!scriptPath) {
                showStatus('Please select a script', 'error');
                return;
            }
            
            currentScriptName = select.options[select.selectedIndex].dataset.name;
            
            showStatus('Executing script... <span class="loading"></span>', 'info');
            
            fetch('/api/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({script_path: scriptPath})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentScriptOutput = data.output;
                    document.getElementById('output').textContent = data.output;
                    document.getElementById('outputPanel').style.display = 'block';
                    
                    // Show format detection modal
                    const modal = document.getElementById('formatModal');
                    document.getElementById('detectedFormat').textContent = 
                        `Detected format: ${data.detected_format}`;
                    modal.style.display = 'block';
                } else {
                    showStatus('Error: ' + data.error, 'error');
                }
            })
            .catch(error => showStatus('Error executing script: ' + error, 'error'));
        }
        
        function processLogs(format) {
            closeModal();
            showStatus('Processing logs as ' + format + ' format... <span class="loading"></span>', 'info');
            
            // Get the current output directory value from the input field
            const outputDir = document.getElementById('outputDir').value;
            
            fetch('/api/process', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    output: currentScriptOutput,
                    format: format,
                    script_name: currentScriptName,
                    output_dir: outputDir  // Include the current directory value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showStatus(data.message, 'success');
                } else {
                    showStatus('Error: ' + data.error, 'error');
                }
            })
            .catch(error => showStatus('Error processing logs: ' + error, 'error'));
        }
        
        function updateOutputDir() {
            const newDir = document.getElementById('outputDir').value;
            
            fetch('/api/update-output-dir', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({directory: newDir})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showStatus('Output directory updated successfully', 'success');
                } else {
                    showStatus('Error: ' + data.error, 'error');
                }
            })
            .catch(error => showStatus('Error updating directory: ' + error, 'error'));
        }
        
        function closeModal() {
            document.getElementById('formatModal').style.display = 'none';
        }
        
        function showStatus(message, type) {
            const statusArea = document.getElementById('statusArea');
            statusArea.innerHTML = `<div class="status-message ${type}">${message}</div>`;
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('formatModal');
            if (event.target == modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Render the main UI"""
    return render_template_string(HTML_TEMPLATE, output_dir=config_manager.get_output_dir())

@app.route('/api/scripts')
def api_scripts():
    """Return available scripts"""
    scripts = scan_scripts()
    return jsonify(scripts)

@app.route('/api/execute', methods=['POST'])
def api_execute():
    """Execute a script and return its output"""
    data = request.json
    script_path = data.get('script_path')
    
    if not script_path or not os.path.exists(script_path):
        return jsonify({'success': False, 'error': 'Invalid script path'})
    
    try:
        # Execute the script
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        # Detect format
        detected_format = detect_log_format(output)
        
        return jsonify({
            'success': True,
            'output': output,
            'detected_format': detected_format
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Script execution timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/process', methods=['POST'])
def api_process():
    """Process logs according to selected format"""
    data = request.json
    output = data.get('output', '')
    format_type = data.get('format', 'RAW')
    script_name = data.get('script_name', 'unknown')
    
    # Use the output directory from the request if provided, otherwise use config
    output_dir = data.get('output_dir', config_manager.get_output_dir())
    
    # Check directory permissions
    is_writable, message = ensure_output_directory(output_dir)
    if not is_writable:
        return jsonify({'success': False, 'error': message})
    
    try:
        if format_type == 'JSON':
            cleaned_output = clean_json_logs(output)
            filename = f"{script_name}-json.log"
        else:
            cleaned_output = clean_raw_logs(output, script_name)
            filename = f"{script_name}-raw.log"
        
        # Write to file
        output_path = os.path.join(output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_output)
        
        return jsonify({
            'success': True,
            'message': f'Logs processed and saved to {output_path}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update-output-dir', methods=['POST'])
def api_update_output_dir():
    """Update the output directory"""
    data = request.json
    new_dir = data.get('directory', '')
    
    if not new_dir:
        return jsonify({'success': False, 'error': 'Directory path cannot be empty'})
    
    # Check if directory is writable
    is_writable, message = ensure_output_directory(new_dir)
    if not is_writable:
        return jsonify({'success': False, 'error': message})
    
    # Save configuration
    config_manager.set_output_dir(new_dir)
    
    return jsonify({'success': True, 'message': 'Output directory updated'})

if __name__ == '__main__':
    # Ensure default output directory exists
    default_dir = config_manager.get_output_dir()
    ensure_output_directory(default_dir)
    
    print(f"Starting Roarin Vibelog UI...")
    print(f"Output directory: {default_dir}")
    print(f"Access the UI at: http://localhost:8000")
    
    app.run(debug=True, host='0.0.0.0', port=8000)
