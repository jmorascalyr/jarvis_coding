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
        # Define all default configuration options
        default_config = {
            'output_directory': os.path.join(os.getcwd(), 'logs'),
            'syslog_ip': '127.0.0.1',
            'syslog_port': '514',
            'syslog_protocol': 'UDP'
        }
        
        # 1. Load existing config or initialize defaults
        if os.path.exists(CONFIG_FILE):
            self.config.read(CONFIG_FILE)
            if 'DEFAULT' not in self.config:
                self.config['DEFAULT'] = {}
        else:
            self.config['DEFAULT'] = {}
        
        # 2. Check for and add any missing keys (migration/first run)
        config_changed = False
        for key, value in default_config.items():
            if key not in self.config['DEFAULT']:
                self.config['DEFAULT'][key] = value
                config_changed = True
        
        # 3. Save if a key was missing or if the file didn't exist
        if config_changed or not os.path.exists(CONFIG_FILE):
            self.save_config()
    
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)
    
    def get_output_dir(self):
        return self.config.get('DEFAULT', 'output_directory')
    
    def set_output_dir(self, directory):
        self.config['DEFAULT']['output_directory'] = directory
        self.save_config()

    def get_syslog_config(self):
        return {
            'ip': self.config.get('DEFAULT', 'syslog_ip'),
            'port': self.config.get('DEFAULT', 'syslog_port'),
            'protocol': self.config.get('DEFAULT', 'syslog_protocol')
        }

    def set_syslog_config(self, ip, port, protocol):
        self.config['DEFAULT']['syslog_ip'] = ip
        self.config['DEFAULT']['syslog_port'] = port
        self.config['DEFAULT']['syslog_protocol'] = protocol
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

def check_nc_availability():
    """Check if 'nc' (netcat) command is available"""
    try:
        subprocess.run(['nc', '-h'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

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

        select, input[type="text"], input[type="number"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.1);
            border: 2px solid var(--light-purple);
            border-radius: 10px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        select:focus, input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: var(--lighter-purple);
            box-shadow: 0 0 20px rgba(199, 125, 255, 0.5);
        }

        select option { background: var(--dark-purple); }
        
        .radio-group {
            display: flex;
            gap: 1.5rem;
            padding-top: 0.5rem;
        }
        
        .radio-group label {
            display: inline-flex;
            align-items: center;
            cursor: pointer;
            margin-bottom: 0;
            color: var(--lightest-purple);
            font-size: 1rem;
        }
        
        .radio-group input[type="radio"] {
            width: auto;
            margin-right: 0.5rem;
            appearance: none;
            background-color: rgba(255, 255, 255, 0.1);
            border: 2px solid var(--light-purple);
            border-radius: 50%;
            width: 16px;
            height: 16px;
            transition: all 0.2s ease;
        }
        
        .radio-group input[type="radio"]:checked {
            border-color: var(--lighter-purple);
            background-color: var(--lighter-purple);
            box-shadow: 0 0 10px rgba(199, 125, 255, 0.8);
        }

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
            background-color: rgba(0, 0, 0, 0.5);
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
            
            <h3 style="color: var(--lightest-purple); margin: 1rem 0;">Output Configuration</h3>

            <div class="form-group">
                <label for="outputTarget">Output Target</label>
                <div class="radio-group" id="outputTarget">
                    <label>
                        <input type="radio" name="output_target" value="local" checked>
                        Local File
                    </label>
                    <label>
                        <input type="radio" name="output_target" value="syslog">
                        Remote Syslog
                    </label>
                </div>
            </div>

            <div id="localFileConfig">
                <div class="form-group">
                    <label for="outputDir">Output Directory</label>
                    <input type="text" id="outputDir" value="{{ output_dir }}" placeholder="/path/to/output/directory">
                </div>
            </div>

            <div id="syslogConfig" style="display: none;">
                <div class="form-group">
                    <label for="syslogIP">Syslog IP Address</label>
                    <input type="text" id="syslogIP" value="{{ syslog_ip }}" placeholder="e.g., 192.168.1.1">
                </div>
                <div class="form-group">
                    <label for="syslogPort">Syslog Port</label>
                    <input type="number" id="syslogPort" value="{{ syslog_port }}" placeholder="e.g., 514">
                </div>
                <div class="form-group">
                    <label for="syslogProtocol">Syslog Protocol</label>
                    <div class="radio-group" id="syslogProtocol">
                        <label>
                            <input type="radio" name="syslog_protocol" value="UDP" {{ 'checked' if syslog_protocol == 'UDP' else '' }}>
                            UDP
                        </label>
                        <label>
                            <input type="radio" name="syslog_protocol" value="TCP" {{ 'checked' if syslog_protocol == 'TCP' else '' }}>
                            TCP
                        </label>
                    </div>
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn-primary" onclick="executeScript()">Execute Script</button>
                <button class="btn-secondary" onclick="updateOutputConfig()">Save Configuration</button>
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

    <div id="ncWarningModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">Warning: Netcat (nc) Not Found</div>
            <div class="modal-body">
                <p>The **Remote Syslog** option requires the `nc` (netcat) command to be installed and available in your system's PATH. Please install it to use this feature.</p>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" onclick="closeWarningModal()">Acknowledge</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentScriptOutput = '';
        let currentScriptName = '';
        let ncAvailable = {{ 'true' if nc_available else 'false' }};
        
        // Load scripts on page load
        window.onload = function() {
            loadScripts();
            setupOutputTargetToggle();
            checkNcWarning();
        };

        function checkNcWarning() {
            if (!ncAvailable) {
                document.getElementById('ncWarningModal').style.display = 'block';
            }
        }

        function closeWarningModal() {
            document.getElementById('ncWarningModal').style.display = 'none';
        }

        function setupOutputTargetToggle() {
            const radioButtons = document.querySelectorAll('input[name="output_target"]');
            const localConfig = document.getElementById('localFileConfig');
            const syslogConfig = document.getElementById('syslogConfig');
            
            radioButtons.forEach(radio => {
                radio.addEventListener('change', function() {
                    if (this.value === 'local') {
                        localConfig.style.display = 'block';
                        syslogConfig.style.display = 'none';
                    } else if (this.value === 'syslog') {
                        localConfig.style.display = 'none';
                        syslogConfig.style.display = 'block';
                    }
                });
            });

            // Initial state based on checked radio button (default to local)
            const initialTarget = document.querySelector('input[name="output_target"]:checked')?.value || 'local';
            if (initialTarget === 'local') {
                localConfig.style.display = 'block';
                syslogConfig.style.display = 'none';
            } else {
                localConfig.style.display = 'none';
                syslogConfig.style.display = 'block';
            }
        }
        
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
            const outputTarget = document.querySelector('input[name="output_target"]:checked').value;
            const outputDir = document.getElementById('outputDir').value;
            const syslogIP = document.getElementById('syslogIP').value;
            const syslogPort = document.getElementById('syslogPort').value;
            const syslogProtocol = document.querySelector('input[name="syslog_protocol"]:checked').value;
            
            if (outputTarget === 'syslog' && !ncAvailable) {
                showStatus('Error: Netcat (nc) command is not available for Syslog output.', 'error');
                return;
            }

            showStatus('Processing logs as ' + format + ' format to ' + outputTarget + '... <span class="loading"></span>', 'info');
            
            fetch('/api/process', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    output: currentScriptOutput,
                    format: format,
                    script_name: currentScriptName,
                    output_target: outputTarget,
                    output_dir: outputDir,
                    syslog_ip: syslogIP,
                    syslog_port: syslogPort,
                    syslog_protocol: syslogProtocol
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
        
        function updateOutputConfig() {
            const outputTarget = document.querySelector('input[name="output_target"]:checked').value;
            const newDir = document.getElementById('outputDir').value;
            const newSyslogIP = document.getElementById('syslogIP').value;
            const newSyslogPort = document.getElementById('syslogPort').value;
            const newSyslogProtocol = document.querySelector('input[name="syslog_protocol"]:checked').value;

            if (outputTarget === 'local' && !newDir) {
                showStatus('Error: Output directory cannot be empty', 'error');
                return;
            }

            if (outputTarget === 'syslog' && (!newSyslogIP || !newSyslogPort)) {
                showStatus('Error: Syslog IP and Port cannot be empty', 'error');
                return;
            }
            
            fetch('/api/update-output-config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    output_dir: newDir,
                    syslog_ip: newSyslogIP,
                    syslog_port: newSyslogPort,
                    syslog_protocol: newSyslogProtocol
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
            .catch(error => showStatus('Error updating configuration: ' + error, 'error'));
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
            const ncWarningModal = document.getElementById('ncWarningModal');
            if (event.target == modal) {
                closeModal();
            }
            if (event.target == ncWarningModal) {
                closeWarningModal();
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Render the main UI"""
    syslog_config = config_manager.get_syslog_config()
    return render_template_string(
        HTML_TEMPLATE, 
        output_dir=config_manager.get_output_dir(),
        syslog_ip=syslog_config['ip'],
        syslog_port=syslog_config['port'],
        syslog_protocol=syslog_config['protocol'],
        nc_available=check_nc_availability()
    )

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

def send_to_syslog(logs, ip, port, protocol):
    """Send cleaned logs to a remote syslog server using nc (netcat)"""
    if not check_nc_availability():
        return False, "Error: 'nc' (netcat) command is not available. Cannot send to syslog."

    if protocol.upper() == 'TCP':
        nc_command = ['nc', '-w', '3', ip, port]
    elif protocol.upper() == 'UDP':
        nc_command = ['nc', '-u', '-w', '3', ip, port]
    else:
        return False, f"Error: Unknown protocol '{protocol}'. Must be TCP or UDP."

    try:
        # Use subprocess.run with input to pipe the logs to nc
        result = subprocess.run(
            nc_command,
            input=logs,
            encoding='utf-8',
            capture_output=True,
            timeout=10  # Timeout for nc execution
        )

        if result.returncode == 0:
            return True, f"Logs successfully sent to syslog at {ip}:{port} ({protocol})."
        else:
            error_message = result.stderr or f"nc command failed with exit code {result.returncode}."
            return False, f"Syslog transmission failed: {error_message}"
    except FileNotFoundError:
        return False, "Error: 'nc' command is not available. Cannot send to syslog."
    except subprocess.TimeoutExpired:
        return False, f"Syslog transmission timed out to {ip}:{port}."
    except Exception as e:
        return False, f"Syslog transmission failed: {str(e)}"


@app.route('/api/process', methods=['POST'])
def api_process():
    """Process logs according to selected format and send to target"""
    data = request.json
    output = data.get('output', '')
    format_type = data.get('format', 'RAW')
    script_name = data.get('script_name', 'unknown')
    output_target = data.get('output_target', 'local')
    
    try:
        if format_type == 'JSON':
            cleaned_output = clean_json_logs(output)
            filename = f"{script_name}-json.log"
        else:
            cleaned_output = clean_raw_logs(output, script_name)
            filename = f"{script_name}-raw.log"
        
        if output_target == 'local':
            output_dir = data.get('output_dir', config_manager.get_output_dir())
            
            # Check directory permissions
            is_writable, message = ensure_output_directory(output_dir)
            if not is_writable:
                return jsonify({'success': False, 'error': message})
            
            # Write to file
            output_path = os.path.join(output_dir, filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(cleaned_output)
            
            return jsonify({
                'success': True,
                'message': f'Logs processed and saved to {output_path}'
            })

        elif output_target == 'syslog':
            syslog_ip = data.get('syslog_ip')
            syslog_port = data.get('syslog_port')
            syslog_protocol = data.get('syslog_protocol')
            
            if not syslog_ip or not syslog_port or not syslog_protocol:
                 return jsonify({'success': False, 'error': 'Syslog configuration is incomplete.'})

            success, message = send_to_syslog(cleaned_output, syslog_ip, syslog_port, syslog_protocol)

            return jsonify({'success': success, 'message': message} if success else {'success': False, 'error': message})
            
        else:
            return jsonify({'success': False, 'error': f'Unknown output target: {output_target}'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update-output-config', methods=['POST'])
def api_update_output_config():
    """Update the output directory and syslog configuration"""
    data = request.json
    new_dir = data.get('output_dir')
    new_syslog_ip = data.get('syslog_ip')
    new_syslog_port = data.get('syslog_port')
    new_syslog_protocol = data.get('syslog_protocol')
    
    messages = []
    errors = []

    # Update local output directory
    if new_dir:
        is_writable, message = ensure_output_directory(new_dir)
        if is_writable:
            config_manager.set_output_dir(new_dir)
            messages.append('Output directory updated successfully.')
        else:
            errors.append(f'Output directory error: {message}')
    
    # Update syslog configuration
    if new_syslog_ip and new_syslog_port and new_syslog_protocol:
        config_manager.set_syslog_config(new_syslog_ip, new_syslog_port, new_syslog_protocol)
        messages.append('Syslog configuration updated successfully.')
    
    if errors:
        return jsonify({'success': False, 'error': '; '.join(errors)})
    
    if not messages:
        # A successful no-op for when the user clicks 'Save' but hasn't changed anything relevant.
        return jsonify({'success': True, 'message': 'Configuration settings saved.'})

    return jsonify({'success': True, 'message': '; '.join(messages)})


if __name__ == '__main__':
    # Ensure default output directory exists
    default_dir = config_manager.get_output_dir()
    ensure_output_directory(default_dir)
    
    print(f"Starting Roarin Vibelog UI...")
    print(f"Output directory: {default_dir}")
    print(f"Access the UI at: http://localhost:8000")
    
    app.run(debug=True, host='0.0.0.0', port=8000)