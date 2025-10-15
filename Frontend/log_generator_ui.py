import time
import os
import subprocess
import json
import socket
import requests
from flask import Flask, request, Response, stream_with_context, jsonify, render_template
try:
    import keyring  # type: ignore
    HAS_KEYRING = True
except Exception:
    HAS_KEYRING = False

app = Flask(__name__)

EVENT_GENERATORS_DIR = os.path.join(os.getcwd(), 'event_generators')
API_BASE_URL = os.environ.get('API_BASE_URL', 'http://localhost:9001')
BACKEND_API_KEY = os.environ.get('BACKEND_API_KEY')
DESTINATIONS_FILE = os.path.join(os.path.dirname(__file__), 'destinations.json')
KEYRING_SERVICE = 'jarvis_frontend_hec_destinations'

@app.route('/')
def index():
    return render_template('log_generator.html')

def get_scripts():
    scripts = {}
    try:
        if not os.path.exists(EVENT_GENERATORS_DIR):
            return scripts
        for root, dirs, files in os.walk(EVENT_GENERATORS_DIR):
            py_files = sorted([f for f in files if f.endswith('.py')])
            if py_files:
                relative_root = os.path.relpath(root, EVENT_GENERATORS_DIR)
                if relative_root == '.':
                    category_name = "Uncategorized"
                else:
                    category_name = relative_root.replace(os.sep, ' - ').title()
                scripts[category_name] = [os.path.join(relative_root, f) for f in py_files]
    except Exception as e:
        print(f"Error scanning for scripts: {e}")
    return scripts

def _load_destinations():
    try:
        if not os.path.exists(DESTINATIONS_FILE):
            return []
        with open(DESTINATIONS_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_destinations(items):
    try:
        with open(DESTINATIONS_FILE, 'w') as f:
            json.dump(items, f)
        return True
    except Exception:
        return False

def fetch_generators():
    base_url = f"{API_BASE_URL}/api/v1/generators"
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else None
        all_items = []
        # First try to request a large page to avoid pagination
        resp = requests.get(base_url, params={'page': 1, 'per_page': 500}, headers=headers, timeout=20)
        if resp.status_code == 200:
            payload = resp.json()
            data = payload.get('data', {})
            all_items = data.get('generators', [])
        else:
            # Fallback to default pagination loop
            page = 1
            total_pages = 1
            while page <= total_pages:
                resp = requests.get(base_url, params={'page': page}, headers=headers, timeout=20)
                if resp.status_code != 200:
                    # If we already have some items, return them rather than hard-fail
                    if all_items:
                        break
                    return None, f"Backend returned {resp.status_code}: {resp.text}"
                payload = resp.json()
                data = payload.get('data', {})
                items = data.get('generators', [])
                all_items.extend(items)
                meta = payload.get('metadata', {})
                pagination = meta.get('pagination', {})
                total_pages = int(pagination.get('total_pages', total_pages)) or 1
                page += 1

        # Simplify for dropdown: list of {id, name, category, file_path}
        simplified = [
            {
                'id': g.get('id'),
                'name': g.get('name'),
                'category': g.get('category'),
                'file_path': g.get('file_path')
            }
            for g in all_items
        ]
        return simplified, None
    except Exception as e:
        return None, str(e)

@app.route('/get-generators', methods=['GET'])
def get_generators():
    data, err = fetch_generators()
    if err:
        return jsonify({'error': f'Failed to fetch generators from backend: {err}'}), 502
    return jsonify({'generators': data})

@app.route('/destinations', methods=['GET'])
def list_destinations():
    items = _load_destinations()
    # Do not expose HEC token
    redacted = []
    for d in items:
        base = {
            'id': d.get('id'),
            'name': d.get('name'),
            'type': d.get('type'),
        }
        if d.get('type') == 'hec':
            base['url'] = d.get('url')
        elif d.get('type') == 'syslog':
            base['ip'] = d.get('ip')
            base['port'] = d.get('port')
            base['protocol'] = d.get('protocol')
        redacted.append(base)
    return jsonify({'destinations': redacted})

@app.route('/destinations', methods=['POST'])
def create_destination():
    payload = request.get_json(silent=True) or {}
    dest_type = payload.get('type')  # 'hec' or 'syslog'
    name = payload.get('name')

    if dest_type == 'hec':
        url = payload.get('url')
        token = payload.get('token')
        if not name or not url or not token:
            return jsonify({'error': 'name, url and token are required'}), 400
        # Normalize URL for HEC
        base = url.rstrip('/')
        if not (base.endswith('/event') or base.endswith('/raw') or '/services/collector' in base):
            base = base + '/services/collector'
    elif dest_type == 'syslog':
        ip = payload.get('ip')
        port = payload.get('port')
        protocol = (payload.get('protocol') or '').upper()
        if not name or not ip or not port or protocol not in ('UDP','TCP'):
            return jsonify({'error': 'name, ip, port, protocol (UDP/TCP) are required'}), 400
    else:
        return jsonify({'error': 'Unsupported destination type'}), 400

    items = _load_destinations()
    # Upsert by name and type
    existing = next((d for d in items if d.get('name') == name and d.get('type') == dest_type), None)
    if existing:
        if dest_type == 'hec':
            existing['url'] = base
            # Store token securely; if unavailable, do not fall back to plaintext
            if not HAS_KEYRING or not existing.get('id'):
                return jsonify({'error': 'Secure storage unavailable. Unable to save token. Please contact support.'}), 500
            try:
                keyring.set_password(KEYRING_SERVICE, existing['id'], token)
                existing.pop('token', None)
            except Exception:
                return jsonify({'error': 'Failed to save token securely. Please contact support.'}), 500
        else:
            existing['ip'] = ip
            existing['port'] = int(port)
            existing['protocol'] = protocol
        dest_id = existing.get('id')
    else:
        # Simple id
        dest_id = f"{dest_type}:{len(items)+1}"
        if dest_type == 'hec':
            entry = {'id': dest_id, 'type': dest_type, 'name': name, 'url': base}
            # Require secure storage for new entries
            if not HAS_KEYRING:
                return jsonify({'error': 'Secure storage unavailable. Unable to save token. Please contact support.'}), 500
            try:
                keyring.set_password(KEYRING_SERVICE, dest_id, token)
            except Exception:
                return jsonify({'error': 'Failed to save token securely. Please contact support.'}), 500
        else:
            entry = {'id': dest_id, 'type': dest_type, 'name': name, 'ip': ip, 'port': int(port), 'protocol': protocol}
        items.append(entry)

    if not _save_destinations(items):
        return jsonify({'error': 'Failed to save destination'}), 500

    return jsonify({'id': dest_id, 'name': name, 'type': dest_type, 'url': base}), 201

@app.route('/destinations/<dest_id>', methods=['DELETE'])
def delete_destination(dest_id: str):
    items = _load_destinations()
    # Remove from keyring first (best-effort)
    if HAS_KEYRING:
        try:
            keyring.delete_password(KEYRING_SERVICE, dest_id)
        except Exception:
            pass
    # Remove from file
    new_items = [d for d in items if d.get('id') != dest_id]
    if not _save_destinations(new_items):
        return jsonify({'error': 'Failed to delete destination'}), 500
    return ('', 204)

@app.route('/scenarios', methods=['GET'])
def list_scenarios():
    """List available attack scenarios"""
    scenarios = [
        {
            'id': 'attack_scenario_orchestrator',
            'name': 'Operation Digital Heist',
            'description': 'Sophisticated 14-day APT campaign against a financial services company. Simulates reconnaissance, initial access, persistence, privilege escalation, and data exfiltration.',
            'duration_days': 14,
            'events_per_day': 50,
            'total_events': 700,
            'phases': ['Reconnaissance & Phishing', 'Initial Access', 'Persistence & Lateral Movement', 'Privilege Escalation', 'Data Exfiltration']
        },
        {
            'id': 'enterprise_attack_scenario',
            'name': 'Enterprise Breach Scenario',
            'description': 'Enhanced enterprise attack scenario with 330+ events across multiple security products. Demonstrates correlated attack patterns.',
            'duration_minutes': 60,
            'total_events': 330,
            'phases': ['Initial Compromise', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration', 'Persistence']
        },
        {
            'id': 'enterprise_attack_scenario_10min',
            'name': 'Enterprise Breach (10 min)',
            'description': 'Condensed enterprise breach scenario for quick demos.',
            'duration_minutes': 10,
            'total_events': 120,
            'phases': ['Initial Access', 'Lateral Movement', 'Exfiltration']
        },
        {
            'id': 'enterprise_scenario_sender',
            'name': 'Enterprise Scenario Sender (330+ events)',
            'description': 'Sends enhanced enterprise attack scenario events to HEC using proper routing.',
            'duration_minutes': 45,
            'total_events': 330,
            'phases': ['Initial Compromise', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration']
        },
        {
            'id': 'enterprise_scenario_sender_10min',
            'name': 'Enterprise Scenario Sender (10 min)',
            'description': 'Fast sender for enterprise scenario suitable for time-boxed demos.',
            'duration_minutes': 10,
            'total_events': 120,
            'phases': ['Initial Access', 'Lateral Movement', 'Exfiltration']
        },
        {
            'id': 'showcase_attack_scenario',
            'name': 'AI-SIEM Showcase Scenario',
            'description': 'Showcase scenario demonstrating multi-platform correlation across EDR, Email, Identity, Cloud, Network, WAF, and more.',
            'duration_minutes': 30,
            'total_events': 200,
            'phases': ['Phishing', 'Compromise', 'Movement', 'Privilege Escalation', 'Exfiltration']
        },
        {
            'id': 'showcase_scenario_sender',
            'name': 'Showcase Scenario Sender',
            'description': 'Sends the showcase scenario events to HEC with compact progress output.',
            'duration_minutes': 20,
            'total_events': 180,
            'phases': ['Phishing', 'Compromise', 'Movement', 'Exfiltration']
        },
        {
            'id': 'quick_scenario',
            'name': 'Quick Scenario (Comprehensive)',
            'description': 'Generates a compact yet comprehensive attack scenario spanning multiple sources.',
            'duration_minutes': 5,
            'total_events': 80,
            'phases': ['Initial Access', 'Reconnaissance', 'Movement', 'Exfiltration']
        },
        {
            'id': 'quick_scenario_simple',
            'name': 'Quick Scenario (Simple)',
            'description': 'Minimal scenario for smoke testing pipeline and parsers.',
            'duration_minutes': 2,
            'total_events': 30,
            'phases': ['Access', 'Movement']
        },
        {
            'id': 'scenario_hec_sender',
            'name': 'Scenario HEC Sender',
            'description': 'Generic scenario sender that replays a scenario JSON to HEC.',
            'duration_minutes': 15,
            'total_events': 150,
            'phases': ['Replay']
        },
        {
            'id': 'star_trek_integration_test',
            'name': 'Integration Test (Star Trek)',
            'description': 'Integration test scenario for end-to-end validation and fun output.',
            'duration_minutes': 3,
            'total_events': 20,
            'phases': ['Test']
        }
    ]
    return jsonify({'scenarios': scenarios})

@app.route('/scenarios/run', methods=['POST'])
def run_scenario():
    """Execute a scenario and stream progress"""
    data = request.json
    scenario_id = data.get('scenario_id')
    destination_id = data.get('destination_id')
    
    if not scenario_id:
        return jsonify({'error': 'scenario_id is required'}), 400
    if not destination_id:
        return jsonify({'error': 'destination_id is required'}), 400
    
    # Resolve destination
    dest_items = _load_destinations()
    chosen = next((d for d in dest_items if d.get('id') == destination_id), None)
    if not chosen:
        return jsonify({'error': 'Destination not found'}), 404
    
    if chosen.get('type') != 'hec':
        return jsonify({'error': 'Scenarios currently only support HEC destinations'}), 400
    
    hec_url = chosen.get('url')
    hec_token = None
    if HAS_KEYRING and chosen.get('id'):
        try:
            hec_token = keyring.get_password(KEYRING_SERVICE, chosen['id'])
        except Exception:
            pass
    
    if not hec_url or not hec_token:
        return jsonify({'error': 'HEC destination incomplete or token missing'}), 400
    
    def generate_and_stream():
        try:
            yield "INFO: Starting scenario execution...\n"
            # Map scenario ids to filenames when they differ
            id_to_file = {
                'attack_scenario_orchestrator': 'attack_scenario_orchestrator.py',
                'enterprise_attack_scenario': 'enterprise_attack_scenario.py',
                'enterprise_attack_scenario_10min': 'enterprise_attack_scenario_10min.py',
                'enterprise_scenario_sender': 'enterprise_scenario_sender.py',
                'enterprise_scenario_sender_10min': 'enterprise_scenario_sender_10min.py',
                'showcase_attack_scenario': 'showcase_attack_scenario.py',
                'showcase_scenario_sender': 'showcase_scenario_sender.py',
                'quick_scenario': 'quick_scenario.py',
                'quick_scenario_simple': 'quick_scenario_simple.py',
                'scenario_hec_sender': 'scenario_hec_sender.py',
                'star_trek_integration_test': 'star_trek_integration_test.py',
            }
            scenarios_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend', 'scenarios'))
            # Resolve script path
            filename = id_to_file.get(scenario_id, f"{scenario_id}.py")
            script_path = os.path.join(scenarios_dir, filename)
            if not os.path.exists(script_path):
                yield f"ERROR: Scenario script not found: {filename}\n"
                return

            # Prepare environment for HEC sender used by scenario scripts
            env = os.environ.copy()
            env['S1_HEC_TOKEN'] = hec_token
            env['S1_HEC_URL'] = hec_url.rstrip('/')

            yield f"INFO: Executing {filename}...\n"
            import subprocess
            process = subprocess.Popen(
                ['python', script_path],
                cwd=scenarios_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env
            )

            # Stream output lines
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                yield line

            process.wait()
            rc = process.returncode
            if rc == 0:
                yield "INFO: Scenario execution complete\n"
            else:
                yield f"ERROR: Scenario exited with code {rc}\n"
        except Exception as e:
            yield f"ERROR: Scenario execution failed: {e}\n"
    
    return Response(stream_with_context(generate_and_stream()), mimetype='text/plain')

@app.route('/get-scripts', methods=['GET'])
def get_available_scripts():
    scripts = get_scripts()
    if not scripts:
        return jsonify({"message": "No log scripts found."}), 404
    return jsonify(scripts)

@app.route('/generate-logs', methods=['POST'])
def generate_logs():
    data = request.json
    destination = data.get('destination', 'syslog')
    script_path = data.get('script')
    log_count = int(data.get('count', 3))
    eps = float(data.get('eps', 1.0))
    syslog_ip = data.get('ip')
    syslog_port = int(data.get('port')) if data.get('port') is not None else None
    syslog_protocol = data.get('protocol')
    product_id = data.get('product')
    # Unified destination id (preferred)
    unified_dest_id = data.get('destination_id')
    # Back-compat fields
    hec_dest_id = data.get('hec_destination_id')
    syslog_dest_id = data.get('syslog_destination_id')
    
    if destination == 'syslog':
        full_script_path = os.path.join(EVENT_GENERATORS_DIR, script_path)
        if not os.path.exists(full_script_path):
            return jsonify({'error': 'Invalid script name or path'}), 400

    def generate_and_stream():
        sock = None
        try:
            if destination == 'syslog':
                # Resolve syslog destination if provided
                resolved_syslog_id = unified_dest_id if unified_dest_id else syslog_dest_id
                if resolved_syslog_id:
                    dest_items = _load_destinations()
                    chosen = next((d for d in dest_items if d.get('id') == resolved_syslog_id and d.get('type') == 'syslog'), None)
                    if not chosen:
                        yield "ERROR: Selected syslog destination not found.\n"
                        return
                    syslog_ip_local = chosen.get('ip')
                    syslog_port_local = int(chosen.get('port') or 0)
                    syslog_protocol_local = (chosen.get('protocol') or '').upper()
                else:
                    syslog_ip_local = syslog_ip
                    syslog_port_local = syslog_port
                    syslog_protocol_local = (syslog_protocol or '').upper()

                if not syslog_ip_local or not syslog_port_local or syslog_protocol_local not in ('UDP','TCP'):
                    yield "ERROR: Missing or invalid syslog destination details.\n"
                    return

                if syslog_protocol_local == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif syslog_protocol_local == 'TCP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect((syslog_ip_local, syslog_port_local))
                    except Exception as e:
                        yield f"ERROR: Could not connect to TCP syslog server at {syslog_ip_local}:{syslog_port_local}. Details: {e}\n"
                        return
                else:
                    yield "ERROR: Invalid syslog protocol. Please select TCP or UDP.\n"
                    return

                yield "INFO: Starting log generation...\n"

                command = ['python', full_script_path, str(log_count)]
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                for line in iter(process.stdout.readline, ''):
                    if line:
                        log_line = line.strip()
                        try:
                            if syslog_protocol_local == 'UDP':
                                sock.sendto(bytes(log_line + '\n', 'utf-8'), (syslog_ip_local, syslog_port_local))
                            else:
                                sock.sendall(bytes(log_line + '\n', 'utf-8'))
                        except Exception as e:
                            yield f"ERROR: Failed to send log to syslog server. Details: {e}\n"
                            process.terminate()
                            break

                        yield f"LOG: {log_line}\n"

                errors = process.stderr.read()
                if errors:
                    yield f"ERROR: Script execution produced errors:\n{errors}\n"

                process.wait()

            elif destination == 'hec':
                # Validate inputs
                if not product_id:
                    yield "ERROR: Missing product id for HEC.\n"
                    return

                # Resolve destination (prefer unified id, else legacy id, else first saved HEC)
                dest_items = _load_destinations()
                chosen = None
                resolved_hec_id = unified_dest_id if unified_dest_id else hec_dest_id
                if resolved_hec_id:
                    chosen = next((d for d in dest_items if d.get('id') == resolved_hec_id and d.get('type') == 'hec'), None)
                if not chosen:
                    chosen = next((d for d in dest_items if d.get('type') == 'hec'), None)
                if not chosen:
                    yield "ERROR: No HEC destination configured. Add one in Settings > Destinations.\n"
                    return
                hec_url = chosen.get('url')
                hec_token = None
                # Fetch token from keyring; if unavailable, warn and abort
                if not HAS_KEYRING or not chosen.get('id'):
                    yield "ERROR: Secure token storage unavailable. Cannot access HEC token. Please contact support.\n"
                    return
                try:
                    hec_token = keyring.get_password(KEYRING_SERVICE, chosen['id'])
                except Exception:
                    hec_token = None
                if not hec_url or not hec_token:
                    yield "ERROR: Selected HEC destination is incomplete or token missing from secure storage. Please contact support.\n"
                    return

                yield "INFO: Starting HEC send...\n"

                # Build path to hec_sender.py (Frontend/../Backend/event_generators/shared/hec_sender.py)
                hec_sender_path = os.path.normpath(
                    os.path.join(os.path.dirname(__file__), '..', 'Backend', 'event_generators', 'shared', 'hec_sender.py')
                )
                if not os.path.exists(hec_sender_path):
                    yield "ERROR: HEC sender not found.\n"
                    return

                # Normalize HEC URL: accept bare domain and append collector path
                def _normalize_hec_url(u: str) -> str:
                    if not u:
                        return u
                    base = u.rstrip('/')
                    if base.endswith('/event') or base.endswith('/raw'):
                        return base
                    # If already includes /services/collector, keep it
                    if '/services/collector' in base:
                        return base
                    return base + '/services/collector'

                normalized_hec_url = _normalize_hec_url(hec_url)

                env = os.environ.copy()
                env['S1_HEC_TOKEN'] = hec_token
                env['S1_HEC_URL'] = normalized_hec_url
                # Enable debug output to see exact payloads
                env['S1_HEC_DEBUG'] = '1'

                # Calculate delay from EPS: delay = 1 / eps
                delay = 1.0 / eps if eps > 0 else 1.0
                command = ['python3', hec_sender_path, '--product', product_id, '-n', str(log_count), 
                           '--min-delay', str(delay), '--max-delay', str(delay), '--print-responses']
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env
                )

                # Stream sanitized output
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        continue
                    sanitized = (line
                        .replace(hec_token, '***')
                        .replace(hec_url or '', '<hec_url>')
                        .replace(normalized_hec_url or '', '<hec_url>'))
                    yield sanitized

                errors = process.stderr.read()
                if errors:
                    sanitized_err = (errors
                        .replace(hec_token, '***')
                        .replace(hec_url or '', '<hec_url>')
                        .replace(normalized_hec_url or '', '<hec_url>'))
                    yield f"ERROR: HEC sender errors:\n{sanitized_err}\n"
                process.wait()

        except FileNotFoundError:
            yield f"ERROR: Python executable not found. Please ensure Python is in your system's PATH.\n"
        except Exception as e:
            yield f"ERROR: An unexpected error occurred: {e}\n"
            
        finally:
            yield "INFO: Log generation complete.\n"
            if sock:
                sock.close()

    return Response(stream_with_context(generate_and_stream()), mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)

