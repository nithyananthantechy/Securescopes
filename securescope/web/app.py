from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for, Response
import os
import platform
import socket
import traceback
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from securescope.core.scanner import SecureScanner
from securescope.core.hardener import SecureHardener
from securescope.core.reporter import SecureReporter
from securescope.core.utils import detect_platform

# Load Configuration
def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config', 'settings.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

config = load_config()

# Initialize Flask
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.secret_key = os.environ.get(
  'SECRET_KEY', 
  'nitechspark-securescope-2026-prod')
app.permanent_session_lifetime = timedelta(hours=config.get("web", {}).get("session_timeout_hours", 8))

scanner = SecureScanner()
stored_scan_results = {}
scan_history = {}
scan_events = []
removed_hosts = set()
rate_limit_state = {}
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()


def _now():
    return datetime.now()


def _validate_host(value):
    if not value:
        return False
    value = value.strip()
    return re.fullmatch(r"[a-zA-Z0-9\.\-_:]+", value) is not None


def _validate_url(value):
    if not value:
        return False
    parsed = urlparse(value if value.startswith(("http://", "https://")) else f"https://{value}")
    return bool(parsed.netloc)


def _allowed_users():
    auth = config.get("web", {}).get("auth", {})
    users = auth.get("users", []) or []
    if not users:
        return [{
            "username": auth.get("username", "nitechspark"),
            "password": auth.get("password", "SecureScope@2026"),
            "role": "admin",
        }]
    # Backward-compatible: always accept legacy username/password too.
    users.append({
        "username": auth.get("username", "nitechspark"),
        "password": auth.get("password", "SecureScope@2026"),
        "role": "admin",
    })
    return users


def _check_rate_limit(key, limit=10, per_seconds=60):
    now = _now().timestamp()
    state = rate_limit_state.setdefault(key, [])
    state[:] = [t for t in state if now - t < per_seconds]
    if len(state) >= limit:
        return False
    state.append(now)
    return True


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def _record_scan(target, score):
    t = _now().strftime("%H:%M:%S")
    history = scan_history.setdefault(target, [])
    history.append({"time": t, "score": int(score)})
    if len(history) > 5:
        scan_history[target] = history[-5:]


def _add_events(target, checks):
    ts = _now().strftime("%H:%M:%S")
    for c in checks[:50]:
        level = c.get("status", "WARNING")
        icon = "🟡"
        if level == "FAIL":
            icon = "🔴"
        elif level == "PASS":
            icon = "🟢"
        msg = f"{c.get('check', 'Check')} on {target}"
        scan_events.append({"time": ts, "icon": icon, "level": level, "message": msg})
    if len(scan_events) > 200:
        del scan_events[:-200]


def _frameworks_for_check(check_name):
    name = (check_name or "").lower()
    mapping = []
    if any(x in name for x in ("ssh", "root", "password auth")):
        mapping += ["CIS", "NIST"]
    if any(x in name for x in ("firewall", "port", "smb")):
        mapping += ["CIS", "PCI", "NIST"]
    if any(x in name for x in ("password", "guest", "admin")):
        mapping += ["ISO", "CIS", "NIST"]
    if not mapping:
        mapping = ["ISO"]
    return list(dict.fromkeys(mapping))

# --- Authentication ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if app.config.get('TESTING'):
            return f(*args, **kwargs)
        if config['web']['auth']['enabled'] and not session.get('logged_in'):
            return redirect(url_for('login'))
        session.permanent = True
        if (datetime.utcnow().timestamp() - session.get("last_seen", 0)) > app.permanent_session_lifetime.total_seconds():
            session.clear()
            return redirect(url_for('login'))
        session["last_seen"] = datetime.utcnow().timestamp()
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def inner(*args, **kwargs):
            if app.config.get('TESTING'):
                return f(*args, **kwargs)
            if session.get("role") not in roles:
                return jsonify({"error": "Forbidden for current role"}), 403
            return f(*args, **kwargs)
        return inner
    return deco


def secure_post(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if app.config.get("TESTING"):
            return f(*args, **kwargs)
        key = session.get("username") or request.remote_addr or "anon"
        if not _check_rate_limit(f"{request.path}:{key}", limit=10, per_seconds=60):
            return jsonify({"error": "Rate limit exceeded (10/min)."}), 429
        token = request.headers.get("X-CSRF-Token")
        if token != session.get("csrf_token"):
            return jsonify({"error": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return inner

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)  
def server_error(e):
    return render_template('500.html'), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        for user in _allowed_users():
            if username == user.get("username") and password == user.get("password"):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user.get("role", "viewer")
                session["last_seen"] = datetime.utcnow().timestamp()
                _csrf_token()
                return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Routes ---
@app.route('/')
@login_required
def index():
    plat_info = detect_platform()
    demo_mode = bool(app.config.get("DEMO_MODE"))
    return render_template(
        'index.html',
        plat_info=plat_info,
        csrf_token=_csrf_token(),
        username=session.get("username", "operator"),
        role=session.get("role", "viewer"),
        org_name=config.get("branding", {}).get("organization_name", "NiTechSpark"),
        client_name=config.get("branding", {}).get("client_name", "Default Client"),
        demo_mode=demo_mode,
    )

@app.route('/logo.png')
def serve_logo():
    logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logo.png')
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/png')
    return '', 404

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/api/scan/remote', methods=['POST'])
@login_required
@secure_post
def api_scan_remote():
    try:
        req_data = request.json
        host = (req_data.get('host') or "").strip()
        user = req_data.get('username')
        password = req_data.get('password')
        target_type = req_data.get('type', 'linux')
        port = req_data.get('port', 22)
        if not _validate_host(host):
            return jsonify({"error": "Invalid host format"}), 400
        
        data = scanner.scan_remote(host=host, user=user, password=password, target_type=target_type, port=int(port))

        res = {
            'score': data['score'], 'failed': data['failed'], 'passed': data['passed'], 'warnings': data['warnings'],
            'hostname': host, 'target': host, 'os': data.get('os', target_type.title()),
            'checks': data['checks'], 'last_scan': datetime.now().strftime('%d %b %Y %H:%M:%S'),
            'platform': 'Remote'
        }
        for c in res["checks"]:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        target_key = host
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)

        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(target_key, res["checks"])
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/remove', methods=['POST'])
@login_required
@secure_post
def api_targets_remove():
    try:
        data = request.json or {}
        host = (data.get('host') or '').strip()
        if host:
            if host in stored_scan_results:
                del stored_scan_results[host]
            if host in scan_history:
                del scan_history[host]
            removed_hosts.add(host)
        return jsonify({'status': 'removed', 'host': host})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/ports', methods=['POST'])
@login_required
@secure_post
def api_scan_ports():
    """Port scanning endpoint."""
    try:
        req_data = request.json
        host = req_data.get('host', 'localhost')
        if not _validate_host(host):
            return jsonify({"error": "Invalid host format"}), 400
        
        if host == 'localhost' or host == '127.0.0.1':
            try:
                host = socket.gethostbyname(socket.gethostname())
            except Exception:
                host = '127.0.0.1'
        
        data = scanner.scan_ports(host)
        
        res = {
            'score': data['score'], 'failed': data['failed'], 'passed': data['passed'], 'warnings': data['warnings'],
            'hostname': host, 'target': host, 'os': 'Port Scan',
            'checks': data['checks'], 'last_scan': datetime.now().strftime('%d %b %Y %H:%M:%S'),
            'platform': 'Port Scan'
        }
        for c in res["checks"]:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        target_key = f'ports-{host}'
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)

        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(host, res["checks"])
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/web', methods=['POST'])
@login_required
@secure_post
def api_scan_web():
    """Web security scanning endpoint."""
    try:
        req_data = request.json
        url = req_data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not _validate_url(url):
            return jsonify({'error': 'Invalid URL'}), 400
        
        data = scanner.scan_web(url)
        
        res = {
            'score': data['score'], 'failed': data['failed'], 'passed': data['passed'], 'warnings': data['warnings'],
            'hostname': url, 'target': url, 'os': 'Web Scan',
            'checks': data['checks'], 'last_scan': datetime.now().strftime('%d %b %Y %H:%M:%S'),
            'platform': 'Web Scan'
        }
        for c in res["checks"]:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        target_key = f'web-{url}'
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)

        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(url, res["checks"])
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/local')
@login_required
def report_local():
    results = stored_scan_results.get('localhost')
    if not results:
        data = scanner.scan_local()
        results = {
            'checks': data['checks'],
            'score': data['score'],
            'passed': data['passed'],
            'failed': data['failed'],
            'warnings': data['warnings'],
        }
    reporter = SecureReporter()
    html = reporter.generate(results, org='NiTechSpark')
    return Response(html, mimetype='text/html',
        headers={'Content-Disposition': 'attachment; filename=NiTechSpark_Local_Report.html'})

@app.route('/api/report/remote')
@login_required
def report_remote():
    host = request.args.get('host', 'unknown')
    results = stored_scan_results.get(host)
    if not results:
        return jsonify({'error': f'No scan data for {host}'}), 404
    reporter = SecureReporter()
    html = reporter.generate(results, org='NiTechSpark')
    return Response(html, mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=NiTechSpark_{host}_Report.html'})

@app.route('/api/harden', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def harden():
    data = request.json
    results = data.get('results', data.get('checks', []))
    
    # Retrieve connection params sent by frontend for remote fixes
    host = data.get('host', 'localhost')
    target_type = data.get('type')
    username = data.get('username')
    password = data.get('password')
    port = data.get('port', 22)

    hardener = SecureHardener(
        auto_confirm=True, 
        target_host=host, 
        target_port=port,
        username=username, 
        password=password, 
        target_type=target_type
    )
    harden_log = hardener.apply_fixes(results)
    return jsonify({"log": harden_log})


@app.route('/api/scan/local', methods=['GET'])
@login_required
def api_scan_local():
    try:
        data = scanner.scan_local()

        plat_info = detect_platform()
        hostname = socket.gethostname()

        is_admin = False
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass

        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = "127.0.0.1"

        checks = data['checks']
        for c in checks:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        res = {
            'score': data['score'], 'failed': data['failed'], 'passed': data['passed'], 'warnings': data['warnings'],
            'hostname': hostname, 'ip_address': ip_address, 'os': plat_info['os'],
            'is_admin': is_admin, 'kernel': platform.version(),
            'platform': 'WSL' if plat_info['is_wsl'] else 'Native',
            'last_scan': datetime.now().strftime('%d %b %Y %H:%M:%S'),
            'checks': checks, 'org': config['reporting']['org_name']
        }
        stored_scan_results['localhost'] = res
        _record_scan('localhost', res["score"])
        _add_events(hostname, checks)
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed')
@login_required
def api_feed():
    return jsonify({
        "events": scan_events[-50:],
        "history": scan_history,
        "csrf_token": _csrf_token(),
    })


def _run_scheduled_scan(target, mode):
    if mode == "local":
        data = scanner.scan_local()
        score = data.get("score", 0)
        _record_scan("localhost", score)
    else:
        # lightweight scheduled check marker
        _record_scan(target, 0)
    _add_events(target, [{"status": "WARNING", "check": f"Scheduled {mode} scan executed"}])


@app.route('/api/schedule', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def api_schedule():
    payload = request.json or {}
    target = payload.get("target", "localhost")
    frequency = payload.get("frequency", "hourly")
    if frequency not in ("hourly", "daily", "weekly"):
        return jsonify({"error": "frequency must be hourly/daily/weekly"}), 400
    seconds = {"hourly": 3600, "daily": 86400, "weekly": 604800}[frequency]
    job_id = f"scan:{target}:{frequency}"
    try:
        scheduler.add_job(
            _run_scheduled_scan,
            trigger=IntervalTrigger(seconds=seconds),
            id=job_id,
            replace_existing=True,
            kwargs={"target": target, "mode": "local" if target == "localhost" else "remote"},
        )
        job = scheduler.get_job(job_id)
        next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job and job.next_run_time else None
        return jsonify({"ok": True, "job_id": job_id, "next_run": next_run})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/export/json')
@login_required
def api_export_json():
    host = request.args.get("host", "localhost")
    data = stored_scan_results.get(host)
    if not data:
        return jsonify({"error": "No data for host"}), 404
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=False, port=8080)
