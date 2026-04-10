from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for, Response
import os
import platform
import socket
import traceback
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
from urllib.parse import urlparse

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from securescope.core.scanner import Scanner
from securescope.core.hardener import SecureHardener
from securescope.core.reporter import Reporter
from securescope.core.utils import detect_platform
from securescope.scanners.llm_scanner import LLMSecurityScanner
from securescope.web.llm_store import LLMStore
from securescope.web.report_generator import LLMReportGenerator
from securescope.integrations.slack import send_slack_alert
from securescope.integrations.email import send_email_report

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

scanner = Scanner()
stored_scan_results = {}
scan_history = {}
scan_events = []
removed_hosts = set()
rate_limit_state = {}
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
llm_store = LLMStore(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "llm_audit.db"))
llm_store.init_db()
llm_scan_state = {}
llm_reporter = LLMReportGenerator()
SUPER_ADMINS = set((os.environ.get("SECURESCOPE_SUPER_ADMINS", "nitechspark").split(",")))


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


def _llm_user_id() -> str:
    org_id = session.get("org_id")
    if org_id:
        return f"org:{org_id}"
    return session.get("username", "anonymous")


def _is_super_admin() -> bool:
    return (session.get("username") or "").strip() in SUPER_ADMINS


def _build_llm_html_report(scan: dict):
    data = scan.get("report_json") or {}
    vulnerabilities = data.get("vulnerabilities", [])
    score = int(scan.get("security_score", 0))
    score_color = "#22c55e" if score >= 80 else "#f97316" if score >= 50 else "#ef4444"
    vuln_html = "".join(
        (
            f"<li><b>{v.get('severity', 'low').upper()}</b> - {v.get('type', 'unknown')}: "
            f"{v.get('description', 'No description')}<br><i>Remediation:</i> {v.get('remediation', 'N/A')}</li>"
        )
        for v in vulnerabilities
    ) or "<li>No vulnerabilities found.</li>"
    compliance = data.get("compliance_status", {})
    compliance_html = "".join(
        f"<li><b>{k}</b>: {(v or {}).get('status', 'partial')}</li>" for k, v in compliance.items()
    ) or "<li>No compliance mapping available.</li>"
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>SecureScope LLM Report</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; background: #f5f7fb; color: #0f172a; }}
        .header {{ display: flex; align-items: center; gap: 12px; background: #0b1730; color: #fff; padding: 16px 24px; }}
        .logo {{ height: 38px; width: auto; }}
        .wrap {{ padding: 24px; }}
        .score {{ font-size: 42px; font-weight: 700; color: {score_color}; }}
        .box {{ background: #fff; border: 1px solid #d6deea; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
      </style>
    </head>
    <body>
      <div class="header">
        <img src="/logo.png" class="logo" alt="SecureScope logo" />
        <div>
          <div style="font-size:20px;font-weight:700;">SecureScope</div>
          <div style="font-size:12px;opacity:.9;">LLM & Chatbot Security Audit Report</div>
        </div>
      </div>
      <div class="wrap">
        <div class="box">
          <div>Scan ID: {scan.get("scan_id")}</div>
          <div class="score">{score}/100</div>
        </div>
        <div class="box"><h3>Vulnerabilities</h3><ul>{vuln_html}</ul></div>
        <div class="box"><h3>Compliance</h3><ul>{compliance_html}</ul></div>
      </div>
    </body>
    </html>
    """


def _set_llm_scan_state(scan_id: str, progress: int, message: str, status: str = "in_progress") -> None:
    llm_scan_state[scan_id] = {
        "progress": max(0, min(100, int(progress))),
        "message": message,
        "status": status,
    }


def _run_llm_scan_job(scan_id: str, model: dict) -> None:
    try:
        _set_llm_scan_state(scan_id, 5, "Scan queued")
        scanner = LLMSecurityScanner(
            model_id=model["id"],
            model_type=model["model_type"],
            api_endpoint=model.get("api_endpoint"),
            api_key=model.get("api_key"),
            model_parameters=model.get("model_parameters"),
        )
        report = scanner.scan_all(on_progress=lambda p, m: _set_llm_scan_state(scan_id, p, m))
        report["model_name"] = model.get("model_name")
        html_report = llm_reporter.build_html(
            {"scan_id": scan_id, "security_score": report.get("security_score"), "report_json": report}
        )
        llm_store.complete_scan(scan_id, report, html_report)
        _set_llm_scan_state(scan_id, 100, "Completed", status="completed")
    except Exception as exc:
        llm_store.fail_scan(scan_id, str(exc))
        _set_llm_scan_state(scan_id, 100, f"Failed: {exc}", status="failed")

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


def super_admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if app.config.get('TESTING'):
            return f(*args, **kwargs)
        if not _is_super_admin():
            return jsonify({"error": "Super admin required"}), 403
        return f(*args, **kwargs)
    return inner


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
        db_user = llm_store.authenticate_user(username, password)
        if db_user:
            session['logged_in'] = True
            session['username'] = db_user["username"]
            session['role'] = db_user.get("role", "viewer")
            session['org_id'] = db_user.get("org_id")
            session["last_seen"] = datetime.utcnow().timestamp()
            _csrf_token()
            return redirect(url_for('index'))
        for user in _allowed_users():
            if username == user.get("username") and password == user.get("password"):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user.get("role", "viewer")
                session['org_id'] = None
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
        is_super_admin=_is_super_admin(),
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
    from securescope.core.scanner import Scanner
    from securescope.core.reporter import Reporter
    from flask import send_file
    import os, tempfile
    scanner = Scanner()
    results = scanner.scan_local()
    
    # Enrich results with system info as required by Reporter
    plat_info = detect_platform()
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "127.0.0.1"
        
    report_data = {
        'checks': results['checks'],
        'score': results['score'],
        'hostname': hostname,
        'os': plat_info['os'],
        'kernel': platform.version(),
        'ip_address': ip_address
    }
    
    reporter = Reporter()
    org = config.get('branding', {}).get('organization_name', 'NiTechSpark')
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.html', 
        delete=False, encoding='utf-8') as f:
        content = reporter.generate_html(
            report_data, org=org)
        f.write(content)
        tmp_path = f.name
    return send_file(
        tmp_path,
        as_attachment=True,
        download_name='NiTechSpark_Security_Report.html',
        mimetype='text/html')

@app.route('/api/report/remote')
@login_required
def report_remote():
    host = request.args.get('host', 'unknown')
    results = stored_scan_results.get(host)
    if not results:
        return jsonify({'error': f'No scan data for {host}'}), 404
    reporter = Reporter()
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
            'checks': checks, 'org': config.get('branding', {}).get('organization_name', 'NiTechSpark')
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

@app.route('/api/settings/save', methods=['POST'])
@login_required
@secure_post
def save_settings():
    try:
        data = request.json
        app.config['ORG_NAME'] = data.get('org_name', 'NiTechSpark')
        app.config['CLIENT_NAME'] = data.get('client_name', '')
        return jsonify({'status': 'saved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/llm/models', methods=['POST'])
@login_required
@secure_post
@role_required("admin", "org_admin")
def add_llm_model():
    try:
        import json

        data = request.json or {}
        model_name = (data.get("model_name") or "").strip()
        model_type = (data.get("model_type") or "").strip()
        if not model_name or not model_type:
            return jsonify({"error": "model_name and model_type are required"}), 400
        raw_params = data.get("model_parameters")
        model_parameters = {}
        if isinstance(raw_params, dict):
            model_parameters = raw_params
        elif isinstance(raw_params, str) and raw_params.strip():
            try:
                parsed = json.loads(raw_params)
                if isinstance(parsed, dict):
                    model_parameters = parsed
            except Exception:
                return jsonify({"error": "model_parameters must be valid JSON object"}), 400

        model_id = llm_store.add_model(
            user_id=_llm_user_id(),
            model_name=model_name,
            model_type=model_type,
            api_endpoint=data.get("api_endpoint"),
            api_key=data.get("api_key"),
            model_parameters=model_parameters,
        )
        llm_store.log_activity(_llm_user_id(), "create_model", "model", model_id, {"model_name": model_name, "model_type": model_type})
        return jsonify({"model_id": model_id, "status": "created"}), 201
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/llm/models', methods=['GET'])
@login_required
def list_llm_models():
    try:
        rows = llm_store.list_models(_llm_user_id())
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/llm/scan', methods=['POST'])
@login_required
@secure_post
@role_required("admin", "org_admin")
def start_llm_scan():
    try:
        data = request.json or {}
        model_id = data.get("model_id")
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        model = llm_store.get_model(model_id, _llm_user_id())
        if not model:
            return jsonify({"error": "Model not found"}), 404

        scan_id = llm_store.create_scan(model_id)
        _set_llm_scan_state(scan_id, 0, "Starting", status="in_progress")
        worker = Thread(target=_run_llm_scan_job, args=(scan_id, model), daemon=True)
        worker.start()
        return jsonify({"scan_id": scan_id, "status": "in_progress"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/llm/scan/<scan_id>', methods=['GET'])
@login_required
def get_llm_scan(scan_id):
    scan = llm_store.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    state = llm_scan_state.get(scan_id, {})
    db_status = scan.get("status")
    # Always trust terminal DB states to avoid endless polling loops.
    if db_status in ("completed", "failed"):
        state = {
            "progress": 100,
            "message": "Completed" if db_status == "completed" else "Failed",
            "status": db_status,
        }
        llm_scan_state[scan_id] = state
    return jsonify(
        {
            "scan_id": scan["scan_id"],
            "progress": int(state.get("progress", scan["progress"])),
            "message": state.get("message", ""),
            "status": state.get("status", scan["status"]),
            "vulnerabilities": scan["report_json"].get("vulnerabilities", []),
            "security_score": scan["security_score"],
            "vulnerabilities_count": scan["vulnerabilities_count"],
            "critical_count": scan["critical_count"],
            "high_count": scan["high_count"],
            "medium_count": scan["medium_count"],
            "low_count": scan["low_count"],
        }
    )


@app.route('/api/llm/report/<scan_id>', methods=['GET'])
@login_required
def get_llm_report(scan_id):
    scan = llm_store.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Report not found"}), 404
    fmt = request.args.get("format", "json")
    if fmt == "html":
        return Response(scan.get("report_html") or llm_reporter.build_html(scan), mimetype='text/html')
    if fmt == "pdf":
        pdf_data = llm_reporter.build_pdf(scan)
        return Response(
            pdf_data,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=LLM_Security_Report_{scan_id}.pdf"},
        )
    return jsonify(scan.get("report_json") or {})


@app.route('/api/llm/dashboard', methods=['GET'])
@login_required
def llm_dashboard():
    user_id = _llm_user_id()
    models = llm_store.list_models(user_id)
    scans = llm_store.list_recent_scans(user_id, limit=30)
    vulns = llm_store.list_vulnerabilities(user_id, limit=500)
    total = len(scans)
    avg_score = int(sum(s.get("security_score", 0) for s in scans) / total) if total else 0
    open_items = sum(1 for v in vulns if v.get("status") in ("open", "in_progress"))
    resolved_items = sum(1 for v in vulns if v.get("status") in ("resolved", "verified", "fixed"))
    remediation_rate = int((resolved_items / max(1, len(vulns))) * 100) if vulns else 0
    critical_open = sum(1 for v in vulns if v.get("severity") == "critical" and v.get("status") in ("open", "in_progress"))
    return jsonify(
        {
            "models_count": len(models),
            "avg_security_score": avg_score,
            "total_scans": total,
            "open_items": open_items,
            "critical_open": critical_open,
            "remediation_rate": remediation_rate,
            "recent_scans": scans,
        }
    )


@app.route('/api/llm/vulnerabilities', methods=['GET'])
@login_required
def llm_vulnerabilities():
    status = request.args.get("status")
    rows = llm_store.list_vulnerabilities(_llm_user_id(), status=status, limit=500)
    return jsonify(rows)


@app.route('/api/llm/vulnerabilities/<vuln_id>', methods=['PATCH'])
@login_required
@secure_post
@role_required("admin")
def patch_llm_vulnerability(vuln_id):
    payload = request.json or {}
    if llm_store.update_vulnerability(vuln_id, payload):
        llm_store.log_activity(_llm_user_id(), "update_vulnerability", "vulnerability", vuln_id, payload)
        return jsonify({"ok": True})
    return jsonify({"error": "vulnerability not found or no valid fields"}), 404


@app.route('/api/llm/vulnerabilities/trending', methods=['GET'])
@login_required
def llm_vuln_trending():
    rows = llm_store.list_recent_scans(_llm_user_id(), limit=30)
    series = [{"date": r.get("scan_date", "")[:10], "open": r.get("vulnerabilities_count", 0)} for r in rows]
    return jsonify({"series": list(reversed(series))})


@app.route('/api/llm/models/<model_id>/rescan', methods=['POST'])
@login_required
@secure_post
@role_required("admin", "org_admin")
def llm_rescan(model_id):
    model = llm_store.get_model(model_id, _llm_user_id())
    if not model:
        return jsonify({"error": "Model not found"}), 404
    scan_id = llm_store.create_scan(model_id)
    _set_llm_scan_state(scan_id, 0, "Starting", status="in_progress")
    worker = Thread(target=_run_llm_scan_job, args=(scan_id, model), daemon=True)
    worker.start()
    llm_store.log_activity(_llm_user_id(), "rescan_model", "model", model_id, {"scan_id": scan_id})
    return jsonify({"scan_id": scan_id, "status": "in_progress"})


@app.route('/api/llm/vulnerabilities/<vuln_id>/assign', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def assign_llm_vulnerability(vuln_id):
    data = request.json or {}
    payload = {
        "assigned_to": data.get("assigned_to"),
        "due_date": data.get("due_date"),
        "jira_ticket": data.get("jira_ticket"),
        "status": data.get("status", "in_progress"),
    }
    if llm_store.update_vulnerability(vuln_id, payload):
        llm_store.log_activity(_llm_user_id(), "assign_vulnerability", "vulnerability", vuln_id, payload)
        return jsonify({"ok": True})
    return jsonify({"error": "vulnerability not found"}), 404


@app.route('/api/llm/vulnerabilities/<vuln_id>/comments', methods=['POST'])
@login_required
@secure_post
def comment_llm_vulnerability(vuln_id):
    data = request.json or {}
    text = (data.get("comment") or "").strip()
    if not text:
        return jsonify({"error": "comment is required"}), 400
    cid = llm_store.add_comment(vuln_id, _llm_user_id(), text)
    llm_store.log_activity(_llm_user_id(), "comment_vulnerability", "vulnerability", vuln_id, {"comment_id": cid})
    return jsonify({"comment_id": cid, "status": "created"}), 201


@app.route('/api/llm/vulnerabilities/<vuln_id>/comments', methods=['GET'])
@login_required
def list_llm_vuln_comments(vuln_id):
    return jsonify(llm_store.list_comments(vuln_id))


@app.route('/api/llm/activity', methods=['GET'])
@login_required
def llm_activity():
    return jsonify(llm_store.list_activity(_llm_user_id(), limit=120))


@app.route('/api/integrations/slack/alert', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def slack_alert():
    payload = request.json or {}
    ok, msg = send_slack_alert(payload, webhook_url=payload.get("webhook_url"))
    if ok:
        llm_store.log_activity(_llm_user_id(), "slack_alert", "integration", "slack", {"summary": payload.get("summary", "")})
        return jsonify({"ok": True, "result": msg})
    return jsonify({"ok": False, "error": msg}), 400


@app.route('/api/llm/report/<scan_id>/email', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def email_llm_report(scan_id):
    scan = llm_store.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Report not found"}), 404
    data = request.json or {}
    recipients = data.get("recipients") or []
    if not isinstance(recipients, list):
        return jsonify({"error": "recipients must be a list"}), 400
    message = data.get("message", "Please find the attached LLM security report summary.")
    html = scan.get("report_html") or llm_reporter.build_html(scan)
    score = scan.get("security_score", 0)
    body = f"SecureScope LLM report\nScan ID: {scan_id}\nScore: {score}/100\n\n{message}"
    ok, msg = send_email_report(recipients=recipients, subject=f"SecureScope LLM Report {scan_id}", body=body, html=html)
    if ok:
        llm_store.log_activity(_llm_user_id(), "email_report", "report", scan_id, {"recipients": recipients})
        return jsonify({"ok": True, "result": msg})
    return jsonify({"ok": False, "error": msg}), 400


@app.route('/api/admin/users', methods=['GET'])
@login_required
def list_admin_users():
    if _is_super_admin():
        return jsonify(llm_store.list_users())
    if session.get("role") in ("org_admin", "admin"):
        org_id = session.get("org_id")
        if not org_id:
            return jsonify([])
        return jsonify(llm_store.list_users(org_id=org_id))
    return jsonify({"error": "Forbidden"}), 403


@app.route('/api/admin/users', methods=['POST'])
@login_required
@secure_post
def create_admin_user():
    payload = request.json or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    role = (payload.get("role") or "viewer").strip()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if _is_super_admin():
        org_id = payload.get("org_id")
    elif session.get("role") == "org_admin":
        org_id = session.get("org_id")
        if role not in ("normal", "viewer"):
            return jsonify({"error": "org_admin can only create normal/viewer users"}), 403
    else:
        return jsonify({"error": "Forbidden"}), 403
    uid = llm_store.create_user(username=username, password=password, role=role, org_id=org_id)
    llm_store.log_activity(_llm_user_id(), "create_user", "user", uid, {"username": username, "role": role})
    return jsonify({"user_id": uid, "status": "created"}), 201


@app.route('/api/admin/users/<user_id>/password', methods=['POST'])
@login_required
@secure_post
def update_admin_user_password(user_id):
    payload = request.json or {}
    new_password = (payload.get("password") or "").strip()
    if len(new_password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    target = llm_store.get_user_by_id(user_id)
    if not target:
        return jsonify({"error": "user not found"}), 404

    actor_role = session.get("role")
    actor_org = session.get("org_id")
    actor_name = (session.get("username") or "").strip()
    target_name = (target.get("username") or "").strip()

    if _is_super_admin():
        pass
    elif actor_role in ("org_admin", "admin"):
        if not actor_org or target.get("org_id") != actor_org:
            return jsonify({"error": "Forbidden for selected user"}), 403
        if target_name in SUPER_ADMINS:
            return jsonify({"error": "Cannot modify super admin account"}), 403
        if actor_role == "admin" and target.get("role") in ("org_admin", "admin") and actor_name != target_name:
            return jsonify({"error": "admin can update only own/admin-level restricted passwords"}), 403
    else:
        return jsonify({"error": "Forbidden"}), 403

    ok = llm_store.update_user_password(user_id, new_password)
    if not ok:
        return jsonify({"error": "password update failed"}), 400
    llm_store.log_activity(_llm_user_id(), "update_user_password", "user", user_id, {"username": target.get("username")})
    return jsonify({"ok": True, "status": "password_updated"})


@app.route('/api/admin/licenses', methods=['GET'])
@login_required
@super_admin_required
def list_admin_licenses():
    return jsonify(llm_store.list_licenses())


@app.route('/api/admin/licenses', methods=['POST'])
@login_required
@secure_post
@super_admin_required
def create_admin_license():
    payload = request.json or {}
    tier = (payload.get("tier", "standard") or "standard").strip()
    max_users = int(payload.get("max_users", 5))
    expires_at = payload.get("expires_at")
    organization_id = (payload.get("organization_id") or "").strip() or None
    org_name = (payload.get("org_name") or "").strip()
    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = (payload.get("admin_password") or "").strip()

    if max_users < 1:
        return jsonify({"error": "max_users must be at least 1"}), 400

    # Flow:
    # 1) existing org id provided -> assign license to that org
    # 2) org fields provided -> create license, create org+org_admin, and link both
    # 3) only license fields -> normal license creation
    try:
        if organization_id:
            lic = llm_store.create_license(
                tier=tier,
                expires_at=expires_at,
                max_users=max_users,
                organization_id=organization_id,
            )
            llm_store.log_activity(_llm_user_id(), "create_license", "license", lic["id"], {"tier": tier, "organization_id": organization_id})
            return jsonify({"status": "created", **lic, "organization_id": organization_id}), 201

        if org_name or admin_username or admin_password:
            if not (org_name and admin_username and admin_password):
                return jsonify({"error": "org_name, admin_username and admin_password are required for auto organization setup"}), 400
            lic = llm_store.create_license(tier=tier, expires_at=expires_at, max_users=max_users, organization_id=None)
            oid = llm_store.create_organization(org_name, admin_username, admin_password, license_id=lic["id"])
            llm_store.link_license_organization(lic["id"], oid)
            llm_store.log_activity(
                _llm_user_id(),
                "create_license_with_org",
                "license",
                lic["id"],
                {"tier": tier, "organization_id": oid, "org_name": org_name, "admin_username": admin_username},
            )
            return jsonify({"status": "created", **lic, "organization_id": oid, "organization_name": org_name, "admin_username": admin_username}), 201

        lic = llm_store.create_license(tier=tier, expires_at=expires_at, max_users=max_users, organization_id=None)
        llm_store.log_activity(_llm_user_id(), "create_license", "license", lic["id"], {"tier": tier})
        return jsonify({"status": "created", **lic}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/organizations', methods=['GET'])
@login_required
def list_admin_orgs():
    if _is_super_admin():
        return jsonify(llm_store.list_organizations())
    if session.get("org_id"):
        rows = [o for o in llm_store.list_organizations() if o.get("id") == session.get("org_id")]
        return jsonify(rows)
    return jsonify([])


@app.route('/api/admin/organizations', methods=['POST'])
@login_required
@secure_post
@super_admin_required
def create_admin_org():
    payload = request.json or {}
    org_name = (payload.get("name") or "").strip()
    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = (payload.get("admin_password") or "").strip()
    if not org_name or not admin_username or not admin_password:
        return jsonify({"error": "name, admin_username, admin_password are required"}), 400
    oid = llm_store.create_organization(org_name, admin_username, admin_password, license_id=payload.get("license_id"))
    llm_store.log_activity(_llm_user_id(), "create_organization", "organization", oid, {"name": org_name})
    return jsonify({"organization_id": oid, "status": "created"}), 201


@app.route('/api/admin/org-license/link', methods=['POST'])
@login_required
@secure_post
@super_admin_required
def admin_link_org_license():
    payload = request.json or {}
    org_id = (payload.get("organization_id") or "").strip()
    license_id = (payload.get("license_id") or "").strip()
    if not org_id or not license_id:
        return jsonify({"error": "organization_id and license_id are required"}), 400
    org_ids = {o.get("id") for o in llm_store.list_organizations()}
    lic_ids = {l.get("id") for l in llm_store.list_licenses()}
    if org_id not in org_ids:
        return jsonify({"error": "organization not found"}), 404
    if license_id not in lic_ids:
        return jsonify({"error": "license not found"}), 404
    llm_store.link_license_organization(license_id=license_id, organization_id=org_id)
    llm_store.log_activity(_llm_user_id(), "link_org_license", "organization", org_id, {"license_id": license_id})
    return jsonify({"ok": True, "organization_id": org_id, "license_id": license_id})


@app.route('/api/admin/org-license/unlink', methods=['POST'])
@login_required
@secure_post
@super_admin_required
def admin_unlink_org_license():
    payload = request.json or {}
    org_id = (payload.get("organization_id") or "").strip() or None
    license_id = (payload.get("license_id") or "").strip() or None
    if not org_id and not license_id:
        return jsonify({"error": "organization_id or license_id is required"}), 400
    llm_store.unlink_license_organization(organization_id=org_id, license_id=license_id)
    llm_store.log_activity(_llm_user_id(), "unlink_org_license", "organization", org_id or "-", {"license_id": license_id})
    return jsonify({"ok": True})


@app.route('/api/llm/remediate', methods=['POST'])
@login_required
@secure_post
@role_required("admin")
def llm_remediate():
    data = request.json or {}
    vulnerability_id = data.get("vulnerability_id")
    action = data.get("action", "mark_fixed")
    if not vulnerability_id:
        return jsonify({"error": "vulnerability_id is required"}), 400
    new_status = "fixed" if action in ("fix", "mark_fixed") else "in_progress"
    ok = llm_store.update_vulnerability_status(vulnerability_id, new_status)
    if not ok:
        return jsonify({"error": "vulnerability not found"}), 404
    return jsonify({"status": "ok", "result": f"vulnerability {new_status}"})

if __name__ == '__main__':
    app.run(debug=False, port=8080)
