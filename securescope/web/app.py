from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    send_file,
    make_response,
    Response,
)
from io import BytesIO
from dotenv import load_dotenv
import os

load_dotenv()
import platform
import socket
import traceback
import secrets
import re
import json
import logging
from html import escape as html_escape
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
from urllib.parse import urlparse, unquote, quote
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from securescope.core.scanner import Scanner
from securescope.core.hardener import SecureHardener
from securescope.core.reporter import Reporter
from securescope.core.utils import detect_platform
from securescope.scanners.llm_scanner import LLMSecurityScanner
from securescope.web.llm_store import LLMStore
from securescope.web.report_generator import LLMReportGenerator
from securescope.integrations.slack import send_slack_alert
from securescope.integrations.email import send_email_report
from securescope.core.compliance.dpdp_2023 import DPDP_2023_FRAMEWORK


# Load Configuration
def load_config():
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "config",
        "settings.yaml",
    )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


config = load_config()

# Initialize Flask
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.secret_key = os.environ.get("SECRET_KEY", "nitechspark-nitesentinel-2026-prod")
app.permanent_session_lifetime = timedelta(
    hours=config.get("web", {}).get("session_timeout_hours", 8)
)

scanner = Scanner()
stored_scan_results = {}
scan_history = {}
scan_events = []
removed_hosts = set()
rate_limit_state = {}
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
db_path = os.environ.get("SECURESCOPE_DB_PATH")
if not db_path:
    db_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "llm_audit.db"
    )
llm_store = LLMStore(db_path)
llm_store.init_db()
from securescope.web.demo_routes import demo_bp
app.register_blueprint(demo_bp)
llm_scan_state = {}
llm_reporter = LLMReportGenerator()

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4")
LLM_API_KEY = os.environ.get("LLM_API_KEY")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
chat_history = {}


def init_llm_client():
    try:
        if LLM_PROVIDER == "openai" and LLM_API_KEY:
            from openai import OpenAI

            return OpenAI(api_key=LLM_API_KEY)
        elif LLM_PROVIDER == "claude" and LLM_API_KEY:
            from anthropic import Anthropic

            return Anthropic(api_key=LLM_API_KEY)
        elif LLM_PROVIDER == "ollama":
            import requests

            return requests
        elif LLM_PROVIDER == "gemini" and LLM_API_KEY:
            import google.generativeai as genai

            genai.configure(api_key=LLM_API_KEY)
            return genai
    except Exception as e:
        print(f"[WARN] LLM client init failed: {e}")
    return None


llm_client = init_llm_client()


def get_security_context():
    from datetime import datetime

    context = {
        "timestamp": datetime.utcnow().isoformat(),
        "findings_total": len(
            [
                f
                for target_data in stored_scan_results.values()
                for f in target_data.get("findings", [])
            ]
        ),
        "targets_total": len(stored_scan_results),
        "critical_findings": 0,
        "high_findings": 0,
        "organizations": len(llm_store.list_organizations()) if llm_store else 0,
        "recent_findings": [],
    }
    for target_data in stored_scan_results.values():
        for finding in target_data.get("findings", []):
            severity = (finding.get("severity") or "").lower()
            if severity == "critical":
                context["critical_findings"] += 1
            elif severity == "high":
                context["high_findings"] += 1
    all_findings = []
    for target_key, target_data in stored_scan_results.items():
        for finding in target_data.get("findings", []):
            all_findings.append(
                {
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "target": target_key,
                    "timestamp": target_data.get("last_scan"),
                }
            )
    context["recent_findings"] = sorted(
        all_findings, key=lambda x: x.get("timestamp") or "", reverse=True
    )[:5]
    return context


def create_system_prompt():
    context = get_security_context()
    return f"""You are NiteSentinel, an AI-powered security assistant for enterprise cybersecurity assessment and remediation.

Current Environment Context:
- Total Targets: {context["targets_total"]}
- Total Findings: {context["findings_total"]}
- Critical Findings: {context["critical_findings"]}
- High Findings: {context["high_findings"]}

Your capabilities:
1. Security Analysis: Analyze findings and provide risk assessment
2. Remediation: Suggest actionable remediation steps
3. Compliance: Map findings to compliance frameworks (CIS, ISO 27001, PCI DSS)
4. Threat Intelligence: Provide context and best practices
5. Recommendations: Prioritize security improvements

Guidelines:
- Be direct and actionable
- Provide step-by-step remediation guidance
- Consider business impact and effort
- Suggest automation where possible
- Always cite relevant compliance controls"""


def query_llm(user_message, user_id):
    try:
        if user_id not in chat_history:
            chat_history[user_id] = []
        chat_history[user_id].append(
            {
                "role": "user",
                "content": user_message,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        messages = []
        for msg in chat_history[user_id][-10:]:
            messages.append({"role": msg["role"], "content": msg["content"]})
        system_prompt = create_system_prompt()
        response_text = ""
        if LLM_PROVIDER == "openai" and llm_client:
            response = llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "system", "content": system_prompt}, *messages],
                temperature=0.7,
                max_tokens=1500,
            )
            response_text = response.choices[0].message.content
        elif LLM_PROVIDER == "claude" and llm_client:
            response = llm_client.messages.create(
                model=LLM_MODEL,
                max_tokens=1500,
                system=system_prompt,
                messages=messages,
            )
            response_text = response.content[0].text
        elif LLM_PROVIDER == "ollama":
            import requests

            try:
                models_resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
                available_models = models_resp.json().get("models", [])
                if not available_models:
                    return "No Ollama models found. Run 'ollama pull mistral' to download a model."
                model_name = LLM_MODEL
                if not any(
                    m.get("name", "").startswith(model_name) for m in available_models
                ):
                    model_name = (
                        available_models[0].get("name", "mistral").split(":")[0]
                    )
                response = requests.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            *messages,
                        ],
                        "stream": False,
                    },
                    timeout=60,
                )
                if response.ok:
                    response_text = (
                        response.json().get("message", {}).get("content", "")
                    )
                else:
                    response_text = f"Ollama error: {response.status_code}"
            except Exception as e:
                response_text = f"Ollama error: {str(e)}"
        elif LLM_PROVIDER == "gemini":
            import google.generativeai as genai

            model = genai.GenerativeModel(LLM_MODEL)
            response = model.generate_content(
                f"{system_prompt}\n\nUser: {user_message}"
            )
            response_text = response.text
        else:
            response_text = "LLM not configured. Please set LLM_PROVIDER and LLM_API_KEY environment variables."
        chat_history[user_id].append(
            {
                "role": "assistant",
                "content": response_text,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        if len(chat_history[user_id]) > 50:
            chat_history[user_id] = chat_history[user_id][-50:]
        print(
            f"[LLM] {user_id} query successful, response length: {len(response_text)}"
        )
        return response_text
    except Exception as e:
        print(f"[ERROR] LLM query failed: {str(e)}")
        return f"Error querying LLM: {str(e)}"


def analyze_finding_with_ai(finding_id):
    try:
        target_key, idx = (
            finding_id.rsplit(":", 1) if ":" in finding_id else (finding_id, 0)
        )
        target_data = stored_scan_results.get(target_key) or {}
        checks = target_data.get("checks") or []
        idx = int(idx) if idx.isdigit() else 0
        if idx >= len(checks):
            return {"error": "Finding not found"}
        finding = checks[idx]
        analysis_prompt = f"""Analyze this security finding and provide:
1. Risk Assessment (CRITICAL/HIGH/MEDIUM/LOW with explanation)
2. Business Impact (what could happen if not fixed)
3. Remediation Steps (step-by-step guide)
4. Estimated Effort (hours)

Finding:
Title: {finding.get("title")}
Severity: {finding.get("severity")}
Category: {finding.get("category")}
Description: {finding.get("details")}

Provide detailed, actionable analysis."""
        system_prompt = create_system_prompt()
        if LLM_PROVIDER == "openai" and llm_client:
            response = llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": analysis_prompt},
                ],
                temperature=0.7,
                max_tokens=2000,
            )
            analysis = response.choices[0].message.content
        else:
            analysis = "Analysis unavailable - LLM not configured"
        return {
            "finding_id": finding_id,
            "analysis": analysis,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        print(f"[ERROR] Finding analysis failed: {str(e)}")
        return {"error": str(e)}


def get_remediation_suggestions(finding_id):
    analysis = analyze_finding_with_ai(finding_id)
    if "error" in analysis:
        return analysis
    return {
        "finding_id": finding_id,
        "suggestions": analysis.get("analysis"),
        "timestamp": datetime.utcnow().isoformat(),
    }


license_organization_map = {}
organization_licenses = {}

SUPER_ADMINS = set(
    (
        os.environ.get(
            "SECURESCOPE_SUPER_ADMINS", "nitechspark,nitechspark_admin"
        ).split(",")
    )
)
FINDING_STATUS_FLOW = (
    "new",
    "reviewed",
    "assigned",
    "in_progress",
    "verification",
    "remediated",
    "closed",
)

user_preferences: dict[str, dict] = {}
currently_scanning: set[str] = set()

finding_remediation: dict[str, dict] = {}

ROLE_PERMISSIONS = {
    "super_admin": {
        "users": ["view", "create", "update", "delete"],
        "licenses": ["view", "create", "update", "delete"],
        "organizations": ["view", "create", "update"],
        "findings": ["view", "update", "close"],
        "targets": ["view", "create", "scan", "delete"],
        "reports": ["view", "create", "export"],
        "compliance": ["view"],
    },
    "org_admin": {
        "users": ["view", "create", "update"],
        "licenses": [],
        "organizations": [],
        "findings": ["view", "update", "close"],
        "targets": ["view", "create", "scan"],
        "reports": ["view", "create", "export"],
        "compliance": ["view"],
    },
    "security_manager": {
        "users": [],
        "licenses": [],
        "organizations": [],
        "findings": ["view", "update", "close"],
        "targets": ["view", "create", "scan"],
        "reports": ["view", "create", "export"],
        "compliance": ["view"],
    },
    "normal_user": {
        "users": [],
        "licenses": [],
        "organizations": [],
        "findings": ["view"],
        "targets": ["view"],
        "reports": ["view"],
        "compliance": ["view"],
    },
    "viewer": {
        "users": [],
        "licenses": [],
        "organizations": [],
        "findings": ["view"],
        "targets": ["view"],
        "reports": ["view"],
        "compliance": ["view"],
    },
}


def get_user_role():
    return session.get("role", "viewer")


def get_org_id():
    return session.get("org_id")


def get_user_id():
    return session.get("user_id")


def check_permission(resource, action):
    role = get_user_role()
    if role not in ROLE_PERMISSIONS:
        return False
    permissions = ROLE_PERMISSIONS.get(role, {})
    resource_perms = permissions.get(resource, [])
    return action in resource_perms


def require_permission(resource, action):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not check_permission(resource, action):
                return jsonify(
                    {
                        "error": "Forbidden",
                        "message": f"You lack permission to {action} {resource}",
                    }
                ), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


def check_org_access(item_org_id):
    role = get_user_role()
    user_org = get_org_id()
    if role == "super_admin":
        return True
    return item_org_id == user_org


def is_super_admin():
    return get_user_role() == "super_admin"


ROLE_MAP = {
    "admin": "admin",
    "super_admin": "super_admin",
    "viewer": "viewer",
    "guest": "guest",
}


def normalize_role(role):
    return ROLE_MAP.get(role, role)


COMPLIANCE_FRAMEWORKS = {
    "cis": {
        "name": "CIS Controls v8",
        "version": "8.0",
        "controls": {
            "CIS-1.1": {
                "title": "Inventory Hardware Assets",
                "domain": "Asset Management",
                "description": "Actively manage (inventory, track, and correct) all IT hardware devices on the network.",
            },
            "CIS-2.1": {
                "title": "Authorized Software",
                "domain": "Software & SaaS Management",
                "description": "Establish an inventory of authorized software on enterprise assets.",
            },
            "CIS-2.3": {
                "title": "Patch Management",
                "domain": "Software & SaaS Management",
                "description": "Address unapproved software by ensuring only authorized software is deployed.",
            },
            "CIS-3.13": {
                "title": "Encrypt Sensitive Data at Rest",
                "domain": "Data Protection",
                "description": "Encrypt sensitive data at rest on servers, applications, and databases.",
            },
        },
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "controls": {
            "A.5.1": {
                "title": "Information Security Policies",
                "domain": "Organizational Controls",
                "description": "Information security policies shall be defined, approved, published, communicated and acknowledged.",
            },
            "A.6.1": {
                "title": "Organization of Information Security",
                "domain": "Organizational Controls",
                "description": "Implement information security governance structures and responsibilities.",
            },
            "A.8.1": {
                "title": "Asset Management",
                "domain": "Technological Controls",
                "description": "Assets associated with information and information processing facilities shall be identified and managed.",
            },
            "A.10.1": {
                "title": "Cryptographic Controls",
                "domain": "Technological Controls",
                "description": "Rules for the effective use of cryptography shall be defined and implemented.",
            },
            "A.12.6": {
                "title": "Technical Vulnerability Management",
                "domain": "Technological Controls",
                "description": "Information about technical vulnerabilities shall be obtained and exposures addressed.",
            },
        },
    },
    "pci-dss": {
        "name": "PCI DSS v4.0",
        "version": "4.0",
        "controls": {
            "PCI-1": {
                "title": "Firewall Configuration Standards",
                "domain": "Network Security",
                "description": "Firewall and router configuration standards shall be defined and implemented.",
            },
            "PCI-2": {
                "title": "Default Passwords and Security Parameters",
                "domain": "Default Security Parameters",
                "description": "Always change default passwords and remove unnecessary accounts.",
            },
            "PCI-4": {
                "title": "Protect Cardholder Data in Transit",
                "domain": "Data Protection",
                "description": "Strong cryptography and security protocols shall protect cardholder data in transit.",
            },
            "PCI-6": {
                "title": "Secure Systems and Applications",
                "domain": "Secure Development",
                "description": "Develop and maintain secure systems and software, including patch management.",
            },
        },
    },
    "dpdp_2023": DPDP_2023_FRAMEWORK,
}

FINDING_TO_CONTROL_MAP = {
    "default_password": {
        "cis": ["CIS-1.1"],
        "iso27001": ["A.5.1"],
        "pci-dss": ["PCI-2"],
        "dpdp_2023": ["DPDP-8.5"],
    },
    "weak_encryption": {
        "cis": ["CIS-3.13"],
        "iso27001": ["A.10.1"],
        "pci-dss": ["PCI-4"],
        "dpdp_2023": ["DPDP-8.5"],
    },
    "exposed_service": {
        "cis": ["CIS-1.1"],
        "iso27001": ["A.8.1"],
        "pci-dss": ["PCI-1"],
        "dpdp_2023": ["DPDP-8.5"],
    },
    "missing_patch": {
        "cis": ["CIS-2.3"],
        "iso27001": ["A.12.6"],
        "pci-dss": ["PCI-6"],
        "dpdp_2023": ["DPDP-8.5"],
    },
}


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
    parsed = urlparse(
        value if value.startswith(("http://", "https://")) else f"https://{value}"
    )
    return bool(parsed.netloc)


def _allowed_users():
    auth = config.get("web", {}).get("auth", {})
    users = auth.get("users", []) or []
    if not users:
        return [
            {
                "username": auth.get("username", "nitechspark"),
                "password": auth.get("password", "NiteSentinel@2026"),
                "role": "super_admin",
            }
        ]
    # Backward-compatible: always accept legacy username/password too.
    legacy_user = auth.get("username", "nitechspark")
    legacy_pass = auth.get("password", "NiteSentinel@2026")
    users.append(
        {
            "username": legacy_user,
            "password": legacy_pass,
            "role": "super_admin",
        }
    )
    # Also support 'nitechspark' as standard fallback
    if legacy_user != "nitechspark":
        users.append(
            {
                "username": "nitechspark",
                "password": "NiteSentinel@2026",
                "role": "super_admin",
            }
        )
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
        mapping += ["CIS", "NIST", "DPDP"]
    if any(x in name for x in ("firewall", "port", "smb")):
        mapping += ["CIS", "PCI", "NIST", "DPDP"]
    if any(x in name for x in ("password", "guest", "admin")):
        mapping += ["ISO", "CIS", "NIST", "DPDP"]
    if not mapping:
        mapping = ["ISO", "DPDP"]
    return list(dict.fromkeys(mapping))


def _severity_rank(sev):
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get((sev or "").lower(), 0)


def _normalize_severity(check):
    status = (check.get("status") or "").upper()
    sev = (check.get("severity") or "").lower()
    if sev:
        return sev
    if status == "FAIL":
        return "high"
    if status == "WARNING":
        return "medium"
    return "low"


def _build_finding_id(target_key, idx):
    return f"{target_key}:{idx}"


def _extract_findings():
    findings = []
    org_filter_val = org_filter()
    for target_key, data in stored_scan_results.items():
        if org_filter_val and data.get("org_id") != org_filter_val:
            continue
        checks = data.get("checks") or []
        target = data.get("target") or data.get("hostname") or target_key
        last_scan = data.get("last_scan")
        for idx, check in enumerate(checks):
            status = (check.get("status") or "WARNING").upper()
            severity = _normalize_severity(check)
            findings.append(
                {
                    "id": _build_finding_id(target_key, idx),
                    "target_key": target_key,
                    "target": target,
                    "title": check.get("check", "Unknown check"),
                    "category": check.get("category", "General"),
                    "status": check.get("workflow_status", "new"),
                    "scan_status": status,
                    "severity": severity,
                    "details": check.get("details", ""),
                    "frameworks": check.get("frameworks")
                    or _frameworks_for_check(check.get("check")),
                    "assigned_to": check.get("assigned_to"),
                    "reviewed": bool(check.get("reviewed", False)),
                    "last_scan": last_scan,
                }
            )
    return findings


def _finding_compliance_keys(finding: dict) -> set[str]:
    """Map scanner finding text to FINDING_TO_CONTROL_MAP keys."""
    blob = f"{finding.get('category', '')} {finding.get('title', '')} {finding.get('details', '')}".lower()
    keys: set[str] = set()
    if any(x in blob for x in ("password", "guest", "default account", "credential")):
        keys.add("default_password")
    if any(x in blob for x in ("tls", "ssl", "encrypt", "cipher", "https")):
        keys.add("weak_encryption")
    if any(x in blob for x in ("firewall", "ufw", "port", "smb", "exposed", "network")):
        keys.add("exposed_service")
    if any(x in blob for x in ("patch", "update", "cve", "version", "vulnerabilit")):
        keys.add("missing_patch")
    return keys


def _finding_visible_for_session_org(finding: dict) -> bool:
    tk = finding.get("target_key")
    row = stored_scan_results.get(tk) if tk else None
    if not row:
        return True
    return _target_visible_for_org(row)


def _remediation_deadline_for_finding(finding_id: str) -> str | None:
    rec = finding_remediation.get(finding_id) or {}
    return rec.get("deadline")


def _findings_mapped_to_control(
    framework: str, control_id: str, org_id: str | None
) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for map_key, fmapping in FINDING_TO_CONTROL_MAP.items():
        if control_id not in fmapping.get(framework, []):
            continue
        for f in _extract_findings():
            if not _finding_visible_for_session_org(f):
                continue
            if map_key not in _finding_compliance_keys(f):
                continue
            fid = f.get("id")
            if not fid or fid in seen:
                continue
            seen.add(fid)
            out.append(
                {
                    "id": fid,
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "status": f.get("status", "new"),
                    "remediation_deadline": _remediation_deadline_for_finding(fid),
                }
            )
    return out


def _control_status_from_findings(mapped: list[dict]) -> str:
    if not mapped:
        return "na"
    terminal = {"closed", "remediated"}
    if all((x.get("status") or "").lower() in terminal for x in mapped):
        return "compliant"
    if any((x.get("status") or "").lower() in ("new", "reviewed") for x in mapped):
        return "non_compliant"
    return "in_progress"


def _compliance_payload(framework: str, org_id: str | None) -> dict:
    if framework not in COMPLIANCE_FRAMEWORKS:
        return {}
    framework_data = COMPLIANCE_FRAMEWORKS[framework]
    controls_def = framework_data["controls"]
    control_status: dict = {}
    for control_id, control_info in controls_def.items():
        mapped_findings = _findings_mapped_to_control(framework, control_id, org_id)
        status = _control_status_from_findings(mapped_findings)
        control_status[control_id] = {
            "control_id": control_id,
            "title": control_info["title"],
            "domain": control_info["domain"],
            "status": status,
            "mapped_findings_count": len(mapped_findings),
            "remediated_count": sum(
                1
                for f in mapped_findings
                if (f.get("status") or "").lower() in ("closed", "remediated")
            ),
            "findings": mapped_findings[:5],
        }
    statuses = [v["status"] for v in control_status.values() if v["status"] != "na"]
    compliant_count = sum(1 for s in statuses if s == "compliant")
    compliance_pct = (compliant_count / len(statuses) * 100) if statuses else 0.0
    return {
        "framework": framework,
        "framework_name": framework_data["name"],
        "compliance_percentage": round(compliance_pct, 1),
        "total_controls": len(controls_def),
        "compliant_controls": compliant_count,
        "non_compliant_controls": len([s for s in statuses if s == "non_compliant"]),
        "in_progress_controls": len([s for s in statuses if s == "in_progress"]),
        "na_controls": len([v for v in control_status.values() if v["status"] == "na"]),
        "controls": control_status,
    }


def _parse_finding_row(finding_id: str) -> tuple[str | None, int | None]:
    if ":" not in finding_id:
        return None, None
    target_key, raw_idx = finding_id.rsplit(":", 1)
    try:
        return target_key, int(raw_idx)
    except ValueError:
        return None, None


def _read_check_workflow_status(finding_id: str) -> str | None:
    target_key, idx = _parse_finding_row(finding_id)
    if target_key is None or idx is None:
        return None
    row = stored_scan_results.get(target_key) or {}
    checks = row.get("checks") or []
    if idx < 0 or idx >= len(checks):
        return None
    return (
        checks[idx].get("workflow_status") or checks[idx].get("status") or "new"
    ) or "new"


def _workflow_to_remediation_status(wf: str | None) -> str:
    w = (wf or "new").lower()
    if w in ("closed", "remediated"):
        return "closed"
    if w == "verification":
        return "verification"
    if w in ("assigned", "in_progress"):
        return "in_progress"
    return "not_started"


def _prefs_user_key() -> str | None:
    return session.get("user_id") or session.get("username")


def _default_user_preferences() -> dict:
    return {"theme": "dark", "language": "en", "notifications": True}


def has_permission(_org_id, perm: str) -> bool:
    if app.config.get("TESTING") and "role" not in session:
        role = "super_admin"
    else:
        role = session.get("role", "viewer")

    # Permission matrix
    PERMISSIONS = {
        "super_admin": [
            "user_create",
            "user_view",
            "user_update",
            "user_delete",
            "license_view",
            "license_create",
            "license_update",
            "license_delete",
            "org_view",
            "org_create",
            "org_update",
            "finding_view",
            "finding_update",
            "finding_close",
            "target_view",
            "target_create",
            "target_scan",
            "target_delete",
            "report_create",
            "report_view",
            "report_export",
            "compliance_view",
            "settings_view",
            "settings_edit",
        ],
        "org_admin": [
            "user_create",
            "user_view",
            "user_update",  # org-scoped
            "finding_view",
            "finding_update",
            "finding_close",
            "target_view",
            "target_create",
            "target_scan",
            "report_create",
            "report_view",
            "report_export",
            "compliance_view",
            "settings_view",
            "settings_edit",  # org-scoped
        ],
        "security_manager": [
            "finding_view",
            "finding_update",
            "finding_close",
            "target_view",
            "target_create",
            "target_scan",
            "report_create",
            "report_view",
            "report_export",
            "compliance_view",
            "remediation_view",
            "remediation_update",
        ],
        "normal_user": [
            "finding_view",  # assigned only
            "finding_update",  # status/comments only
            "target_view",  # read-only
            "report_view",  # own reports
            "compliance_view",  # read-only
        ],
        "admin": [
            "user_create",
            "user_view",
            "user_update",
            "finding_view",
            "finding_update",
            "finding_close",
            "target_view",
            "target_create",
            "target_scan",
            "report_create",
            "report_view",
            "report_export",
            "compliance_view",
            "settings_view",
            "settings_edit",
            "llm_use",
            "llm_view",
        ],
        "viewer": [
            "finding_view",  # summary only
            "target_view",  # summary only
            "report_view",  # view only
            "compliance_view",  # read-only
        ],
        "guest": [
            "finding_view",
            "target_view",
            "compliance_view",
        ],
    }

    return perm in PERMISSIONS.get(role, [])


def require_permission(permission):
    """Decorator: abort 403 if user lacks permission."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not has_permission(session.get("org_id"), permission):
                return jsonify({"error": "Forbidden: insufficient permissions"}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


def org_filter():
    """Return org_id filter for current user. Returns None if super_admin."""
    if session.get("role") == "super_admin":
        return None  # No filter, see all
    return session.get("org_id")  # Filter by user's org


def _target_visible_for_org(target_data: dict) -> bool:
    oid = session.get("org_id")
    if not oid:
        return True
    t_org = target_data.get("org_id")
    if t_org is None:
        return True
    return t_org == oid


def get_target_compliance_score(target_key: str) -> int:
    row = stored_scan_results.get(target_key) or {}
    return int(row.get("score", 0))


def get_target_last_scan_time(target_key: str) -> str | None:
    row = stored_scan_results.get(target_key) or {}
    v = row.get("last_scan")
    return str(v) if v else None


def _parse_last_scan_ts(timestamp_str: str | None) -> datetime | None:
    if not timestamp_str:
        return None
    s = str(timestamp_str).strip()
    try:
        return datetime.strptime(s, "%d %b %Y %H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00").split("+")[0])
    except ValueError:
        return None


def is_recent(timestamp_str: str | None, hours: int = 24) -> bool:
    ts = _parse_last_scan_ts(timestamp_str)
    if not ts:
        return False
    return datetime.now() - ts < timedelta(hours=hours)


def determine_target_status(target_key: str, last_scan_time: str | None) -> str:
    if target_key in currently_scanning:
        return "scanning"
    if not last_scan_time:
        return "offline"
    if is_recent(last_scan_time, hours=24):
        return "online"
    return "offline"


def count_findings_by_target(target_key: str, severity: str | None = None) -> int:
    n = 0
    for f in _extract_findings():
        if f.get("target_key") != target_key:
            continue
        if severity and (f.get("severity") or "").lower() != severity.lower():
            continue
        n += 1
    return n


def _normalize_os_family(os_raw: str | None) -> str:
    o = (os_raw or "").lower()
    if "windows" in o or "winrm" in o:
        return "windows"
    if "linux" in o or "ssh" in o:
        return "linux"
    if "mac" in o or "darwin" in o:
        return "macos"
    return "other"


def _run_target_scan_job(target_key: str, org_id) -> None:
    try:
        res = None
        if target_key == "localhost":
            data = scanner.scan_local()
            plat_info = detect_platform()
            hostname = socket.gethostname()
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = "127.0.0.1"
            is_admin = False
            try:
                import ctypes

                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                pass
            checks = data["checks"]
            for c in checks:
                c["frameworks"] = _frameworks_for_check(c.get("check"))
            res = {
                "score": data["score"],
                "failed": data["failed"],
                "passed": data["passed"],
                "warnings": data["warnings"],
                "hostname": hostname,
                "ip_address": ip_address,
                "os": plat_info["os"],
                "is_admin": is_admin,
                "kernel": platform.version(),
                "platform": "WSL" if plat_info["is_wsl"] else "Native",
                "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
                "checks": checks,
                "org": config.get("branding", {}).get(
                    "organization_name", "NiTechSpark"
                ),
                "org_id": org_id,
            }
        elif target_key.startswith("web-"):
            url = target_key[len("web-") :]
            data = scanner.scan_web(url)
            res = {
                "score": data["score"],
                "failed": data["failed"],
                "passed": data["passed"],
                "warnings": data["warnings"],
                "hostname": url,
                "target": url,
                "os": "Web Scan",
                "checks": data["checks"],
                "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
                "platform": "Web Scan",
                "org_id": org_id,
            }
            for c in res["checks"]:
                c["frameworks"] = _frameworks_for_check(c.get("check"))
        elif target_key.startswith("ports-"):
            host = target_key[len("ports-") :]
            data = scanner.scan_ports(host)
            res = {
                "score": data["score"],
                "failed": data["failed"],
                "passed": data["passed"],
                "warnings": data["warnings"],
                "hostname": host,
                "target": host,
                "os": "Port Scan",
                "checks": data["checks"],
                "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
                "platform": "Port Scan",
                "org_id": org_id,
            }
            for c in res["checks"]:
                c["frameworks"] = _frameworks_for_check(c.get("check"))
        if res is None:
            return
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)
        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(target_key, res.get("checks") or [])
    except Exception:
        traceback.print_exc()
    finally:
        currently_scanning.discard(target_key)


def _apply_finding_update(finding_id, payload):
    if ":" not in finding_id:
        return False
    # target_key may contain ':' (e.g. web-https://host/...) — split from the right
    target_key, raw_idx = finding_id.rsplit(":", 1)
    if target_key not in stored_scan_results:
        return False
    try:
        idx = int(raw_idx)
    except ValueError:
        return False
    checks = stored_scan_results[target_key].get("checks") or []
    if idx < 0 or idx >= len(checks):
        return False
    check = checks[idx]
    if "reviewed" in payload:
        check["reviewed"] = bool(payload["reviewed"])
    if "assigned_to" in payload:
        check["assigned_to"] = payload["assigned_to"]
    if "status" in payload and payload["status"] in FINDING_STATUS_FLOW:
        check["workflow_status"] = payload["status"]
    return True


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
    vuln_html = (
        "".join(
            (
                f"<li><b>{v.get('severity', 'low').upper()}</b> - {v.get('type', 'unknown')}: "
                f"{v.get('description', 'No description')}<br><i>Remediation:</i> {v.get('remediation', 'N/A')}</li>"
            )
            for v in vulnerabilities
        )
        or "<li>No vulnerabilities found.</li>"
    )
    compliance = data.get("compliance_status", {})
    compliance_html = (
        "".join(
            f"<li><b>{k}</b>: {(v or {}).get('status', 'partial')}</li>"
            for k, v in compliance.items()
        )
        or "<li>No compliance mapping available.</li>"
    )
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>NiteSentinel LLM Report</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; background: #071124; color: #e8f0ff; }}
        .header {{ display: flex; align-items: center; gap: 12px; background: #10213d; color: #fff; padding: 16px 24px; }}
        .logo {{ height: 38px; width: auto; }}
        .wrap {{ padding: 24px; }}
        .score {{ font-size: 42px; font-weight: 700; color: {score_color}; }}
        .box {{ background: rgba(15, 25, 52, 0.95); border: 1px solid rgba(109, 132, 255, 0.22); border-radius: 10px; padding: 16px; margin-bottom: 16px; color: #e8f0ff; }}
      </style>
    </head>
    <body>
      <div class="header">
        <img src="/static/img/nitesentinel-logo.png" class="logo" alt="NiteSentinel logo" />
        <div>
          <div style="font-size:20px;font-weight:700;">NiteSentinel</div>
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


def _set_llm_scan_state(
    scan_id: str, progress: int, message: str, status: str = "in_progress"
) -> None:
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
        report = scanner.scan_all(
            on_progress=lambda p, m: _set_llm_scan_state(scan_id, p, m)
        )
        report["model_name"] = model.get("model_name")
        html_report = llm_reporter.build_html(
            {
                "scan_id": scan_id,
                "security_score": report.get("security_score"),
                "report_json": report,
            }
        )
        llm_store.complete_scan(scan_id, report, html_report)
        _set_llm_scan_state(scan_id, 100, "Completed", status="completed")
    except Exception as exc:
        llm_store.fail_scan(scan_id, str(exc))
        _set_llm_scan_state(scan_id, 100, f"Failed: {exc}", status="failed")


# --- Authentication ---
def _login_or_api_unauthorized():
    """Browser navigation gets a redirect; XHR/fetch to /api/* gets JSON so the UI can show a clear error."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not authenticated"}), 401
    return redirect(url_for("login"))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if app.config.get("TESTING"):
            return f(*args, **kwargs)
        if config["web"]["auth"]["enabled"] and not session.get("logged_in"):
            return _login_or_api_unauthorized()
        session.permanent = True
        now_ts = datetime.utcnow().timestamp()
        if session.get("demo_session"):
            if now_ts > session.get("demo_expiry", 0):
                session.clear()
                return _login_or_api_unauthorized()
        # Do not treat missing last_seen as epoch 0 — that would instantly expire every session.
        if "last_seen" in session:
            try:
                if (
                    now_ts - float(session["last_seen"])
                    > app.permanent_session_lifetime.total_seconds()
                ):
                    session.clear()
                    return _login_or_api_unauthorized()
            except (TypeError, ValueError):
                session["last_seen"] = now_ts
        session["last_seen"] = now_ts
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def inner(*args, **kwargs):
            if app.config.get("TESTING"):
                return f(*args, **kwargs)
            current_role = session.get("role")
            print(
                f"[DEBUG role_required] User role: {current_role}, Required roles: {roles}"
            )
            if current_role not in roles:
                print(
                    f"[DEBUG role_required] FAIL - role {current_role} not in {roles}"
                )
                return jsonify({"error": "Forbidden for current role"}), 403
            return f(*args, **kwargs)

        return inner

    return deco


def super_admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if app.config.get("TESTING"):
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
        if session.get("demo_session"):
            if request.path.startswith("/api/") or request.headers.get("Content-Type") == "application/json":
                return jsonify({"error": "Forbidden: write operations are not allowed in demo mode."}), 403
            from flask import flash
            flash("Write operations are not allowed in demo mode.", "warning")
            return redirect(url_for("dashboard"))
        token = request.headers.get("X-CSRF-Token")
        if token != session.get("csrf_token"):
            return jsonify({"error": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)

    return inner


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db_user = llm_store.authenticate_user(username, password)
        if db_user:
            session.clear()
            session["logged_in"] = True
            session["username"] = db_user["username"]
            session["user_id"] = db_user.get("id")
            session["role"] = normalize_role(db_user.get("role", "viewer"))
            session["org_id"] = db_user.get("org_id")
            session["last_seen"] = datetime.utcnow().timestamp()
            _csrf_token()
            return redirect(url_for("dashboard"))
        for user in _allowed_users():
            if username == user.get("username") and password == user.get("password"):
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["user_id"] = username
                session["role"] = normalize_role(user.get("role", "viewer"))
                session["org_id"] = None
                session["last_seen"] = datetime.utcnow().timestamp()
                _csrf_token()
                return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    plat_info = detect_platform()
    demo_mode = bool(app.config.get("DEMO_MODE"))
    return render_template(
        "dashboard.html",
        plat_info=plat_info,
        csrf_token=_csrf_token(),
        username=session.get("username", "operator"),
        role=session.get("role", "viewer"),
        is_super_admin=_is_super_admin(),
        org_name=config.get("branding", {}).get("organization_name", "NiTechSpark"),
        client_name=config.get("branding", {}).get("client_name", "Default Client"),
        demo_mode=demo_mode,
        stored_scan_results_json=json.dumps(stored_scan_results),
    )


@app.route("/logo.png")
def serve_logo():
    logo_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "logo.png",
    )
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype="image/png")
    return "", 404


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/api/scan/remote", methods=["POST"])
@login_required
@secure_post
def api_scan_remote():
    try:
        req_data = request.json
        host = (req_data.get("host") or "").strip()
        user = req_data.get("username")
        password = req_data.get("password")
        target_type = req_data.get("type", "linux")
        port = req_data.get("port", 22)
        if not _validate_host(host):
            return jsonify({"error": "Invalid host format"}), 400

        data = scanner.scan_remote(
            host=host,
            user=user,
            password=password,
            target_type=target_type,
            port=int(port),
        )

        res = {
            "score": data["score"],
            "failed": data["failed"],
            "passed": data["passed"],
            "warnings": data["warnings"],
            "hostname": host,
            "target": host,
            "os": data.get("os", target_type.title()),
            "checks": data["checks"],
            "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
            "platform": "Remote",
            "org_id": session.get("org_id"),
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
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/remove", methods=["POST"])
@login_required
@secure_post
def api_targets_remove():
    try:
        data = request.json or {}
        host = (data.get("host") or "").strip()
        if host:
            if host in stored_scan_results:
                del stored_scan_results[host]
            if host in scan_history:
                del scan_history[host]
            removed_hosts.add(host)
        return jsonify({"status": "removed", "host": host})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/ports", methods=["POST"])
@login_required
@secure_post
def api_scan_ports():
    """Port scanning endpoint."""
    try:
        req_data = request.json
        host = req_data.get("host", "localhost")
        if not _validate_host(host):
            return jsonify({"error": "Invalid host format"}), 400

        if host == "localhost" or host == "127.0.0.1":
            try:
                host = socket.gethostbyname(socket.gethostname())
            except Exception:
                host = "127.0.0.1"

        data = scanner.scan_ports(host)

        res = {
            "score": data["score"],
            "failed": data["failed"],
            "passed": data["passed"],
            "warnings": data["warnings"],
            "hostname": host,
            "target": host,
            "os": "Port Scan",
            "checks": data["checks"],
            "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
            "platform": "Port Scan",
            "org_id": session.get("org_id"),
        }
        for c in res["checks"]:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        target_key = f"ports-{host}"
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)

        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(host, res["checks"])
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/web", methods=["POST"])
@login_required
@secure_post
def api_scan_web():
    """Web security scanning endpoint."""
    try:
        req_data = request.json
        url = req_data.get("url", "")

        if not url:
            return jsonify({"error": "URL is required"}), 400
        if not _validate_url(url):
            return jsonify({"error": "Invalid URL"}), 400

        data = scanner.scan_web(url)

        res = {
            "score": data["score"],
            "failed": data["failed"],
            "passed": data["passed"],
            "warnings": data["warnings"],
            "hostname": url,
            "target": url,
            "os": "Web Scan",
            "checks": data["checks"],
            "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
            "platform": "Web Scan",
            "org_id": session.get("org_id"),
        }
        for c in res["checks"]:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        target_key = f"web-{url}"
        if target_key in removed_hosts:
            removed_hosts.discard(target_key)

        stored_scan_results[target_key] = res
        _record_scan(target_key, res["score"])
        _add_events(url, res["checks"])
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/local")
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
        "checks": results["checks"],
        "score": results["score"],
        "hostname": hostname,
        "os": plat_info["os"],
        "kernel": platform.version(),
        "ip_address": ip_address,
    }

    reporter = Reporter()
    org = config.get("branding", {}).get("organization_name", "NiTechSpark")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        content = reporter.generate_html(report_data, org=org)
        f.write(content)
        tmp_path = f.name
    return send_file(
        tmp_path,
        as_attachment=True,
        download_name="NiTechSpark_Security_Report.html",
        mimetype="text/html",
    )


@app.route("/api/report/remote")
@login_required
def report_remote():
    host = request.args.get("host", "unknown")
    results = stored_scan_results.get(host)
    if not results:
        return jsonify({"error": f"No scan data for {host}"}), 404
    reporter = Reporter()
    html = reporter.generate(results, org="NiTechSpark")
    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f"attachment; filename=NiTechSpark_{host}_Report.html"
        },
    )


@app.route("/api/harden", methods=["POST"])
@login_required
@secure_post
@role_required("admin")
def harden():
    data = request.json
    results = data.get("results", data.get("checks", []))

    # Retrieve connection params sent by frontend for remote fixes
    host = data.get("host", "localhost")
    target_type = data.get("type")
    username = data.get("username")
    password = data.get("password")
    port = data.get("port", 22)

    hardener = SecureHardener(
        auto_confirm=True,
        target_host=host,
        target_port=port,
        username=username,
        password=password,
        target_type=target_type,
    )
    harden_log = hardener.apply_fixes(results)
    return jsonify({"log": harden_log})


@app.route("/api/scan/local", methods=["GET"])
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

        checks = data["checks"]
        for c in checks:
            c["frameworks"] = _frameworks_for_check(c.get("check"))

        res = {
            "score": data["score"],
            "failed": data["failed"],
            "passed": data["passed"],
            "warnings": data["warnings"],
            "hostname": hostname,
            "ip_address": ip_address,
            "os": plat_info["os"],
            "is_admin": is_admin,
            "kernel": platform.version(),
            "platform": "WSL" if plat_info["is_wsl"] else "Native",
            "last_scan": datetime.now().strftime("%d %b %Y %H:%M:%S"),
            "checks": checks,
            "org": config.get("branding", {}).get("organization_name", "NiTechSpark"),
            "org_id": session.get("org_id"),
        }
        stored_scan_results["localhost"] = res
        _record_scan("localhost", res["score"])
        _add_events(hostname, checks)
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/feed")
@login_required
def api_feed():
    return jsonify(
        {
            "events": scan_events[-50:],
            "history": scan_history,
            "csrf_token": _csrf_token(),
        }
    )


@app.route("/api/dashboard/kpis")
@login_required
def dashboard_kpis():
    findings = _extract_findings()
    total_targets = len(stored_scan_results)
    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    remediated = sum(1 for f in findings if f["status"] in ("remediated", "closed"))
    remediation_rate = (
        int((remediated / max(1, len(findings))) * 100) if findings else 0
    )
    scores = [int(v.get("score", 0)) for v in stored_scan_results.values()]
    avg_score = int(sum(scores) / len(scores)) if scores else 0
    trend = []
    for host, points in scan_history.items():
        for p in points[-3:]:
            trend.append(
                {"target": host, "time": p.get("time"), "score": int(p.get("score", 0))}
            )
    trend = sorted(trend, key=lambda x: x["time"] or "")[-30:]
    return jsonify(
        {
            "total_targets_scanned": total_targets,
            "critical_vulnerabilities": critical_count,
            "remediation_rate": remediation_rate,
            "compliance_score_avg": avg_score,
            "score_trend": trend,
            "llm_health": "healthy"
            if llm_store.list_models(_llm_user_id())
            else "not_configured",
        }
    )


@app.route("/api/targets")
@login_required
@require_permission("target_view")
def api_targets():
    sort_by = (
        request.args.get("sort") or request.args.get("sort_by") or "name"
    ).lower()
    order = (
        request.args.get("order") or request.args.get("sort_order") or "asc"
    ).lower()
    page = max(1, int(request.args.get("page", 1)))
    page_size = int(request.args.get("page_size") or request.args.get("per_page", 25))
    page_size = min(100, max(1, page_size))
    status_filter = (request.args.get("status") or "").lower() or None
    os_filter = (request.args.get("os") or "").lower() or None
    q = (request.args.get("q") or "").lower().strip()

    all_targets = []
    org_filter_val = org_filter()
    for target_key, target_data in stored_scan_results.items():
        if target_key in removed_hosts:
            continue
        if org_filter_val and target_data.get("org_id") != org_filter_val:
            continue
        compliance_score = get_target_compliance_score(target_key)
        last_scan_time = get_target_last_scan_time(target_key)
        target_status = determine_target_status(target_key, last_scan_time)
        if status_filter and target_status != status_filter:
            continue
        os_type = _normalize_os_family(target_data.get("os"))
        if os_filter and os_type != os_filter:
            continue
        name = (target_data.get("hostname") or target_key) or ""
        ip = target_data.get("ip_address") or target_data.get("target") or ""
        if (
            q
            and q not in name.lower()
            and q not in (ip or "").lower()
            and q not in target_key.lower()
        ):
            continue
        all_targets.append(
            {
                "id": target_key,
                "name": name or target_key,
                "ip": ip,
                "os": target_data.get("os", "Unknown"),
                "status": target_status,
                "compliance_score": compliance_score,
                "last_scan": last_scan_time,
                "findings_count": count_findings_by_target(target_key),
                "critical_count": count_findings_by_target(target_key, "critical"),
                "high_count": count_findings_by_target(target_key, "high"),
                "platform": target_data.get("platform"),
                "removable": True,
            }
        )

    print(
        f"[TARGETS API] Found {len(all_targets)} targets in stored_scan_results (org_filter: {org_filter_val})"
    )

    reverse = order == "desc"
    if sort_by == "score":
        all_targets.sort(key=lambda x: x["compliance_score"], reverse=reverse)
    elif sort_by == "last_scan":
        all_targets.sort(
            key=lambda x: _parse_last_scan_ts(x["last_scan"]) or datetime.min,
            reverse=reverse,
        )
    elif sort_by == "status":
        all_targets.sort(key=lambda x: x["status"], reverse=reverse)
    else:
        all_targets.sort(key=lambda x: (x["name"] or "").lower(), reverse=reverse)

    total = len(all_targets)
    start = (page - 1) * page_size
    end = start + page_size
    page_rows = all_targets[start:end]
    total_pages = (total + page_size - 1) // page_size if page_size else 1

    return jsonify(
        {
            "targets": page_rows,
            "items": page_rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "per_page": page_size,
            "total_pages": total_pages,
        }
    )


@app.route("/api/targets/<path:target_id>/scan", methods=["POST"])
@login_required
@require_permission("target_scan")
def api_scan_target(target_id):
    target_key = unquote(target_id)
    if target_key not in stored_scan_results:
        return jsonify({"error": "Target not found"}), 404

    # Check org access
    org_filter_val = org_filter()
    target_org = stored_scan_results[target_key].get("org_id")
    if org_filter_val and target_org != org_filter_val:
        return jsonify({"error": "Forbidden: target outside your org"}), 403

    if (
        target_key not in ("localhost",)
        and not target_key.startswith("web-")
        and not target_key.startswith("ports-")
    ):
        return jsonify(
            {
                "error": "Server-side rescan is only supported for localhost, web-*, and ports-* targets. "
                "Use Remote Scan from the dashboard for SSH targets."
            }
        ), 400
    org_id = session.get("org_id")
    currently_scanning.add(target_key)
    worker = Thread(target=_run_target_scan_job, args=(target_key, org_id), daemon=True)
    worker.start()
    return jsonify(
        {"message": "Scan queued", "target_id": target_id, "status": "scanning"}
    )


@app.route("/api/preferences", methods=["GET"])
@login_required
def api_get_preferences():
    uid = _prefs_user_key()
    if not uid:
        return jsonify({"error": "Not authenticated"}), 401
    prefs = {**_default_user_preferences(), **user_preferences.get(uid, {})}
    return jsonify(prefs)


@app.route("/api/preferences", methods=["POST"])
@login_required
def api_set_preferences():
    uid = _prefs_user_key()
    if not uid:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json() or {}
    merged = {**_default_user_preferences(), **user_preferences.get(uid, {}), **data}
    user_preferences[uid] = merged
    return jsonify({"message": "Preferences updated", "preferences": merged})


@app.route("/targets")
@login_required
def targets_page():
    plat_info = detect_platform()
    demo_mode = bool(app.config.get("DEMO_MODE"))
    return render_template(
        "targets.html",
        plat_info=plat_info,
        csrf_token=_csrf_token(),
        username=session.get("username", "operator"),
        role=session.get("role", "viewer"),
        is_super_admin=_is_super_admin(),
        org_name=config.get("branding", {}).get("organization_name", "NiTechSpark"),
        client_name=config.get("branding", {}).get("client_name", "Default Client"),
        demo_mode=demo_mode,
    )


@app.route("/targets/<path:target_detail_id>")
@login_required
def targets_detail_redirect(target_detail_id):
    return redirect(f"{url_for('index')}?target={quote(target_detail_id, safe='')}")


@app.route("/api/findings")
@login_required
@require_permission("finding_view")
def list_findings():
    severity = (request.args.get("severity") or "").lower()
    status = (request.args.get("status") or "").lower()
    target = (request.args.get("target") or "").lower()
    target_key_exact = (request.args.get("target_key") or "").strip()
    cat = (request.args.get("cat") or "").lower()
    scan_status = (request.args.get("scan_status") or "").upper()
    q = (request.args.get("q") or "").lower()
    sort_by = (request.args.get("sort_by") or "severity").lower()
    sort_order = (request.args.get("sort_order") or "desc").lower()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 25))))

    items = _extract_findings()
    if target_key_exact:
        items = [f for f in items if f.get("target_key") == target_key_exact]
    if severity:
        items = [f for f in items if f["severity"] == severity]
    if status:
        items = [f for f in items if f["status"] == status]
    if scan_status in ("PASS", "FAIL", "WARNING"):
        items = [f for f in items if (f.get("scan_status") or "") == scan_status]
    if cat:
        items = [
            f
            for f in items
            if cat in (f.get("category") or "").lower()
            or cat in (f.get("title") or "").lower()
        ]
    cfw = (request.args.get("compliance_framework") or "").strip()
    cctrl = (request.args.get("compliance_control") or "").strip()
    if cfw and cctrl and cfw in COMPLIANCE_FRAMEWORKS:
        allowed_keys = [
            k for k, fm in FINDING_TO_CONTROL_MAP.items() if cctrl in fm.get(cfw, [])
        ]
        if allowed_keys:
            allow = set(allowed_keys)
            items = [f for f in items if _finding_compliance_keys(f) & allow]
    if target:
        items = [
            f
            for f in items
            if target in (f["target"] or "").lower()
            or target in (f.get("target_key") or "").lower()
        ]
    if q:
        items = [
            f
            for f in items
            if q in (f["title"] or "").lower()
            or q in (f["details"] or "").lower()
            or q in (f.get("category") or "").lower()
        ]

    sort_key = {
        "severity": lambda x: _severity_rank(x.get("severity")),
        "status": lambda x: x.get("status") or "",
        "target": lambda x: (x.get("target") or "").lower(),
        "last_scan": lambda x: x.get("last_scan") or "",
        "category": lambda x: (x.get("category") or "").lower(),
        "title": lambda x: (x.get("title") or "").lower(),
    }.get(sort_by, lambda x: _severity_rank(x.get("severity")))
    items = sorted(items, key=sort_key, reverse=(sort_order == "desc"))

    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return jsonify(
        {"items": items[start:end], "page": page, "per_page": per_page, "total": total}
    )


@app.route("/api/findings/bulk", methods=["POST"])
@login_required
@require_permission("finding_update")
def bulk_findings_action():
    payload = request.json or {}
    finding_ids = payload.get("finding_ids") or []
    action = (payload.get("action") or "").strip().lower()
    if not isinstance(finding_ids, list) or not finding_ids:
        return jsonify({"error": "finding_ids is required"}), 400
    updated = 0
    for fid in finding_ids:
        if action == "mark_reviewed":
            ok = _apply_finding_update(fid, {"reviewed": True, "status": "reviewed"})
        elif action == "assign":
            ok = _apply_finding_update(
                fid, {"assigned_to": payload.get("assigned_to"), "status": "assigned"}
            )
        elif action == "close":
            ok = _apply_finding_update(fid, {"status": "closed"})
        else:
            return jsonify({"error": "Unsupported action"}), 400
        if ok:
            updated += 1
    return jsonify(
        {
            "ok": True,
            "updated": updated,
            "requested": len(finding_ids),
            "action": action,
        }
    )


@app.route("/api/frameworks", methods=["GET"])
@login_required
def api_frameworks():
    return jsonify(
        {
            "frameworks": [
                {
                    "id": "cis",
                    "name": COMPLIANCE_FRAMEWORKS["cis"]["name"],
                    "version": COMPLIANCE_FRAMEWORKS["cis"]["version"],
                    "control_count": len(COMPLIANCE_FRAMEWORKS["cis"]["controls"]),
                },
                {
                    "id": "iso27001",
                    "name": COMPLIANCE_FRAMEWORKS["iso27001"]["name"],
                    "version": COMPLIANCE_FRAMEWORKS["iso27001"]["version"],
                    "control_count": len(COMPLIANCE_FRAMEWORKS["iso27001"]["controls"]),
                },
                {
                    "id": "pci-dss",
                    "name": COMPLIANCE_FRAMEWORKS["pci-dss"]["name"],
                    "version": COMPLIANCE_FRAMEWORKS["pci-dss"]["version"],
                    "control_count": len(COMPLIANCE_FRAMEWORKS["pci-dss"]["controls"]),
                },
                {
                    "id": "dpdp_2023",
                    "name": COMPLIANCE_FRAMEWORKS["dpdp_2023"]["name"],
                    "version": COMPLIANCE_FRAMEWORKS["dpdp_2023"]["version"],
                    "control_count": len(COMPLIANCE_FRAMEWORKS["dpdp_2023"]["controls"]),
                },
            ]
        }
    )


@app.route("/api/compliance/<framework>", methods=["GET"])
@login_required
def api_compliance_status(framework):
    if framework not in COMPLIANCE_FRAMEWORKS:
        return jsonify({"error": "Unknown framework"}), 400
    # org_id may be None for legacy/config login — still compute compliance for visible scans
    org_id = session.get("org_id")
    return jsonify(_compliance_payload(framework, org_id))


@app.route("/api/findings/<path:finding_id>/remediation", methods=["GET"])
@login_required
@require_permission("finding_view")
def api_get_remediation(finding_id):
    finding_id = unquote(finding_id)
    wf = _read_check_workflow_status(finding_id)
    base = dict(finding_remediation.get(finding_id) or {})
    if "status" not in base or not base.get("status"):
        base["status"] = _workflow_to_remediation_status(wf)
    base.setdefault("assigned_to", None)
    base.setdefault("deadline", None)
    base.setdefault("comments", [])
    base.setdefault("history", [])
    return jsonify(base)


@app.route("/api/findings/<path:finding_id>/remediation", methods=["POST"])
@login_required
@require_permission("finding_update")
def api_update_remediation(finding_id):
    finding_id = unquote(finding_id)
    user_id = session.get("user_id") or session.get("username") or "anonymous"
    data = request.get_json() or {}
    if finding_id not in finding_remediation:
        finding_remediation[finding_id] = {
            "status": "not_started",
            "assigned_to": None,
            "deadline": None,
            "comments": [],
            "history": [],
        }
    rec = finding_remediation[finding_id]
    if "status" in data and data["status"] in (
        "not_started",
        "in_progress",
        "verification",
        "closed",
    ):
        rec["status"] = data["status"]
        wf_map = {
            "not_started": "new",
            "in_progress": "in_progress",
            "verification": "verification",
            "closed": "closed",
        }
        _apply_finding_update(
            finding_id, {"status": wf_map.get(data["status"], "in_progress")}
        )
    if "assigned_to" in data:
        rec["assigned_to"] = data["assigned_to"]
        _apply_finding_update(finding_id, {"assigned_to": data["assigned_to"]})
    if "deadline" in data:
        rec["deadline"] = data["deadline"]
    if data.get("comment"):
        rec.setdefault("comments", []).append(
            {
                "author": user_id,
                "text": data["comment"],
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    rec.setdefault("history", []).append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "changed_by": user_id,
            "changes": {k: v for k, v in data.items() if k != "comment"},
        }
    )
    return jsonify({"message": "Remediation updated", "remediation": rec})


@app.route("/api/findings/<path:finding_id>/close", methods=["POST"])
@login_required
@require_permission("finding_close")
def api_close_finding(finding_id):
    finding_id = unquote(finding_id)
    data = request.get_json() or {}
    if finding_id not in finding_remediation:
        finding_remediation[finding_id] = {
            "status": "closed",
            "assigned_to": None,
            "deadline": None,
            "comments": [],
            "history": [],
        }
    rec = finding_remediation[finding_id]
    rec["status"] = "closed"
    rec["closed_by"] = user_id
    rec["closed_at"] = datetime.utcnow().isoformat()
    if "evidence" in data:
        rec["evidence"] = data["evidence"]
    rec.setdefault("history", []).append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "changed_by": user_id,
            "changes": {"status": "closed", "evidence": data.get("evidence")},
        }
    )
    _apply_finding_update(finding_id, {"status": "closed"})
    return jsonify({"message": "Finding closed", "remediation": rec})


def generate_findings_report(target_ids: list, org_id: str | None) -> dict:
    findings: list[dict] = []
    for finding in _extract_findings():
        tk = finding.get("target_key")
        scan_result = stored_scan_results.get(tk) or {}
        if org_id and scan_result.get("org_id") not in (None, org_id):
            continue
        if target_ids and tk not in target_ids:
            continue
        findings.append({"target": tk, **finding})

    def _sev_count(level: str) -> int:
        return sum(1 for f in findings if (f.get("severity") or "").lower() == level)

    return {
        "title": "Security Findings Report",
        "generated_at": datetime.utcnow().isoformat(),
        "organization": org_id,
        "total_findings": len(findings),
        "findings_by_severity": {
            "critical": _sev_count("critical"),
            "high": _sev_count("high"),
            "medium": _sev_count("medium"),
            "low": _sev_count("low"),
        },
        "findings": findings,
    }


def generate_compliance_report(
    framework: str, target_ids: list, org_id: str | None
) -> dict:
    if framework not in COMPLIANCE_FRAMEWORKS:
        return {"error": "Unknown framework"}
    comp = _compliance_payload(framework, org_id)
    return {
        "title": f"{comp['framework_name']} Compliance Report",
        "generated_at": datetime.utcnow().isoformat(),
        "organization": org_id,
        "framework": framework,
        "compliance_percentage": comp["compliance_percentage"],
        "summary": {
            "compliant_controls": comp["compliant_controls"],
            "non_compliant_controls": comp["non_compliant_controls"],
            "in_progress_controls": comp["in_progress_controls"],
            "total_controls": comp["total_controls"],
        },
        "controls": comp["controls"],
    }


def generate_executive_report(
    framework: str | None, target_ids: list, org_id: str | None
) -> dict:
    findings_part = generate_findings_report(target_ids, org_id)
    comp_part = (
        _compliance_payload(framework, org_id)
        if framework and framework in COMPLIANCE_FRAMEWORKS
        else None
    )
    return {
        "title": "Executive Security Summary",
        "generated_at": datetime.utcnow().isoformat(),
        "organization": org_id,
        "compliance": comp_part,
        "findings_summary": findings_part["findings_by_severity"],
        "total_findings": findings_part["total_findings"],
        "top_findings": (findings_part.get("findings") or [])[:10],
    }


def _attach_report_branding(report_data: dict, org_id: str | None) -> dict:
    """Add logo URL and human-readable org for HTML/PDF/JSON exports (avoids literal 'None')."""
    out = {**report_data}
    root = (request.url_root or "").rstrip("/")
    brand_org = (config.get("branding", {}) or {}).get(
        "organization_name", "NiTechSpark"
    )
    display = brand_org
    if org_id:
        display = f"{brand_org} (org {org_id})"
    out["organization_display_name"] = display
    out["logo_url"] = f"{root}/static/img/nitesentinel-logo.png"
    out["product_name"] = (config.get("app", {}) or {}).get("name", "NiteSentinel")
    out["client_name"] = (config.get("branding", {}) or {}).get("client_name", "")
    return out


def render_report_html(report_data: dict, report_type: str) -> str:
    title = html_escape(str(report_data.get("title", "Report")))
    org_line = html_escape(
        str(
            report_data.get("organization_display_name")
            or report_data.get("organization")
            or ""
        )
    )
    if org_line in ("None", ""):
        org_line = html_escape(
            str(
                (config.get("branding", {}) or {}).get(
                    "organization_name", "NITECHSPARK"
                )
            )
        )
    logo = html_escape(str(report_data.get("logo_url", "")))
    product = html_escape(str(report_data.get("product_name", "NiteSentinel")))
    gen_at = html_escape(str(report_data.get("generated_at", "")))

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; background: #071124; color: #e8f0ff; }}
    .report-brand {{ display: flex; align-items: center; gap: 18px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid rgba(0, 212, 255, 0.25); }}
    .report-brand img {{ height: 52px; width: auto; max-width: 140px; object-fit: contain; }}
    .report-brand .org {{ font-size: 13px; color: #9fb8d4; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }}
    .report-brand .product {{ font-size: 26px; font-weight: 800; color: #49d1ff; }}
    h1 {{ color: #f8fbff; margin: 0 0 8px 0; font-size: 1.4rem; }}
    h2 {{ color: #cbd5e1; margin-top: 30px; }}
    .summary {{ background: rgba(10, 18, 33, 0.96); padding: 22px; border-radius: 16px; margin: 20px 0; border: 1px solid rgba(0, 212, 255, 0.14); box-shadow: 0 16px 36px rgba(0, 0, 0, 0.24); }}
    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: rgba(10, 18, 33, 0.98); color: #e8f0ff; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.08); vertical-align: top; }}
    th {{ background: rgba(8, 17, 32, 0.95); font-weight: 700; color: #a3b4cc; }}
    tr:nth-child(even) {{ background: rgba(255, 255, 255, 0.03); }}
    .critical {{ color: #f87171; font-weight: 700; }}
    .high {{ color: #fb923c; font-weight: 700; }}
    .medium {{ color: #fbbf24; }}
    .footer {{ margin-top: 40px; border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 20px; font-size: 12px; color: #8ea7cb; }}
    details {{ margin: 4px 0; }}
    details summary {{ cursor: pointer; font-weight: 600; color: #7dd3fc; }}
    details summary::-webkit-details-marker {{ color: #7dd3fc; }}
    .finding-mini {{ font-size: 12px; margin: 4px 0; padding: 10px 12px; border-radius: 10px; background: rgba(255, 255, 255, 0.04); border-left: 3px solid rgba(56, 189, 248, 0.8); }}
  </style>
</head>
<body>
  <div class="report-brand">
    <img src="/static/img/nitesentinel-logo.png" alt="NiteSentinel logo" onerror="this.style.display='none'" />
    <div>
      <div class="product">{product}</div>
    </div>
  </div>
  <h1>{title}</h1>
  <p>Generated: {gen_at}</p>
"""
    if report_type == "compliance" and "controls" in report_data:
        s = report_data.get("summary") or {}
        html += f"""
  <div class="summary">
    <h2>Compliance Summary</h2>
    <p><strong>Overall Compliance:</strong> {report_data.get("compliance_percentage", 0)}%</p>
    <p><strong>Compliant Controls:</strong> {s.get("compliant_controls", 0)} / {s.get("total_controls", 0)}</p>
    <p><strong>Non-Compliant Controls:</strong> {s.get("non_compliant_controls", 0)}</p>
    <p><strong>In Progress:</strong> {s.get("in_progress_controls", 0)}</p>
  </div>
  <h2>Control Status</h2>
  <table>
    <tr><th>Control ID</th><th>Title</th><th>Status</th><th>Mapped findings (expand)</th></tr>
"""
        for _cid, control in (report_data.get("controls") or {}).items():
            cid = html_escape(str(control.get("control_id", "")))
            ttl = html_escape(str(control.get("title", "")))
            st = html_escape(str((control.get("status") or "").upper()))
            n = int(control.get("mapped_findings_count", 0) or 0)
            findings = control.get("findings") or []
            if n > 0 and findings:
                rows_li = "".join(
                    f'<div class="finding-mini"><strong>{html_escape(str(f.get("title", "")))}</strong> — '
                    f"severity {html_escape(str(f.get('severity', '')))}, status {html_escape(str(f.get('status', '')))}</div>"
                    for f in findings
                )
                detail_block = f"<details><summary>{n} finding(s) — click to expand</summary>{rows_li}</details>"
            elif n > 0:
                detail_block = (
                    f"<span>{n} mapped (open full JSON export for IDs)</span>"
                )
            else:
                detail_block = "—"
            html += f"""    <tr>
      <td><strong>{cid}</strong></td>
      <td>{ttl}</td>
      <td>{st}</td>
      <td>{detail_block}</td>
    </tr>
"""
        html += "  </table>\n"
    elif report_type == "executive":
        html += "<div class='summary'><h2>Executive overview</h2>"
        if report_data.get("compliance"):
            c = report_data["compliance"]
            html += f"<p><strong>Framework compliance:</strong> {c.get('compliance_percentage', 0)}%</p>"
        fs = report_data.get("findings_summary") or {}
        html += f"<p><strong>Total findings:</strong> {report_data.get('total_findings', 0)}</p>"
        html += f"<p>Critical: {fs.get('critical', 0)} · High: {fs.get('high', 0)} · Medium: {fs.get('medium', 0)} · Low: {fs.get('low', 0)}</p></div>"
    elif report_type == "findings":
        fb = report_data.get("findings_by_severity") or {}
        html += f"""
  <div class="summary">
    <h2>Findings Summary</h2>
    <p><strong>Total Findings:</strong> {report_data.get("total_findings", 0)}</p>
    <p class="critical">Critical: {fb.get("critical", 0)}</p>
    <p class="high">High: {fb.get("high", 0)}</p>
    <p class="medium">Medium: {fb.get("medium", 0)}</p>
    <p>Low: {fb.get("low", 0)}</p>
  </div>
  <h2>All Findings</h2>
  <table>
    <tr><th>Target</th><th>Finding</th><th>Severity</th><th>Status</th></tr>
"""
        for finding in (report_data.get("findings") or [])[:100]:
            sev = (finding.get("severity") or "low").lower()
            if sev not in ("critical", "high", "medium", "low"):
                sev = "low"
            html += f"""    <tr>
      <td>{html_escape(str(finding.get("target", "")))}</td>
      <td>{html_escape(str(finding.get("title", "")))}</td>
      <td class="{sev}">{html_escape(str((finding.get("severity") or "")).upper())}</td>
      <td>{html_escape(str(finding.get("status", "NEW")))}</td>
    </tr>
"""
        html += "  </table>\n"
    html += """
  <div class="footer">
    <p>This report was automatically generated by NiteSentinel.</p>
    <p>CONFIDENTIAL - For authorized recipients only.</p>
  </div>
</body>
</html>
"""
    return html


def generate_pdf_report(report_data: dict, report_type: str) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    org_hdr = report_data.get("organization_display_name") or ""
    story = [
        Paragraph(str(report_data.get("title", "Report")), styles["Title"]),
        Spacer(1, 6),
        Paragraph(str(org_hdr), styles["Normal"]),
        Spacer(1, 6),
        Paragraph(
            f"Generated: {report_data.get('generated_at', '')}", styles["Normal"]
        ),
        Spacer(1, 12),
    ]
    if report_type == "findings":
        rows = [["Target", "Finding", "Severity", "Status"]]
        for f in (report_data.get("findings") or [])[:80]:
            rows.append(
                [
                    str(f.get("target", ""))[:40],
                    str(f.get("title", ""))[:60],
                    str(f.get("severity", "")),
                    str(f.get("status", "")),
                ]
            )
        t = Table(rows, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(t)
    elif report_type == "compliance":
        story.append(
            Paragraph(
                f"Compliance: {report_data.get('compliance_percentage', 0)}%",
                styles["Heading2"],
            )
        )
        rows = [["Control", "Title", "Status"]]
        for _cid, c in (report_data.get("controls") or {}).items():
            rows.append(
                [
                    str(c.get("control_id", "")),
                    str(c.get("title", ""))[:50],
                    str(c.get("status", "")),
                ]
            )
        story.append(Table(rows, repeatRows=1))
    else:
        story.append(
            Paragraph(
                "Executive summary — see HTML or JSON export for details.",
                styles["Normal"],
            )
        )
    doc.build(story)
    return buf.getvalue()


def generate_xlsx_report(report_data: dict, report_type: str) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Report"
    ws.append([report_data.get("title", "NiteSentinel Report")])
    ws.append(["Generated", report_data.get("generated_at", "")])
    if report_type == "findings":
        ws.append(["Target", "Title", "Severity", "Status"])
        for f in report_data.get("findings") or []:
            ws.append(
                [
                    f.get("target"),
                    f.get("title"),
                    f.get("severity"),
                    f.get("status"),
                ]
            )
    elif report_type == "compliance":
        ws.append(["Control ID", "Title", "Status", "Mapped findings"])
        for _cid, c in (report_data.get("controls") or {}).items():
            ws.append(
                [
                    c.get("control_id"),
                    c.get("title"),
                    c.get("status"),
                    c.get("mapped_findings_count"),
                ]
            )
    else:
        ws.append(["Section", "Value"])
        ws.append(["Total findings", report_data.get("total_findings", "")])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


@app.route("/api/reports/generate", methods=["POST"])
@login_required
def api_generate_report():
    org_id = session.get("org_id")
    user_id = session.get("user_id") or session.get("username")
    if not user_id or not has_permission(org_id, "report_create"):
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json() or {}
    report_type = (data.get("type") or "").strip()
    framework = (data.get("framework") or "cis").strip()
    target_ids = data.get("target_ids") or []
    if not isinstance(target_ids, list):
        target_ids = []
    format_type = (data.get("format") or "html").strip().lower()

    if report_type == "compliance":
        report_data = generate_compliance_report(framework, target_ids, org_id)
    elif report_type == "findings":
        report_data = generate_findings_report(target_ids, org_id)
    elif report_type == "executive":
        report_data = generate_executive_report(
            framework if framework in COMPLIANCE_FRAMEWORKS else None,
            target_ids,
            org_id,
        )
    else:
        return jsonify({"error": "Unknown report type"}), 400
    if report_data.get("error"):
        return jsonify({"error": report_data["error"]}), 400

    report_data = _attach_report_branding(report_data, org_id)

    if format_type == "json":
        return jsonify(report_data)
    if format_type == "html":
        html_content = render_report_html(report_data, report_type)
        return Response(html_content, mimetype="text/html")
    if format_type == "pdf":
        html_content = render_report_html(report_data, report_type)
        if session.get("demo_session"):
            watermark_div = """
            <div style="position: fixed; top: 350px; left: 100px; width: 600px; height: 600px; z-index: -1000; font-size: 80px; color: rgba(220, 38, 38, 0.08); font-weight: bold; transform: rotate(-30deg); pointer-events: none;">
              DEMO VERSION
            </div>
            """
            html_content = html_content.replace("<body>", f"<body>{watermark_div}")
        try:
            from xhtml2pdf import pisa
            pdf_buf = BytesIO()
            pisa_status = pisa.CreatePDF(html_content, dest=pdf_buf)
            if pisa_status.err:
                raise Exception("pisa.CreatePDF failed")
            pdf_content = pdf_buf.getvalue()
        except Exception:
            pdf_content = generate_pdf_report(report_data, report_type)
        return Response(
            pdf_content,
            mimetype="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="report.pdf"'},
        )
    if format_type == "xlsx":
        xlsx_content = generate_xlsx_report(report_data, report_type)
        return Response(
            xlsx_content,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="report.xlsx"'},
        )
    return jsonify({"error": "Unsupported format"}), 400


@app.route("/report/<scan_id>/pdf")
@login_required
def download_target_pdf_report(scan_id):
    scan_id = unquote(scan_id)
    if scan_id not in stored_scan_results:
        return jsonify({"error": f"Target/Scan {scan_id} not found."}), 404
        
    org_id = session.get("org_id")
    scan_data = stored_scan_results[scan_id]
    if org_id and scan_data.get("org_id") not in (None, org_id):
        return jsonify({"error": "Forbidden"}), 403
        
    report_data = generate_executive_report("cis", [scan_id], org_id)
    report_data = _attach_report_branding(report_data, org_id)
    
    html_content = render_report_html(report_data, "executive")
    
    if session.get("demo_session"):
        watermark_div = """
        <div style="position: fixed; top: 350px; left: 100px; width: 600px; height: 600px; z-index: -1000; font-size: 80px; color: rgba(220, 38, 38, 0.08); font-weight: bold; transform: rotate(-30deg); pointer-events: none;">
          DEMO VERSION
        </div>
        """
        html_content = html_content.replace("<body>", f"<body>{watermark_div}")
        
    try:
        from xhtml2pdf import pisa
        pdf_buf = BytesIO()
        pisa_status = pisa.CreatePDF(html_content, dest=pdf_buf)
        if pisa_status.err:
            raise Exception("pisa.CreatePDF failed")
        pdf_bytes = pdf_buf.getvalue()
    except Exception:
        pdf_bytes = generate_pdf_report(report_data, "executive")
        
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="nitesentinel_report_{scan_id}.pdf"'},
    )


def _run_scheduled_scan(target, mode):
    if mode == "local":
        data = scanner.scan_local()
        score = data.get("score", 0)
        _record_scan("localhost", score)
    else:
        # lightweight scheduled check marker
        _record_scan(target, 0)
    _add_events(
        target, [{"status": "WARNING", "check": f"Scheduled {mode} scan executed"}]
    )


@app.route("/api/schedule", methods=["POST"])
@login_required
@secure_post
# @role_required("admin", "super_admin")  # Temporarily disabled for testing
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
            kwargs={
                "target": target,
                "mode": "local" if target == "localhost" else "remote",
            },
        )
        job = scheduler.get_job(job_id)
        next_run = (
            job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
            if job and job.next_run_time
            else None
        )
        return jsonify({"ok": True, "job_id": job_id, "next_run": next_run})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/json")
@login_required
def api_export_json():
    host = request.args.get("host", "localhost")
    data = stored_scan_results.get(host)
    if not data:
        return jsonify({"error": "No data for host"}), 404
    return jsonify(data)


@app.route("/api/settings/save", methods=["POST"])
@login_required
@secure_post
def save_settings():
    try:
        data = request.json
        app.config["ORG_NAME"] = data.get("org_name", "NiTechSpark")
        app.config["CLIENT_NAME"] = data.get("client_name", "")
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/llm/models", methods=["POST"])
@login_required
@secure_post
@role_required("admin", "org_admin", "super_admin")
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
                return jsonify(
                    {"error": "model_parameters must be valid JSON object"}
                ), 400

        model_id = llm_store.add_model(
            user_id=_llm_user_id(),
            model_name=model_name,
            model_type=model_type,
            api_endpoint=data.get("api_endpoint"),
            api_key=data.get("api_key"),
            model_parameters=model_parameters,
        )
        llm_store.log_activity(
            _llm_user_id(),
            "create_model",
            "model",
            model_id,
            {"model_name": model_name, "model_type": model_type},
        )
        return jsonify({"model_id": model_id, "status": "created"}), 201
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/llm/models", methods=["GET"])
@login_required
def list_llm_models():
    try:
        rows = llm_store.list_models(_llm_user_id())
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/llm/scan", methods=["POST"])
@login_required
@secure_post
@role_required("admin", "org_admin", "super_admin")
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


@app.route("/api/llm/scan/<scan_id>", methods=["GET"])
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


@app.route("/api/llm/report/<scan_id>", methods=["GET"])
@login_required
def get_llm_report(scan_id):
    try:
        scan = llm_store.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Report not found"}), 404
        fmt = request.args.get("format", "json")
        if fmt == "html":
            try:
                html = scan.get("report_html") or llm_reporter.build_html(scan)
                return Response(html, mimetype="text/html")
            except Exception as e:
                import traceback

                return jsonify(
                    {
                        "error": f"HTML report error: {str(e)}",
                        "trace": traceback.format_exc(),
                    }
                ), 500
        if fmt == "pdf":
            pdf_data = llm_reporter.build_pdf(scan)
            return Response(
                pdf_data,
                mimetype="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=LLM_Security_Report_{scan_id}.pdf"
                },
            )
        return jsonify(scan.get("report_json") or {})
    except Exception as e:
        import traceback

        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/llm/dashboard", methods=["GET"])
@login_required
def llm_dashboard():
    user_id = _llm_user_id()
    models = llm_store.list_models(user_id)
    scans = llm_store.list_recent_scans(user_id, limit=30)
    vulns = llm_store.list_vulnerabilities(user_id, limit=500)
    total = len(scans)
    avg_score = (
        int(sum(s.get("security_score", 0) for s in scans) / total) if total else 0
    )
    open_items = sum(1 for v in vulns if v.get("status") in ("open", "in_progress"))
    resolved_items = sum(
        1 for v in vulns if v.get("status") in ("resolved", "verified", "fixed")
    )
    remediation_rate = int((resolved_items / max(1, len(vulns))) * 100) if vulns else 0
    critical_open = sum(
        1
        for v in vulns
        if v.get("severity") == "critical"
        and v.get("status") in ("open", "in_progress")
    )
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


@app.route("/api/llm/vulnerabilities", methods=["GET"])
@login_required
def llm_vulnerabilities():
    status = request.args.get("status")
    rows = llm_store.list_vulnerabilities(_llm_user_id(), status=status, limit=500)
    return jsonify(rows)


@app.route("/api/llm/vulnerabilities/<vuln_id>", methods=["PATCH"])
@login_required
@secure_post
@role_required("admin")
def patch_llm_vulnerability(vuln_id):
    payload = request.json or {}
    if llm_store.update_vulnerability(vuln_id, payload):
        llm_store.log_activity(
            _llm_user_id(), "update_vulnerability", "vulnerability", vuln_id, payload
        )
        return jsonify({"ok": True})
    return jsonify({"error": "vulnerability not found or no valid fields"}), 404


@app.route("/api/llm/vulnerabilities/trending", methods=["GET"])
@login_required
def llm_vuln_trending():
    rows = llm_store.list_recent_scans(_llm_user_id(), limit=30)
    series = [
        {"date": r.get("scan_date", "")[:10], "open": r.get("vulnerabilities_count", 0)}
        for r in rows
    ]
    return jsonify({"series": list(reversed(series))})


@app.route("/api/llm/models/<model_id>/rescan", methods=["POST"])
@login_required
@secure_post
@role_required("admin", "org_admin", "super_admin")
def llm_rescan(model_id):
    model = llm_store.get_model(model_id, _llm_user_id())
    if not model:
        return jsonify({"error": "Model not found"}), 404
    scan_id = llm_store.create_scan(model_id)
    _set_llm_scan_state(scan_id, 0, "Starting", status="in_progress")
    worker = Thread(target=_run_llm_scan_job, args=(scan_id, model), daemon=True)
    worker.start()
    llm_store.log_activity(
        _llm_user_id(), "rescan_model", "model", model_id, {"scan_id": scan_id}
    )
    return jsonify({"scan_id": scan_id, "status": "in_progress"})


@app.route("/api/llm/vulnerabilities/<vuln_id>/assign", methods=["POST"])
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
        llm_store.log_activity(
            _llm_user_id(), "assign_vulnerability", "vulnerability", vuln_id, payload
        )
        return jsonify({"ok": True})
    return jsonify({"error": "vulnerability not found"}), 404


@app.route("/api/llm/vulnerabilities/<vuln_id>/comments", methods=["POST"])
@login_required
@secure_post
def comment_llm_vulnerability(vuln_id):
    data = request.json or {}
    text = (data.get("comment") or "").strip()
    if not text:
        return jsonify({"error": "comment is required"}), 400
    cid = llm_store.add_comment(vuln_id, _llm_user_id(), text)
    llm_store.log_activity(
        _llm_user_id(),
        "comment_vulnerability",
        "vulnerability",
        vuln_id,
        {"comment_id": cid},
    )
    return jsonify({"comment_id": cid, "status": "created"}), 201


@app.route("/api/llm/vulnerabilities/<vuln_id>/comments", methods=["GET"])
@login_required
def list_llm_vuln_comments(vuln_id):
    return jsonify(llm_store.list_comments(vuln_id))


@app.route("/api/llm/activity", methods=["GET"])
@login_required
def llm_activity():
    return jsonify(llm_store.list_activity(_llm_user_id(), limit=120))


@app.route("/api/integrations/slack/alert", methods=["POST"])
@login_required
@secure_post
@role_required("admin")
def slack_alert():
    payload = request.json or {}
    ok, msg = send_slack_alert(payload, webhook_url=payload.get("webhook_url"))
    if ok:
        llm_store.log_activity(
            _llm_user_id(),
            "slack_alert",
            "integration",
            "slack",
            {"summary": payload.get("summary", "")},
        )
        return jsonify({"ok": True, "result": msg})
    return jsonify({"ok": False, "error": msg}), 400


@app.route("/api/llm/report/<scan_id>/email", methods=["POST"])
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
    message = data.get(
        "message", "Please find the attached LLM security report summary."
    )
    html = scan.get("report_html") or llm_reporter.build_html(scan)
    score = scan.get("security_score", 0)
    body = (
        f"NiteSentinel LLM report\nScan ID: {scan_id}\nScore: {score}/100\n\n{message}"
    )
    ok, msg = send_email_report(
        recipients=recipients,
        subject=f"NiteSentinel LLM Report {scan_id}",
        body=body,
        html=html,
    )
    if ok:
        llm_store.log_activity(
            _llm_user_id(),
            "email_report",
            "report",
            scan_id,
            {"recipients": recipients},
        )
        return jsonify({"ok": True, "result": msg})
    return jsonify({"ok": False, "error": msg}), 400


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json()
    user_message = data.get("message")
    if not user_message:
        return jsonify({"error": "Message required"}), 400
    user_id = _llm_user_id()
    response = query_llm(user_message, user_id)
    return jsonify({"message": response, "timestamp": datetime.utcnow().isoformat()})


@app.route("/api/chat/history", methods=["GET"])
@login_required
def api_chat_history():
    user_id = _llm_user_id()
    history = chat_history.get(user_id, [])
    return jsonify({"history": history[-20:], "total": len(history)})


@app.route("/api/findings/<path:finding_id>/analyze", methods=["POST"])
@login_required
def api_analyze_finding(finding_id):
    finding_id = unquote(finding_id)
    analysis = analyze_finding_with_ai(finding_id)
    return jsonify(analysis)


@app.route("/api/findings/<path:finding_id>/remediate", methods=["POST"])
@login_required
def api_remediate_finding(finding_id):
    finding_id = unquote(finding_id)
    suggestions = get_remediation_suggestions(finding_id)
    return jsonify(suggestions)


@app.route("/api/health", methods=["GET"])
def api_health():
    llm_status = "connected" if llm_client else "disconnected"
    return jsonify(
        {
            "status": "ok",
            "version": "1.0.0",
            "llm_provider": LLM_PROVIDER,
            "llm_status": llm_status,
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@app.route("/api/admin/users", methods=["GET"])
@login_required
@require_permission("user_view")
def list_admin_users():
    """List users. Super admin sees all, org_admin sees own org."""
    role = session.get("role")
    org_filter_val = org_filter()

    users = llm_store.list_users()
    if org_filter_val:
        users = [u for u in users if u.get("org_id") == org_filter_val]

    return jsonify(users)


@app.route("/api/admin/users", methods=["POST"])
@login_required
@require_permission("user_create")
def create_admin_user():
    payload = request.json or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    role = (payload.get("role") or "viewer").strip()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # Only super_admin can create super_admin users
    if role == "super_admin" and session.get("role") != "super_admin":
        return jsonify({"error": "Only super admin can create super admin users"}), 403

    # org_admin cannot assign org outside their own
    if session.get("role") == "org_admin" and payload.get("org_id") != session.get(
        "org_id"
    ):
        return jsonify({"error": "Cannot assign org outside your org"}), 403

    org_id = payload.get("org_id") or session.get("org_id")
    uid = llm_store.create_user(
        username=username, password=password, role=role, org_id=org_id
    )
    llm_store.log_activity(
        _llm_user_id(), "create_user", "user", uid, {"username": username, "role": role}
    )
    return jsonify({"user_id": uid, "status": "created"}), 201


@app.route("/api/admin/users/<user_id>/password", methods=["POST"])
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
        if (
            actor_role == "admin"
            and target.get("role") in ("org_admin", "admin")
            and actor_name != target_name
        ):
            return jsonify(
                {"error": "admin can update only own/admin-level restricted passwords"}
            ), 403
    else:
        return jsonify({"error": "Forbidden"}), 403

    ok = llm_store.update_user_password(user_id, new_password)
    if not ok:
        return jsonify({"error": "password update failed"}), 400
    llm_store.log_activity(
        _llm_user_id(),
        "update_user_password",
        "user",
        user_id,
        {"username": target.get("username")},
    )
    return jsonify({"ok": True, "status": "password_updated"})


@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
@login_required
@secure_post
def delete_admin_user(user_id: str):
    target = llm_store.get_user_by_id(user_id)
    if not target:
        return jsonify({"error": "user not found"}), 404

    actor_role = session.get("role")
    target_role = target.get("role", "")
    target_username = target.get("username", "")

    if target_role == "super_admin":
        return jsonify({"error": "Cannot delete super admin user"}), 403

    if not _is_super_admin():
        return jsonify({"error": "Only super admin can delete users"}), 403

    llm_store.delete_user(user_id)
    llm_store.log_activity(
        _llm_user_id(),
        "delete_user",
        "user",
        user_id,
        {"username": target_username},
    )
    return jsonify({"ok": True, "status": "deleted"})


@app.route("/api/admin/licenses", methods=["GET"])
@login_required
@require_permission("license_view")
def list_admin_licenses():
    return jsonify(llm_store.list_licenses())


@app.route("/api/admin/licenses", methods=["POST"])
@login_required
@require_permission("license_create")
def create_admin_license():
    payload = request.json or {}
    logger.info(f"License create payload: {payload}")
    tier = (payload.get("tier", "standard") or "standard").strip()
    max_users = int(payload.get("max_users", 5))
    expires_at = payload.get("expires_at")
    organization_id = (payload.get("organization_id") or "").strip() or None
    org_name = (payload.get("org_name") or "").strip()
    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = (payload.get("admin_password") or "").strip()

    logger.info(
        f"Parsed: org_name='{org_name}', admin_username='{admin_username}', admin_password set={bool(admin_password)}"
    )

    if max_users < 1:
        return jsonify({"error": "max_users must be at least 1"}), 400

    try:
        if org_name or admin_username or admin_password:
            if not (org_name and admin_username and admin_password):
                return jsonify(
                    {
                        "error": "org_name, admin_username and admin_password are required for auto organization setup"
                    }
                ), 400
            lic = llm_store.create_license(
                tier=tier,
                expires_at=expires_at,
                max_users=max_users,
                organization_id=None,
            )
            oid = llm_store.create_organization(
                org_name, admin_username, admin_password, license_id=lic["id"]
            )
            llm_store.link_license_organization(lic["id"], oid)
            llm_store.log_activity(
                _llm_user_id(),
                "create_license_with_org",
                "license",
                lic["id"],
                {
                    "tier": tier,
                    "organization_id": oid,
                    "org_name": org_name,
                    "admin_username": admin_username,
                },
            )
            return jsonify(
                {
                    "status": "created",
                    **lic,
                    "organization_id": oid,
                    "organization_name": org_name,
                    "admin_username": admin_username,
                }
            ), 201

        if organization_id:
            lic = llm_store.create_license(
                tier=tier,
                expires_at=expires_at,
                max_users=max_users,
                organization_id=organization_id,
            )
            llm_store.log_activity(
                _llm_user_id(),
                "create_license",
                "license",
                lic["id"],
                {"tier": tier, "organization_id": organization_id},
            )
            return jsonify(
                {"status": "created", **lic, "organization_id": organization_id}
            ), 201

        lic = llm_store.create_license(
            tier=tier, expires_at=expires_at, max_users=max_users, organization_id=None
        )
        llm_store.log_activity(
            _llm_user_id(), "create_license", "license", lic["id"], {"tier": tier}
        )
        return jsonify({"status": "created", **lic}), 201
    except Exception as e:
        import traceback

        logger.error(f"create_admin_license error: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 400


@app.route("/api/admin/licenses/<lic_id>", methods=["DELETE"])
@login_required
@secure_post
@super_admin_required
def delete_admin_license(lic_id):
    lic = llm_store.get_license(lic_id)
    if not lic:
        return jsonify({"error": "license not found"}), 404
    llm_store.unlink_license_organization(license_id=lic_id)
    llm_store.log_activity(
        _llm_user_id(), "delete_license", "license", lic_id, {"key": lic.get("key")}
    )
    return jsonify({"ok": True, "status": "deleted"})


@app.route("/api/admin/organizations", methods=["GET"])
@login_required
@require_permission("org_view")
def list_admin_orgs():
    orgs = llm_store.list_organizations()
    org_filter_val = org_filter()
    if org_filter_val:
        orgs = [o for o in orgs if o.get("id") == org_filter_val]
    return jsonify(orgs)


@app.route("/api/admin/organizations", methods=["POST"])
@login_required
@require_permission("org_create")
def create_admin_org():
    payload = request.json or {}
    org_name = (payload.get("name") or "").strip()
    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = (payload.get("admin_password") or "").strip()
    if not org_name or not admin_username or not admin_password:
        return jsonify(
            {"error": "name, admin_username, admin_password are required"}
        ), 400
    oid = llm_store.create_organization(
        org_name, admin_username, admin_password, license_id=payload.get("license_id")
    )
    llm_store.log_activity(
        _llm_user_id(), "create_organization", "organization", oid, {"name": org_name}
    )
    return jsonify({"organization_id": oid, "status": "created"}), 201


@app.route("/api/admin/organizations/<org_id>", methods=["DELETE"])
@login_required
@secure_post
def delete_admin_org(org_id: str):
    org = llm_store.get_organization(org_id)
    if not org:
        return jsonify({"error": "organization not found"}), 404

    llm_store.delete_organization(org_id)
    llm_store.log_activity(
        _llm_user_id(),
        "delete_organization",
        "organization",
        org_id,
        {"name": org.get("name")},
    )
    return jsonify({"ok": True, "status": "deleted"})


@app.route("/api/admin/org-license/link", methods=["POST"])
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
    llm_store.log_activity(
        _llm_user_id(),
        "link_org_license",
        "organization",
        org_id,
        {"license_id": license_id},
    )
    return jsonify({"ok": True, "organization_id": org_id, "license_id": license_id})


@app.route("/api/admin/org-license/unlink", methods=["POST"])
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
    llm_store.log_activity(
        _llm_user_id(),
        "unlink_org_license",
        "organization",
        org_id or "-",
        {"license_id": license_id},
    )
    return jsonify({"ok": True})


@app.route("/api/organizations", methods=["GET"])
@login_required
@require_permission("org_view")
def api_organizations():
    role = session.get("role", "viewer")
    print(f"[DEBUG api_organizations] User: {session.get('username')}, Role: {role}")

    try:
        all_orgs = llm_store.list_organizations()
        print(
            f"[DEBUG api_organizations] Found {len(all_orgs)} organizations in DB: {[o.get('id') + ':' + o.get('name') for o in all_orgs]}"
        )

        orgs_list = []

        for org_data in all_orgs:
            org_id = org_data.get("id")
            linked_licenses = llm_store.get_org_licenses(org_id)
            license_details = []

            for lic in linked_licenses:
                license_details.append(
                    {
                        "id": lic.get("id"),
                        "key": lic.get("key"),
                        "tier": lic.get("tier"),
                        "expiry": lic.get("expiry"),
                    }
                )

            users_count = len(llm_store.list_users(org_id=org_id))

            org_obj = {
                "id": org_id,
                "name": org_data.get("name"),
                "admin": org_data.get("admin"),
                "created_at": org_data.get("created_at"),
                "users_count": users_count,
                "licenses": license_details,
                "licenses_count": len(license_details),
            }

            orgs_list.append(org_obj)

        print(f"[ORG API] Returning {len(orgs_list)} organizations")

        return jsonify(
            {"success": True, "organizations": orgs_list, "total": len(orgs_list)}
        )

    except Exception as e:
        print(f"[ERROR] /api/organizations: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/organizations/<org_id>/licenses", methods=["GET"])
@login_required
@require_permission("org_view")
def api_org_licenses(org_id):
    org = llm_store.get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    try:
        linked_licenses = llm_store.get_org_licenses(org_id)

        linked = []
        now = datetime.utcnow().isoformat()
        for lic in linked_licenses:
            exp = lic.get("expiry", "")
            status = "active" if exp and exp > now else "expired"
            linked.append(
                {
                    "id": lic.get("id"),
                    "key": lic.get("key"),
                    "tier": lic.get("tier"),
                    "expiry": exp,
                    "status": status,
                }
            )

        print(f"[ORG LICENSES] Org {org_id} has {len(linked)} licenses")

        return jsonify(
            {
                "success": True,
                "organization_id": org_id,
                "licenses": linked,
                "total": len(linked),
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/licenses/available", methods=["GET"])
@login_required
@require_permission("license_view")
def api_available_licenses():
    try:
        all_licenses = llm_store.list_licenses()
        available = []

        for lic in all_licenses:
            if not lic.get("organization_id"):
                available.append(
                    {
                        "id": lic.get("id"),
                        "key": lic.get("key"),
                        "tier": lic.get("tier"),
                        "expiry": lic.get("expiry"),
                        "seats": lic.get("max_users"),
                        "status": "available",
                    }
                )

        print(f"[AVAILABLE LICENSES] {len(available)} unlinked licenses")

        return jsonify(
            {"success": True, "available_licenses": available, "total": len(available)}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/organizations/<org_id>/link-license/<lic_id>", methods=["POST"])
@login_required
@require_permission("org_create")
def api_link_license(org_id, lic_id):
    org = llm_store.get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    lic = llm_store.get_license(lic_id)
    if not lic:
        return jsonify({"error": "License not found"}), 404

    if lic.get("organization_id"):
        existing_org = lic["organization_id"]
        if existing_org != org_id:
            return jsonify(
                {"error": f"License already linked to organization {existing_org}"}
            ), 409

    try:
        llm_store.link_license_organization(license_id=lic_id, organization_id=org_id)

        if org_id not in organization_licenses:
            organization_licenses[org_id] = []
        if lic_id not in organization_licenses[org_id]:
            organization_licenses[org_id].append(lic_id)
        license_organization_map[lic_id] = org_id

        print(f"[LINK LICENSE] Linked license {lic_id} to org {org_id}")
        llm_store.log_activity(
            _llm_user_id(),
            "link_license",
            "license",
            lic_id,
            {"details": f"Linked to organization {org_id}"},
        )

        return jsonify(
            {
                "success": True,
                "message": "License linked to organization",
                "organization_id": org_id,
                "license_id": lic_id,
            }
        )

    except Exception as e:
        print(f"[ERROR] Link license: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/organizations/<org_id>/unlink-license/<lic_id>", methods=["POST"])
@login_required
@require_permission("org_create")
def api_unlink_license(org_id, lic_id):
    org = llm_store.get_organization(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    try:
        lic = llm_store.get_license(lic_id)
        if lic and lic.get("organization_id") == org_id:
            llm_store.unlink_license_organization(
                organization_id=org_id, license_id=lic_id
            )

        if lic_id in license_organization_map:
            del license_organization_map[lic_id]

        if org_id in organization_licenses:
            if lic_id in organization_licenses[org_id]:
                organization_licenses[org_id].remove(lic_id)

        print(f"[UNLINK LICENSE] Unlinked license {lic_id} from org {org_id}")
        llm_store.log_activity(
            _llm_user_id(),
            "unlink_license",
            "license",
            lic_id,
            {"details": f"Unlinked from organization {org_id}"},
        )

        return jsonify(
            {
                "success": True,
                "message": "License unlinked from organization",
                "organization_id": org_id,
                "license_id": lic_id,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/llm/remediate", methods=["POST"])
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


if __name__ == "__main__":
    app.run(debug=False, port=8080)
