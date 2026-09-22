# SecureScope (NiteSentinel) — Complete Developer Handover & Technical Specification

> **Organization:** NITECHSPARK — IT Security & DevOps  
> **Platform Version:** 1.1.0 Enterprise  
> **Tagline:** *One Tool. Every Device. Total Visibility.*  
> **Website:** [https://nitechspark.vercel.app/](https://nitechspark.vercel.app/)  
> **Contact:** nitechspark@gmail.com | +91 6385576354  
> **Author / Founder:** Nithyananthan N  

---

## 1. Executive Summary & Purpose

**SecureScope (NiteSentinel)** is a modular, local-first cybersecurity management and vulnerability assessment platform. It unifies **host vulnerability auditing**, **network & port reconnaissance**, **AI/LLM application security analysis**, **scope-gated offensive security tests**, **regulatory compliance automation**, and **automated remediation (hardening)** under a single unified CLI and real-time Web Dashboard.

```
+-------------------------------------------------------------------------------+
|                             NiteSentinel Web UI / CLI                         |
+-------------------------------------------------------------------------------+
         |                     |                     |                    |
         v                     v                     v                    v
+------------------+  +------------------+  +------------------+  +-------------+
| Host Scanners    |  | Sonic Recon /    |  | LLM Application  |  | OffSec      |
| Windows / Linux  |  | Port Scanner     |  | Security Scanner |  | Scope-Gated |
+------------------+  +------------------+  +------------------+  +-------------+
         |                     |                     |                    |
         +---------------------+---------------------+--------------------+
                                       |
                                       v
                  +-----------------------------------------+
                  | Engine: Threat Scoring & Compliance     |
                  | (CIS / ISO27001 / PCI-DSS / NIST / DPDP)|
                  +-----------------------------------------+
                                       |
                     +-----------------+-----------------+
                     |                                   |
                     v                                   v
        +--------------------------+        +--------------------------+
        | Auto-Hardening Engine    |        | PDF & HTML Report Engine |
        | (OS-level Remediation)   |        | (ReportLab / xhtml2pdf)  |
        +--------------------------+        +--------------------------+
```

---

## 2. Technology Stack & Core Dependencies

| Component / Layer | Technology | Purpose |
|---|---|---|
| **Language & Runtime** | Python 3.10+ | Primary application runtime |
| **Web Framework** | Flask 3.0.3, Werkzeug 3.0.3, Jinja2 3.1.3 | Web server and REST API routing |
| **Realtime WebSockets** | Flask-SocketIO 5.3.6, Eventlet 0.35.2 | Real-time scan telemetry and live log streaming |
| **CLI & Terminal UI** | Click 8.1.7, Rich (>=12, <14) | Command-line interface with styled tables & banners |
| **Auth & Security** | Flask-Login 0.6.3, Flask-Bcrypt 1.0.1, Flask-Limiter 3.5.0 | Session auth, password hashing, rate limiting |
| **Remote Audit Protocols**| Paramiko 3.5.0, PySNMP 7.1.22, PyWinRM 0.5.0, Netmiko 4.6.0 | Agentless Linux (SSH), Windows, & Network device auditing |
| **Report Generation** | ReportLab 4.2.0, xhtml2pdf 0.2.17 | Executive & technical PDF security reports |
| **Networking & Recon** | `dnspython`, `python-whois`, `psutil`, `requests`, `pyOpenSSL` | DNS lookups, WHOIS recon, TLS certificate evaluation |
| **Scheduling & Alerts** | APScheduler 3.10.4, Flask-Mail, Slack Webhooks | Scan job scheduling and real-time alert dispatch |
| **Data Persistence** | SQLite3 (`data/llm_audit.db`), JSONL (`audit/audit.jsonl`), YAML (`config/settings.yaml`) | Local databases and tamper-evident audit trails |

---

## 3. Repository Directory Structure

```text
SecureScope/
├── config/
│   └── settings.yaml            # Master configuration, web authentication & branding
├── data/
│   └── llm_audit.db             # SQLite store for LLM audits, models, & vulnerability items
├── audit/
│   └── audit.jsonl              # Cryptographic audit trail for OffSec operations
├── nitesentinels/                # Core Python application package
│   ├── core/                    # Engine coordinators & shared utilities
│   │   ├── scanner.py           # Master scanner orchestrator (Local, Remote, Network)
│   │   ├── hardener.py          # Auto-hardening and remediation controller
│   │   ├── reporter.py          # PDF / HTML report generator (ReportLab & HTML templates)
│   │   ├── utils.py             # Platform detection (Windows/Linux/WSL), logging, banners
│   │   └── compliance/          # Regulatory compliance frameworks (CIS, DPDP 2023, etc.)
│   ├── scanners/                # Dedicated scan modules
│   │   ├── windows_scanner.py   # Windows Defender, Firewall, UAC, BitLocker, updates
│   │   ├── linux_scanner.py     # SSH, UFW, root login, sudoers, file permissions
│   │   ├── wsl_scanner.py       # WSL specific environment checks
│   │   ├── network_scanner.py   # ARP/ICMP network sweeps
│   │   ├── firewall_scanner.py  # SNMP v2c/v3 firewall rule audit
│   │   ├── port_scanner_async.py# High-speed asynchronous socket port scanner
│   │   ├── service_detector.py  # Port & banner heuristic analyzer
│   │   ├── sonic_recon.py       # Rule-based threat intelligence scoring engine
│   │   ├── llm_scanner.py       # LLM API safety, prompt injection, data leak detector
│   │   └── web_scanner.py       # Web security header and TLS certificate checker
│   ├── hardeners/               # Automated remediation execution
│   │   ├── windows_hardener.py  # Windows firewall / registry / service hardening
│   │   └── linux_hardener.py    # UFW enable, SSH hardening, kernel sysctl tuning
│   ├── offsec/                  # Ethical offensive security testing (Scope-gated)
│   │   ├── engine.py            # OffSec engine coordinating recon/web/API tests
│   │   ├── scope.py             # Scope validator (checks target against authorized domains)
│   │   ├── scope_io.py          # Scope YAML loader and acknowledgment checker
│   │   ├── audit.py             # Cryptographic log writer to audit.jsonl
│   │   ├── recon.py             # DNS enumeration & subdomain discovery
│   │   ├── webtests.py          # Safe web vulnerability tests (headers, XSS patterns)
│   │   └── api_tests.py         # REST API fuzzing & authorization check engine
│   ├── integrations/            # External alerting
│   │   ├── slack.py             # Slack webhook integration
│   │   └── email.py             # Email report dispatch via Flask-Mail
│   └── web/                     # Flask Web UI & API backend
│       ├── app.py               # Main Flask application with 50+ REST endpoints
│       ├── llm_store.py         # SQLite DAO for LLM audits, models & vulnerabilities
│       ├── port_scan_routes.py  # Port scanner & Sonic Recon web endpoints
│       ├── demo_fixtures.py     # Mock data generator for live presentations
│       ├── templates/           # Jinja2 templates (dashboard.html, targets.html, etc.)
│       └── static/              # CSS, JS, fonts, and UI assets
├── port_scanner/                # Standalone port scanner workspace & webapp
├── tests/                       # Pytest test suites
├── main.py                      # Master CLI entrypoint (Click commands)
├── requirements.txt             # Python package dependencies
├── run.bat / run.sh             # Quick startup scripts for Windows and Linux
└── securescope.log              # Master application runtime log
```

---

## 4. Key Subsystems Deep-Dive

### 4.1. Local & Remote Host Auditing (CIS-aligned)
* **Local Auditing:** Auto-detects operating system:
  * **Windows:** Verifies Windows Defender, active Firewall profiles, BitLocker drive encryption, UAC levels, Windows Update status, and SMBv1 exposure.
  * **Linux:** Audits SSH configuration (`PermitRootLogin`, `PasswordAuthentication`, port changes), UFW/iptables status, sensitive file permissions (`/etc/shadow`, `/etc/passwd`), password aging (`/etc/login.defs`), and open listening ports.
  * **WSL:** Handles specific WSL environment constraints.
* **Remote Auditing:** Performs agentless remote scans over SSH (`paramiko`) or WinRM.

### 4.2. Sonic Recon AI & Asynchronous Port Scanner
* **Async Port Scanner (`port_scanner_async.py`):** High-concurrency socket scanner with configurable timeouts and worker threads.
* **Banner Grabbing & Service Detection (`service_detector.py`):** Fingerprints service versions and flags exposed legacy protocols.
* **Sonic Recon Engine (`sonic_recon.py`):** Deterministic, rule-based cyber threat scoring (0–100 scale) that categorizes vulnerabilities into *Critical*, *High*, *Medium*, *Low*, and *Informational* with contextual remediation advice without external ML/cloud dependencies.

### 4.3. LLM Application & AI Security Scanner
* **LLM API Security (`llm_scanner.py`):**
  * **Prompt Injection Resilience:** Tests system prompt leakage and jailbreak susceptibility.
  * **Data Leakage & PII:** Verifies if endpoints leak sensitive tokens, credentials, or PII.
  * **Authentication & Rate Limiting:** Audits endpoint exposure and API key protections.
* Backed by SQLite (`data/llm_audit.db`) with full vulnerability lifecycle management (assign, comment, patch status, rescan).

### 4.4. Scope-Gated Ethical OffSec Engine
* Safe-by-default offensive security scanner (`nitesentinels/offsec/`).
* Requires an authorized `scope.yaml` file declaring explicit domain/IP targets and legal authorization acknowledgment.
* All scans generate an immutable, tamper-evident log entry in `audit/audit.jsonl` with timestamps, operator IDs, and target hashes.

### 4.5. Compliance Automation Framework
* Evaluates scan findings against major regulatory standards:
  * **CIS Benchmarks** (v8)
  * **ISO/IEC 27001**
  * **PCI-DSS 4.0**
  * **NIST CSF** (Cybersecurity Framework)
  * **India DPDP Act 2023** (Digital Personal Data Protection)

### 4.6. Automated Hardening Engine
* Provides automated remediation (`main.py harden --yes` or via Web UI).
* Applies safe OS-level hardening (enabling UFW, disabling insecure SSH root login, system security adjustments).

### 4.7. Executive PDF & HTML Reporting
* Generates branded executive and technical PDF reports with risk scorecards, severity breakdowns, compliance checklists, and remediation roadmaps.

---

## 5. Configuration & Credentials

Master configuration is located in `config/settings.yaml`:

```yaml
app:
  name: NiteSentinel
  version: 1.1.0
  company: NITECHSPARK
  license: MIT

reporting:
  org_name: NITECHSPARK
  output_dir: reports/
  default_format: pdf

scanning:
  timeout: 30
  ssh_timeout: 10
  snmp_community: public

web:
  port: 8080
  debug: false
  session_timeout_hours: 8
  auth:
    enabled: true
    username: "nitechspark_admin"
    password: "NiteSentinel@2026"
    users:
      - username: "admin"
        password: "NiteSentinel@2026"
        role: "admin"
      - username: "nitechspark"
        password: "NiteSentinel@2026"
        role: "admin"
      - username: "viewer"
        password: "ViewOnly@2026"
        role: "viewer"

branding:
  organization_name: "NITECHSPARK"
  client_name: "Default Client"
  report_primary_color: "#00d4ff"
```

---

## 6. Setup & Execution Instructions

### Prerequisites
* Python 3.10 or higher
* Git

### Step 1: Environment Setup
```bash
# Clone the repository
git clone <REPOSITORY_URL>
cd SecureScope

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Running the Web Dashboard
```bash
# Production / Standard web UI
python main.py web --port 8080

# Demo mode (with mock data & presentation fixtures)
python main.py web --port 8080 --demo
```
* **URL:** `http://localhost:8080`
* **Default Login:** `admin` / `NiteSentinel@2026`

### Step 3: CLI Usage Guide
```bash
# 1. Run local system audit
python main.py scan local

# 2. Run remote SSH audit (Linux)
python main.py remote --host 192.168.1.50 --user ubuntu --password mypassword --type linux

# 3. Apply automated system hardening fixes
python main.py harden --yes

# 4. Generate security assessment report
python main.py report --format pdf --output report.pdf --org "NITECHSPARK"
python main.py report --format html --output report.html

# 5. Fast port scan with banner grabbing
python main.py port_scan quick scanme.nmap.org --ports 1-1024

# 6. Scope-gated OffSec scan
python main.py offsec scan --scope-file scope.yaml --kind web --target https://example.com
```

---

## 7. Recommended Next Steps for the Development Team

1. **Database & Architecture Refactoring:**
   * Transition from in-memory state and standalone SQLite databases (`llm_audit.db`) to a unified relational database with SQLAlchemy ORM and Alembic migrations (e.g., PostgreSQL).
2. **Background Task Queue:**
   * Integrate Celery or Redis Queue (RQ) for long-running port scans and remote network audits to prevent blocking web worker threads.
3. **Frontend Modernization:**
   * Modularize large Jinja2 templates (`dashboard.html`) into reusable components or a modern frontend framework (React / Next.js / Vue + Tailwind CSS).
4. **API Documentation:**
   * Provide automated OpenAPI / Swagger documentation (`/docs`) across all REST endpoints.
5. **Containerization & CI/CD:**
   * Provide a production-ready `Dockerfile` and `docker-compose.yml` (app, Redis, Postgres).
   * Set up GitHub Actions for automated linting (`ruff`), testing (`pytest`), and container builds.

---

## 8. Feature-by-Feature Handover Tracker & Work Allocation

A comprehensive development tracker and team work allocation matrix for **3 Developers** and **1 QA / Tester** is maintained in:
* **Interactive Markdown Tracker:** [`DEVELOPMENT_HANDOVER_TRACKER.md`](DEVELOPMENT_HANDOVER_TRACKER.md)
* **Spreadsheet Import (CSV):** [`DEVELOPMENT_HANDOVER_TRACKER.csv`](DEVELOPMENT_HANDOVER_TRACKER.csv)

It includes feature-by-feature completion percentages (16 core features), acceptance criteria, developer backlogs, automated test mapping, and a 4-week sprint execution roadmap.

