# NiteSentinel — Feature-by-Feature Development Handover & Team Work Allocation Tracker

> **Product:** NiteSentinel (1.1.0 Enterprise)  
> **Organization:** NITECHSPARK — IT Security & DevOps  
> **Repository:** `https://github.com/nithyananthantechy/Securescopes.git`  
> **Current Version:** `1.1.0-Enterprise`  
> **Test Suite Health:** **136 / 136 Passing (100% Green)**  
> **Last Updated:** September 2026  

---

## 1. Team Composition & Role Distribution

| Role / Assigned Person | Primary Focus Area | Key Modules Owned |
|---|---|---|
| **Person 1 (Dev 1 - Backend & Security Scanners Lead)** | Host scanning, network reconnaissance, LLM security, scope-gated offensive security engines, CLI commands. | `nitesentinels/scanners/`, `nitesentinels/offsec/`, `nitesentinels/core/scanner.py`, `main.py` |
| **Person 2 (Dev 2 - Full-Stack & Frontend UI Lead)** | Platform Hub, multi-tenant client workspace, engagement lifecycle, Jinja2/CSS templates, REST APIs, WebSockets. | `nitesentinels/web/templates/`, `nitesentinels/web/app.py`, `nitesentinels/web/static/` |
| **Person 3 (Dev 3 - HAM, Hardening & DevOps Lead)** | Hardware Asset Management (HAM), endpoint agent, OS-level auto-hardening, integrations (Slack/Email), Alembic migrations, database models. | `nitesentinels/ham/`, `nitesentinels/hardeners/`, `nitesentinels/integrations/`, `alembic/` |
| **Person 4 (QA / Test Automation Lead)** | Test suite execution, E2E validation pipeline, regression testing, acceptance criteria verification, security & negative testing. | `tests/`, `scratch_qa_pipeline.py`, manual UI validation |

---

## 2. Executive Status Summary

```
========================================================================================
                                NITESENTINEL HEALTH METRICS
========================================================================================
Total Core Features:          16 Subsystems
Overall Implementation:       92% Complete
Automated Test Coverage:      136 Tests passing in 89s across 13 test suites
Database Layer:               SQLite3 (LLM Audit, HAM, Port Scan) + Alembic migrations
Supported OS Platforms:       Windows 10/11/Server, Linux (Debian/Ubuntu/RHEL), WSL2
========================================================================================
```

---

## 3. Master Feature Handover Matrix

| Feature ID | Feature Name | Subsystem | Assigned Dev | QA Tester | Status | % Done | Priority | Target Sprint | Primary Code Reference |
|---|---|---|---|---|---|---|---|---|---|
| **FEAT-01** | Local Host Security Audit | Core Scanners | Person 1 | QA Tester | Completed | 95% | P0 | Sprint 1 | [`windows_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/windows_scanner.py), [`linux_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/linux_scanner.py) |
| **FEAT-02** | Remote Agentless Audit | Core Scanners | Person 1 | QA Tester | In Progress | 85% | P1 | Sprint 1 | [`scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/scanner.py) |
| **FEAT-03** | Sonic Recon & Async Port Scanner | Network Scanners | Person 1 | QA Tester | Completed | 95% | P0 | Sprint 1 | [`port_scanner_async.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/port_scanner_async.py), [`sonic_recon.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/sonic_recon.py) |
| **FEAT-04** | AI / LLM Application Security | AI Security | Person 1 | QA Tester | Completed | 90% | P1 | Sprint 2 | [`llm_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/llm_scanner.py), [`llm_store.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/llm_store.py) |
| **FEAT-05** | Scope-Gated Ethical OffSec Engine | Offensive Security | Person 1 | QA Tester | Completed | 90% | P1 | Sprint 2 | [`engine.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/engine.py), [`scope.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/scope.py) |
| **FEAT-06** | Platform Hub & Workspace Navigation | Web Frontend | Person 2 | QA Tester | Completed | 95% | P0 | Sprint 1 | [`platform_hub.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/platform_hub.html), [`app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py) |
| **FEAT-07** | Client Directory & Multi-Tenancy | Client Engagement | Person 2 | QA Tester | Completed | 90% | P0 | Sprint 1 | [`clients.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/clients.html), [`app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py) |
| **FEAT-08** | Engagement Lifecycle & Scope Control | Client Engagement | Person 2 | QA Tester | Completed | 95% | P0 | Sprint 2 | [`engagements.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagements.html), [`engagement_scope.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_scope.html) |
| **FEAT-09** | Vulnerability Findings & Retest Workflow | Findings & Workflow | Person 2 | QA Tester | Completed | 95% | P0 | Sprint 2 | [`engagement_findings.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_findings.html), [`engagement_retest.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_retest.html) |
| **FEAT-10** | Evidence Locker & Hashing | Storage & Evidence | Person 2 | QA Tester | Completed | 90% | P1 | Sprint 2 | [`engagement_evidence.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_evidence.html) |
| **FEAT-11** | HAM (Hardware Asset Management) Core | HAM Subsystem | Person 3 | QA Tester | Completed | 95% | P0 | Sprint 1 | [`ham_store.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/ham_store.py), [`ham_routes.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/ham_routes.py) |
| **FEAT-12** | HAM Endpoint Agent & Heartbeat | HAM Subsystem | Person 3 | QA Tester | Completed | 90% | P0 | Sprint 2 | [`nitesentinel_agent.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/ham/agent/nitesentinel_agent.py) |
| **FEAT-13** | Automated OS Hardening Engine | Remediation | Person 3 | QA Tester | Completed | 90% | P1 | Sprint 2 | [`hardener.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/hardener.py), [`windows_hardener.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/hardeners/windows_hardener.py) |
| **FEAT-14** | Compliance Automation (CIS, DPDP, ISO) | Compliance | Person 1 & 2 | QA Tester | Completed | 90% | P1 | Sprint 3 | [`dpdp_2023.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/compliance/dpdp_2023.py), [`compliance.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/compliance.html) |
| **FEAT-15** | Executive & Technical Reporting (PDF/HTML) | Reporting | Person 2 & 3 | QA Tester | Completed | 95% | P0 | Sprint 2 | [`reporter.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/reporter.py), [`engagement_reports.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_reports.html) |
| **FEAT-16** | Database Migrations & DevOps CI/CD | Infrastructure | Person 3 | QA Tester | In Progress | 80% | P1 | Sprint 3 | [`alembic/`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/alembic/), [`main.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/main.py) |

---

## 4. Deep-Dive Feature Breakdown & Handover Tasks

---

### [FEAT-01] Local Host Security Audit (Windows, Linux, WSL)
- **Primary Owner:** Person 1 (Dev 1)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Coordinator: [`nitesentinels/core/scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/scanner.py)
  - Windows: [`nitesentinels/scanners/windows_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/windows_scanner.py)
  - Linux: [`nitesentinels/scanners/linux_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/linux_scanner.py)
  - WSL: [`nitesentinels/scanners/wsl_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/wsl_scanner.py)
- **Current Completion (95%):**
  - Evaluates Windows Defender status, Windows Firewall profiles (Domain/Private/Public), BitLocker encryption, UAC levels, Windows Update service, and SMBv1 exposure.
  - Linux audits verify SSH configuration (`PermitRootLogin`, `PasswordAuthentication`), UFW/iptables status, `/etc/shadow` and `/etc/passwd` permissions, and password aging policies.
  - Generates unified security score (0–100) and weighted risk classification.
- **Dev 1 Next Steps / Backlog:**
  1. Add support for macOS host audits (FileVault, Gatekeeper, SIP status).
  2. Implement detection for missing critical KB security patches on Windows Server.
  3. Fine-tune WSL scanner to differentiate between WSL1 and WSL2 virtualization limits.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `python main.py scan local` on Windows; table outputs severity, check name, status, and score.
  - [x] Execute `pytest tests/test_scanner.py` (Must pass without failures).
  - [x] Verify that non-admin execution gracefully logs warnings rather than raising uncaught exceptions.

---

### [FEAT-02] Remote Agentless Audit (SSH / WinRM / SNMP)
- **Primary Owner:** Person 1 (Dev 1)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Coordinator: [`nitesentinels/core/scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/scanner.py#scan_remote)
  - Firewall/SNMP: [`nitesentinels/scanners/firewall_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/firewall_scanner.py)
- **Current Completion (85%):**
  - SSH agentless Linux audit using `paramiko` executing remote non-destructive commands.
  - SNMP v2c/v3 firewall scanner for network devices.
- **Dev 1 Next Steps / Backlog:**
  1. Complete native WinRM remote scanner for agentless Windows Domain servers.
  2. Implement SSH private key passphrases and certificate-based authentication.
  3. Add connection timeout retry backoff and host fingerprint validation (`known_hosts`).
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_scanner.py -k "remote"`
  - [x] Test invalid credentials: verify proper error message is returned without leaking credentials into logs.
  - [x] Test SSH connection timeout handling against an unreachable IP.

---

### [FEAT-03] Sonic Recon & Asynchronous Port Scanner
- **Primary Owner:** Person 1 (Dev 1)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Async Port Scanner: [`nitesentinels/scanners/port_scanner_async.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/port_scanner_async.py)
  - Banner & Service: [`nitesentinels/scanners/service_detector.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/service_detector.py)
  - Sonic Threat Engine: [`nitesentinels/scanners/sonic_recon.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/sonic_recon.py)
  - Web UI: [`nitesentinels/web/port_scan_routes.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/port_scan_routes.py), [`port_scan.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/port_scan.html)
- **Current Completion (95%):**
  - Concurrent socket scanner supporting custom port ranges, top-100, and top-1000 ports.
  - Service heuristic banner grabbing for HTTP, SSH, FTP, SMTP, MySQL, Redis, RDP.
  - Sonic Recon threat scoring computes an overall risk score and categorizes open port exposure.
- **Dev 1 Next Steps / Backlog:**
  1. Add UDP port probe heuristics for common services (DNS, SNMP, NTP).
  2. Implement rate limiting and SYN scan packet pacing to avoid triggering IDS rate drops.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_port_scan_integration.py`
  - [x] Test CLI: `python main.py port_scan quick scanme.nmap.org --ports 80,443`
  - [x] Test Web UI: Submit port scan on `127.0.0.1` and verify live updates in `/port_scan`.

---

### [FEAT-04] AI / LLM Application Security Scanner
- **Primary Owner:** Person 1 (Dev 1)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Scanner: [`nitesentinels/scanners/llm_scanner.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/scanners/llm_scanner.py)
  - Persistence Store: [`nitesentinels/web/llm_store.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/llm_store.py)
  - REST Endpoints: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py) (Routes: `/api/llm/*`)
- **Current Completion (90%):**
  - Automated testing for Prompt Injection, Jailbreak susceptibility, Sensitive Data Leakage, and API Key / Auth checks.
  - SQLite storage for registered models, audit runs, and flagged vulnerabilities.
- **Dev 1 Next Steps / Backlog:**
  1. Expand OWASP Top 10 for LLM test library (Add Insecure Output Handling, Vector DB Poisoning checks).
  2. Implement custom adversarial prompt injection payload upload (JSON/CSV).
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_llm_scanner.py tests/test_llm_api.py`
  - [x] Test mock model scan via API and verify results appear in SQLite `data/llm_audit.db`.

---

### [FEAT-05] Scope-Gated Ethical OffSec Engine
- **Primary Owner:** Person 1 (Dev 1)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Engine: [`nitesentinels/offsec/engine.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/engine.py)
  - Scope Validation: [`nitesentinels/offsec/scope.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/scope.py), [`scope_io.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/scope_io.py)
  - Audit Trail: [`nitesentinels/offsec/audit.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/audit.py) -> `audit/audit.jsonl`
  - Recon & Web Tests: [`nitesentinels/offsec/recon.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/recon.py), [`webtests.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/offsec/webtests.py)
- **Current Completion (90%):**
  - Requires explicit `scope.yaml` defining authorized targets and legal acknowledgment.
  - Cryptographic audit trail logging every scan event into immutable `audit/audit.jsonl`.
  - Non-destructive web tests (security headers, CORS misconfigurations, cookie security, SSL/TLS expiry).
- **Dev 1 Next Steps / Backlog:**
  1. Add automated certificate revocation list (CRL) and OCSP stapling verification.
  2. Implement multi-target batch execution in `engine.py`.
- **QA Acceptance Criteria & Verification:**
  - [x] Attempt scan on an unauthorized domain; verify engine strictly rejects with `TargetOutOfScopeError`.
  - [x] Verify each executed scan appends a valid JSON line to `audit/audit.jsonl` with SHA-256 integrity hash.

---

### [FEAT-06] Platform Hub & Unified Navigation
- **Primary Owner:** Person 2 (Dev 2)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Hub Template: [`nitesentinels/web/templates/platform_hub.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/platform_hub.html)
  - Workspace Templates: `admin_workspace.html`, `system_workspace.html`, `reports_workspace.html`, `risk_register.html`
  - Routes: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py)
- **Current Completion (95%):**
  - Unified launchpad linking Host Auditing, Network Recon, HAM, Client Engagements, and Compliance workspaces.
  - Role-based visibility and responsive cyber-themed dark UI.
- **Dev 2 Next Steps / Backlog:**
  1. Add quick-search bar (`Cmd/Ctrl+K`) for universal search across clients, assets, and findings.
  2. Implement customized user theme preferences (Dark / AMOLED / High-Contrast).
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_workspace_navigation.py`
  - [x] Manual verification: Log in as `admin` and `viewer`, verify access control restrictions on workspace cards.

---

### [FEAT-07] Client Multi-Tenant Directory
- **Primary Owner:** Person 2 (Dev 2)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Templates: [`clients.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/clients.html), [`client_profile.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/client_profile.html)
  - Backend API: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py) (Routes: `/api/clients*`)
- **Current Completion (90%):**
  - Full CRUD operations for client organizations, contacts, industry classifications, and locations.
  - Client profile dashboard displaying associated assessments, active findings, and risk distribution.
- **Dev 2 Next Steps / Backlog:**
  1. Add pagination and sorting for deployments with 100+ clients.
  2. Add CSV/Excel client list export/import.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_engagement_api.py -k "client"`
  - [x] Run Phase 4 in `scratch_qa_pipeline.py` (Client creation, validation, XSS sanitization).

---

### [FEAT-08] Engagement Lifecycle & Target Authorization Scope
- **Primary Owner:** Person 2 (Dev 2)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Templates: [`engagements.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagements.html), [`engagement_overview.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_overview.html), [`engagement_scope.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_scope.html)
  - Backend API: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py)
- **Current Completion (95%):**
  - Formal 7-stage state machine: `DRAFT` -> `DISCOVERY` -> `ASSESSMENT` -> `VALIDATION` -> `REPORTING` -> `COMPLETED` -> `ARCHIVED`.
  - Target authorization engine supporting CIDR blocks, specific IPs, domain names, and explicit exclusion rules.
- **Dev 2 Next Steps / Backlog:**
  1. Implement electronic sign-off / RoE (Rules of Engagement) approval locking.
  2. Add automated calendar reminder notifications for assessment start and end dates.
- **QA Acceptance Criteria & Verification:**
  - [x] Run Phase 5 & 6 of `scratch_qa_pipeline.py`.
  - [x] Test scope validation API with included IP, included CIDR subnet, and excluded IP.

---

### [FEAT-09] Vulnerability Findings, Threat Scoring & Retest Workflow
- **Primary Owner:** Person 2 (Dev 2)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Templates: [`engagement_findings.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_findings.html), [`engagement_remediation.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_remediation.html), [`engagement_retest.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_retest.html)
  - Backend API: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py)
- **Current Completion (95%):**
  - Finding classification across Critical, High, Medium, Low, Informational.
  - CVSS v3.1 calculator support and contextual threat scoring.
  - Remediation assignment, SLA tracking, and structured retest cycle (`OPEN` -> `IN_REMEDIATION` -> `VERIFIED_FIXED` / `REOPENED`).
- **Dev 2 Next Steps / Backlog:**
  1. Add Jira / GitHub Issues bidirectional webhook syncing for remediation tickets.
  2. Add bulk findings status update functionality.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_engagement_api.py -k "finding or retest"`
  - [x] Run Phase 8 & 9 of `scratch_qa_pipeline.py`.

---

### [FEAT-10] Evidence Locker & Cryptographic Hashing
- **Primary Owner:** Person 2 (Dev 2)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Template: [`engagement_evidence.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_evidence.html)
  - Storage Backend: `data/evidence/`, [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py)
- **Current Completion (90%):**
  - File upload with automatic SHA-256 checksum generation.
  - Association of evidence files (screenshots, logs, pcaps) with specific vulnerability findings.
- **Dev 2 Next Steps / Backlog:**
  1. Implement virus scanning / ClamAV scan on file upload.
  2. Add cloud storage adapter (AWS S3 / MinIO) for enterprise multi-node deployments.
- **QA Acceptance Criteria & Verification:**
  - [x] Run Phase 10 of `scratch_qa_pipeline.py`.
  - [x] Upload test evidence file and verify stored SHA-256 matches `sha256sum <file>`.

---

### [FEAT-11] Hardware Asset Management (HAM) Subsystem
- **Primary Owner:** Person 3 (Dev 3)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Store: [`nitesentinels/web/ham_store.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/ham_store.py)
  - Routes: [`nitesentinels/web/ham_routes.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/ham_routes.py)
  - Engines: [`health_engine.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/ham/health_engine.py), [`risk_engine.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/ham/risk_engine.py)
  - Templates: `ham_dashboard.html`, `ham_assets.html`, `ham_asset_detail.html`, `ham_custody.html`, `ham_warranty.html`
- **Current Completion (95%):**
  - Complete asset lifecycle (Procured, Deployed, Maintenance, Retired, Disposed).
  - Health & Risk scoring engines calculating hardware degradation, warranty expiry, and security risks.
  - Chain-of-custody tracking with signature/acknowledgment logging.
  - QR code generation for asset labeling and mobile verification.
- **Dev 3 Next Steps / Backlog:**
  1. Add automated email alerts for warranties expiring within 30/60/90 days.
  2. Implement CSV bulk asset import with validation preview.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_ham_store.py tests/test_ham_api.py` (Must all pass).
  - [x] Verify QR code public verification URL: `/ham/public/qr/<asset_id>`.

---

### [FEAT-12] HAM Endpoint Agent & Heartbeat Service
- **Primary Owner:** Person 3 (Dev 3)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Agent Script: [`nitesentinels/ham/agent/nitesentinel_agent.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/ham/agent/nitesentinel_agent.py)
  - Agent Config: [`nitesentinels/ham/agent/agent_config.yaml.example`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/ham/agent/agent_config.yaml.example)
  - Agent API Endpoints: `POST /api/ham/agent/enroll`, `POST /api/ham/agent/checkin`
- **Current Completion (90%):**
  - Standalone, lightweight Python agent capable of running on Windows/Linux.
  - Enrolls via secure token, collects system hardware specs (CPU, RAM, Disks, MAC), and reports periodic heartbeats.
- **Dev 3 Next Steps / Backlog:**
  1. Package agent into standalone executable using PyInstaller (Windows `.exe` and Linux binary).
  2. Implement Windows Service and Linux `systemd` unit installer scripts.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_ham_store.py -k "agent"`
  - [x] Execute test agent check-in against local dev server and verify last-seen timestamp updates.

---

### [FEAT-13] Automated OS Hardening Engine
- **Primary Owner:** Person 3 (Dev 3)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Hardener Orchestrator: [`nitesentinels/core/hardener.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/hardener.py)
  - Windows: [`nitesentinels/hardeners/windows_hardener.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/hardeners/windows_hardener.py)
  - Linux: [`nitesentinels/hardeners/linux_hardener.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/hardeners/linux_hardener.py)
- **Current Completion (90%):**
  - Safe-by-default automated remediation: enables firewall profiles, secures SSH daemon (`PermitRootLogin no`), restricts dangerous file permissions.
  - Dry-run mode (`--dry-run`) allowing administrators to inspect proposed changes before applying.
- **Dev 3 Next Steps / Backlog:**
  1. Implement automated rollback / restore point snapshot mechanism.
  2. Add CIS Level 2 hardening benchmarks.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_hardener.py`
  - [x] Run `python main.py harden --help` and verify `--dry-run` and `--yes` flags work as expected.

---

### [FEAT-14] Regulatory Compliance Frameworks
- **Primary Owner:** Person 1 & Person 2
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Compliance Engine: [`nitesentinels/core/compliance/`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/compliance/)
  - DPDP 2023 Module: [`dpdp_2023.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/compliance/dpdp_2023.py)
  - Web Templates: `compliance.html`, `engagement_compliance.html`
- **Current Completion (90%):**
  - Multi-standard mapping for CIS Benchmarks v8, ISO/IEC 27001, PCI-DSS 4.0, NIST CSF, and India DPDP Act 2023.
  - Auto-calculates compliance percentage and flags non-compliant controls based on scanner telemetry.
- **Dev 1 & 2 Next Steps / Backlog:**
  1. Add HIPAA Security Rule mapping.
  2. Implement auditor export format (Excel spreadsheet with control-by-control evidence references).
- **QA Acceptance Criteria & Verification:**
  - [x] Run Phase 11 of `scratch_qa_pipeline.py`.
  - [x] Verify compliance score updates dynamically as finding statuses change.

---

### [FEAT-15] Executive & Technical Reporting Engine (PDF/HTML)
- **Primary Owner:** Person 2 & Person 3
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Report Generator: [`nitesentinels/core/reporter.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/core/reporter.py)
  - HTML & PDF Routes: [`nitesentinels/web/app.py`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/app.py)
  - Web Template: [`engagement_reports.html`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/nitesentinels/web/templates/engagement_reports.html)
- **Current Completion (95%):**
  - ReportLab PDF generation with professional cover page, risk matrices, finding details, and remediation timelines.
  - HTML web view fallback for browser-based reading and print-to-PDF.
- **Dev 2 & 3 Next Steps / Backlog:**
  1. Add custom agency logo and theme color customizer in UI settings.
  2. Implement automated password-protected PDF encryption.
- **QA Acceptance Criteria & Verification:**
  - [x] Run `pytest tests/test_reporter.py`
  - [x] Run `python main.py report --format pdf --output test_report.pdf` and inspect PDF page formatting.

---

### [FEAT-16] Database Migrations & DevOps CI/CD
- **Primary Owner:** Person 3 (Dev 3)
- **QA Tester:** Person 4 (QA)
- **Code Locations:**
  - Alembic Configuration: `alembic.ini`, [`alembic/`](file:///c:/Users/Nithyananthan/Desktop/SecureScope/alembic/)
  - Migration Scripts: `alembic/versions/`
  - Deployment Files: `run.bat`, `run.sh`, `render.yaml`, `vercel_wsgi.py`
- **Current Completion (80%):**
  - Alembic migrations established for port scan history.
  - Startup scripts for Windows (`run.bat`) and Linux (`run.sh`).
- **Dev 3 Next Steps / Backlog:**
  1. Provide production `Dockerfile` and `docker-compose.yml` (NiteSentinel + PostgreSQL + Redis).
  2. Set up GitHub Actions CI workflow for automated pytest execution on PRs.
  3. Unify SQLite stores into SQLAlchemy models for multi-user concurrent write scaling.
- **QA Acceptance Criteria & Verification:**
  - [x] Execute `alembic upgrade head` and verify schema migrations apply cleanly.
  - [x] Validate zero regression in pytest suite after migrations.

---

## 5. Developer & Tester Quick-Start Runbook

### 5.1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/nithyananthantechy/Securescopes.git
cd SecureScope

# Create & activate Python virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 5.2. Running the Application
```bash
# Standard Production Web Server (Port 8080)
python main.py web --port 8080

# Demo Mode (Pre-populated with presentation data)
python main.py web --port 8080 --demo
```
- **Web UI:** `http://localhost:8080`
- **Default Credentials:**
  - Admin: `admin` / `NiteSentinel@2026`
  - Auditor: `nitechspark` / `NiteSentinel@2026`
  - Viewer: `viewer` / `ViewOnly@2026`

### 5.3. Running Automated Tests (QA Runbook)
```bash
# Run entire test suite (136 tests)
python -m pytest tests/ -v

# Run fast non-network tests
python -m pytest tests/ -k "not remote and not port_scan"

# Run end-to-end QA validation pipeline
python scratch_qa_pipeline.py
```

---

## 6. Handover Sprints & Milestones

### Sprint 1: Knowledge Transfer & Baseline Stabilization (Week 1)
- **Dev 1:** Review Scanner & Sonic Recon engines; establish host test environments.
- **Dev 2:** Review Web application routes, CSRF protections, and Platform Hub templates.
- **Dev 3:** Review HAM SQLite stores, agent heartbeat protocol, and Alembic migrations.
- **QA:** Run baseline test suite (136 tests) and execute `scratch_qa_pipeline.py`.

### Sprint 2: Core Enhancements & Agent Polish (Week 2)
- **Dev 1:** Expand LLM injection heuristics and WinRM remote auditing.
- **Dev 2:** Enhance engagement finding filters and evidence upload preview.
- **Dev 3:** Package HAM endpoint agent with PyInstaller and test heartbeat reliability.
- **QA:** Execute security edge case tests (SQLi/XSS sanitization, role boundary enforcement).

### Sprint 3: Containerization & Integration (Week 3)
- **Dev 1:** Refine compliance control scoring across ISO 27001 and DPDP 2023.
- **Dev 2:** Build universal search shortcut and client CSV export.
- **Dev 3:** Complete `Dockerfile` and `docker-compose.yml`; create GitHub Actions CI workflow.
- **QA:** Validate multi-browser compatibility (Chrome, Firefox, Edge) and load test concurrent port scans.

### Sprint 4: Final Sign-off & Production Readiness (Week 4)
- **Dev 1, 2, 3:** Code freeze, bug burn-down, and documentation finalization.
- **QA:** Comprehensive regression test pass and official handover verification sign-off.
- **Leadership Handover:** Final repository transfer and sign-off meeting.

---
*Document maintained by NITECHSPARK IT Security & DevOps.*
