# AD-OpsGuard 🛡️
> Enterprise Active Directory Lifecycle & Security Compliance Automation Engine

AD-OpsGuard is a modular PowerShell framework designed for hybrid-ready identity management. It automates high-volume user onboarding and zero-trust offboarding pipelines while continuously auditing privileged directory groups (`Domain Admins`, `Enterprise Admins`) to prevent privileged access drift and unapproved group modifications.

---

## 📐 Architecture & Repository Structure

```text
AD-OpsGuard/
├── assets/                  # Visual evidence & documentation screenshots
│   ├── 02_execution_run.png
│   └── 03_audit_log_json.png
├── data/                    # Pipeline input feeds
│   ├── new_hires.csv
│   └── terminations.csv
├── logs/                    # Audit telemetry output (SIEM/Log Analytics)
│   └── ad_opsguard_audit.json
└── src/                     # Core engine codebase
    ├── Config/
    │   └── settings.json
    ├── Modules/
    │   ├── Compliance.psm1
    │   └── UserLifecycle.psm1
    └── AD-OpsGuard.ps1