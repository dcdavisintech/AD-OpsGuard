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
```
    ## ✨ Key Features

* **Automated User Onboarding Pipeline:** Parses incoming user feeds (`new_hires.csv`), standardizes identity naming conventions (`SamAccountName`, `UPN`), generates temporary credentials, and provisions accounts directly into target OUs.
* **Zero-Trust Offboarding Pipeline:** Processes offboarding lists (`terminations.csv`), instantly disables accounts, strips all secondary security group memberships, scrambles credentials, and moves objects to an isolated Quarantine OU.
* **Privileged Group Compliance Engine:** Continuously monitors `Domain Admins` and `Enterprise Admins` against an approved administrator baseline (`settings.json`).
* **Automated Drift Remediation:** Automatically revokes unauthorized group additions in real time when executed with `-Remediate`.
* **SIEM-Ready Audit Telemetry:** Outputs structured JSON logs formatted for direct ingestion into Azure Log Analytics, Microsoft Sentinel, or Splunk.
* **Safe Dry-Run Execution:** Supports a full `-Mock` execution mode allowing validation across non-domain endpoint devices.

---

## 🛠️ Configuration (`settings.json`)

```json
{
  "DomainName": "corp.davistech.internal",
  "BaseOU": "OU=Corporate,DC=corp,DC=davistech,DC=internal",
  "DisabledUserOU": "OU=Disabled_Accounts,OU=Corporate,DC=corp,DC=davistech,DC=internal",
  "PrivilegedGroups": [
    "Domain Admins",
    "Enterprise Admins"
  ],
  "ApprovedDomainAdmins": [
    "sec_admin_davis",
    "svc_ad_automation",
    "breakglass_admin"
  ],
  "LogPath": "./logs/ad_opsguard_audit.json"
}
```

## 🚀 Usage & Execution

### Run Full End-to-End Orchestration (Mock Mode + Remediation)
```powershell
.\src\AD-OpsGuard.ps1 -Action FullRun -Mock -Remediate
### Run Individual Workflows
```powershell
# Execute Onboarding Pipeline Only
.\src\AD-OpsGuard.ps1 -Action Onboard -Mock

# Execute Zero-Trust Offboarding Pipeline Only
.\src\AD-OpsGuard.ps1 -Action Offboard -Mock

# Run Security Audit Only
.\src\AD-OpsGuard.ps1 -Action Audit -Mock -Remediate
