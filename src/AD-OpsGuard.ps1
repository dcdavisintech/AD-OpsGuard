<#
.SYNOPSIS
    AD-OpsGuard - Enterprise Active Directory Lifecycle & Security Compliance Orchestrator
.DESCRIPTION
    Automates user onboarding/offboarding pipelines and enforces privileged group compliance baselines.
    Designed for hybrid-ready AD/Entra ID enterprise environments.
.PARAMETER Action
    The operation to execute: Onboard, Offboard, Audit, or FullRun.
.PARAMETER Mock
    Runs the engine in local simulation mode without requiring live RSAT/AD domain connectivity.
.EXAMPLE
    .\src\AD-OpsGuard.ps1 -Action FullRun -Mock
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Onboard", "Offboard", "Audit", "FullRun")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\src\Config\settings.json",

    [switch]$Mock,

    [switch]$Remediate
)

# 1. Environment & Module Initialization
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "  AD-OpsGuard: Identity & Access Compliance Engine        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Magenta

# Load Configuration
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found at: $ConfigPath"
    exit 1
}

# Parsed for standard PowerShell 5.1 compatibility
$RawJson = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$Config = @{}
$RawJson.psobject.properties | ForEach-Object { $Config[$_.Name] = $_.Value }

Write-Host "[INIT] Loaded configuration for domain: $($Config.DomainName)" -ForegroundColor Green

# Import Custom Modules
$UserModule = Join-Path $ScriptDir "Modules\UserLifecycle.psm1"
$ComplianceModule = Join-Path $ScriptDir "Modules\Compliance.psm1"

if ((Test-Path $UserModule) -and (Test-Path $ComplianceModule)) {
    Import-Module $UserModule -Force
    Import-Module $ComplianceModule -Force
    Write-Host "[INIT] UserLifecycle and Compliance modules loaded successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to locate required modules in $ScriptDir\Modules\"
    exit 1
}

# 2. Execution Logic
try {
    switch ($Action) {
        "Onboard" {
            Write-Host "`n--- Running User Onboarding Pipeline ---" -ForegroundColor Yellow
            $HiresPath = ".\data\new_hires.csv"
            if (Test-Path $HiresPath) {
                $NewHires = Import-Csv -Path $HiresPath
                foreach ($User in $NewHires) {
                    New-ADOpsUser -FirstName $User.FirstName `
                                  -LastName $User.LastName `
                                  -Department $User.Department `
                                  -Title $User.Title `
                                  -Config $Config `
                                  -Mock:$Mock
                }
            } else {
                Write-Warning "Input data file not found: $HiresPath"
            }
        }

        "Offboard" {
            Write-Host "`n--- Running Zero-Trust Offboarding Pipeline ---" -ForegroundColor Yellow
            $TermPath = ".\data\terminations.csv"
            if (Test-Path $TermPath) {
                $Terminations = Import-Csv -Path $TermPath
                foreach ($Term in $Terminations) {
                    Invoke-ADOpsOffboarding -SamAccountName $Term.SamAccountName `
                                            -Config $Config `
                                            -Mock:$Mock
                }
            } else {
                Write-Warning "Input data file not found: $TermPath"
            }
        }

        "Audit" {
            Write-Host "`n--- Running Privileged Group Compliance Audit ---" -ForegroundColor Yellow
            Invoke-ADOpsComplianceAudit -Config $Config `
                                       -Remediate:$Remediate `
                                       -Mock:$Mock
        }

        "FullRun" {
            Write-Host "`n--- Running Full End-to-End Orchestration ---" -ForegroundColor Yellow
            
            # Run Onboarding
            $HiresPath = ".\data\new_hires.csv"
            if (Test-Path $HiresPath) {
                $NewHires = Import-Csv -Path $HiresPath
                foreach ($User in $NewHires) {
                    New-ADOpsUser -FirstName $User.FirstName -LastName $User.LastName -Department $User.Department -Title $User.Title -Config $Config -Mock:$Mock
                }
            }

            # Run Offboarding
            $TermPath = ".\data\terminations.csv"
            if (Test-Path $TermPath) {
                $Terminations = Import-Csv -Path $TermPath
                foreach ($Term in $Terminations) {
                    Invoke-ADOpsOffboarding -SamAccountName $Term.SamAccountName -Config $Config -Mock:$Mock
                }
            }

            # Run Security Audit
            Invoke-ADOpsComplianceAudit -Config $Config -Remediate:$Remediate -Mock:$Mock
        }
    }

    Write-Host "`n==========================================================" -ForegroundColor Magenta
    Write-Host "  AD-OpsGuard Execution Completed Successfully.            " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Magenta
}
catch {
    Write-Error "Execution halted due to an unhandled error: $_"
}