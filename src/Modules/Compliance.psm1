function Invoke-ADOpsComplianceAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [switch]$Remediate,

        [switch]$Mock
    )

    process {
        Write-Host "[COMPLIANCE] Starting Directory Security & Privileged Group Audit..." -ForegroundColor Cyan
        
        $PrivilegedGroups = $Config.PrivilegedGroups
        $ApprovedAdmins = $Config.ApprovedDomainAdmins
        $AuditResults = @()

        foreach ($Group in $PrivilegedGroups) {
            Write-Host "  Checking membership for privileged group: ${Group}" -ForegroundColor Gray

            if ($Mock) {
                # Simulated detection of an unauthorized account
                $CurrentMembers = @("sec_admin_davis", "svc_ad_automation", "unauthorized_contractor")

                foreach ($Member in $CurrentMembers) {
                    $IsApproved = $ApprovedAdmins -contains $Member

                    if (-not $IsApproved) {
                        Write-Host "  [ALERT] Unauthorized member found in ${Group} - ${Member}" -ForegroundColor Red
                        
                        if ($Remediate) {
                            Write-Host "    [REMEDIATION] Automatically revoking ${Member} from ${Group}" -ForegroundColor Yellow
                        }

                        $AuditResults += [PSCustomObject]@{
                            Timestamp      = (Get-Date -Format "o")
                            Group          = $Group
                            User           = $Member
                            Status         = "NON_COMPLIANT"
                            ActionTaken    = if ($Remediate) { "REVOKED" } else { "FLAGGED" }
                            Severity       = "CRITICAL"
                            ComplianceType = "PrivilegedGroupDrift"
                        }
                    }
                    else {
                        $AuditResults += [PSCustomObject]@{
                            Timestamp      = (Get-Date -Format "o")
                            Group          = $Group
                            User           = $Member
                            Status         = "COMPLIANT"
                            ActionTaken    = "NONE"
                            Severity       = "INFO"
                            ComplianceType = "PrivilegedGroupDrift"
                        }
                    }
                }
            }
            else {
                # Live Active Directory Query
                try {
                    $Members = Get-ADGroupMember -Identity $Group | Select-Object -ExpandProperty SamAccountName

                    foreach ($Member in $Members) {
                        if ($ApprovedAdmins -notcontains $Member) {
                            Write-Warning "Unauthorized user '${Member}' detected in '${Group}'!"

                            if ($Remediate) {
                                Remove-ADGroupMember -Identity $Group -Members $Member -Confirm:$false
                                Write-Host "Revoked ${Member} from ${Group}" -ForegroundColor Yellow
                            }

                            $AuditResults += [PSCustomObject]@{
                                Timestamp      = (Get-Date -Format "o")
                                Group          = $Group
                                User           = $Member
                                Status         = "NON_COMPLIANT"
                                ActionTaken    = if ($Remediate) { "REVOKED" } else { "FLAGGED" }
                                Severity       = "CRITICAL"
                                ComplianceType = "PrivilegedGroupDrift"
                            }
                        }
                    }
                }
                catch {
                    $Err = $_.Exception.Message
                    Write-Error "Failed to query group ${Group} - ${Err}"
                }
            }
        }

        # Export findings to JSON audit log for Azure Log Analytics / SIEM ingestion
        if ($Config.LogPath) {
            $LogDir = Split-Path -Path $Config.LogPath -Parent
            if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
            
            $AuditResults | ConvertTo-Json | Set-Content -Path $Config.LogPath
            Write-Host "  [AUDIT LOG] Written to $($Config.LogPath) (SIEM / Log Analytics format)" -ForegroundColor Green
        }

        return $AuditResults
    }
}

Export-ModuleMember -Function Invoke-ADOpsComplianceAudit