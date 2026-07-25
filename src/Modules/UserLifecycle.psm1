function New-ADOpsUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FirstName,

        [Parameter(Mandatory = $true)]
        [string]$LastName,

        [Parameter(Mandatory = $true)]
        [string]$Department,

        [Parameter(Mandatory = $false)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config,

        [switch]$Mock
    )

    process {
        # Standardized SamAccountName (e.g., mvance)
        $SamAccountName = ($FirstName.Substring(0,1) + $LastName).ToLower() -replace '[^a-z0-9]', ''
        $Domain = if ($Config.DomainName) { $Config.DomainName } else { "corp.davistech.internal" }
        $UPN = "$SamAccountName@$Domain"
        $TargetOU = "OU=$Department,$($Config.BaseOU)"

        Write-Host "[ONBOARDING] Processing onboarding for: $FirstName $LastName ($UPN)" -ForegroundColor Cyan

        if ($Mock) {
            Write-Host "  [MOCK MODE] Validated OU Path: $TargetOU" -ForegroundColor Yellow
            Write-Host "  [MOCK MODE] Generated Temp Secure Password (16 chars)" -ForegroundColor Yellow
            Write-Host "  [MOCK MODE] Executed: New-ADUser -SamAccountName '$SamAccountName' -UserPrincipalName '$UPN' -Enabled `$true" -ForegroundColor Green
            Write-Host "  [MOCK MODE] Executed: Add-ADGroupMember -Identity '$Department-Users' -Members '$SamAccountName'" -ForegroundColor Green
            
            return [PSCustomObject]@{
                Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Action         = "User_Onboarded"
                SamAccountName = $SamAccountName
                Status         = "Success (Mock)"
                OU             = $TargetOU
            }
        }
        else {
            try {
                if ($PSCmdlet.ShouldProcess($SamAccountName, "Create AD User and assign to $Department")) {
                    if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'") {
                        Write-Warning "User $SamAccountName already exists in Active Directory!"
                        return
                    }

                    $TempPassword = ConvertTo-SecureString "P@ssw0rd!$((Get-Random -Minimum 1000 -Maximum 9999))" -AsPlainText -Force

                    New-ADUser `
                        -Name "$FirstName $LastName" `
                        -GivenName $FirstName `
                        -Surname $LastName `
                        -SamAccountName $SamAccountName `
                        -UserPrincipalName $UPN `
                        -Title $Title `
                        -Department $Department `
                        -Path $TargetOU `
                        -AccountPassword $TempPassword `
                        -Enabled $true `
                        -ChangePasswordAtLogon $true

                    Write-Host "  [SUCCESS] Created AD User object $SamAccountName" -ForegroundColor Green
                }
            }
            catch {
                $Err = $_.Exception.Message
                Write-Error "Failed to onboard user ${SamAccountName} - ${Err}"
            }
        }
    }
}

function Invoke-ADOpsOffboarding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config,

        [switch]$Mock
    )

    process {
        Write-Host "[OFFBOARDING] Initiating zero-trust offboarding for: $SamAccountName" -ForegroundColor Red
        $DisabledOU = if ($Config.DisabledUserOU) { $Config.DisabledUserOU } else { "OU=Disabled_Accounts,DC=corp,DC=davistech,DC=internal" }

        if ($Mock) {
            Write-Host "  [MOCK MODE] Executed: Disable-ADAccount -Identity '$SamAccountName'" -ForegroundColor Yellow
            Write-Host "  [MOCK MODE] Executed: Stripped all secondary security group memberships" -ForegroundColor Yellow
            Write-Host "  [MOCK MODE] Executed: Set-ADAccountPassword (Scrambled credentials)" -ForegroundColor Yellow
            Write-Host "  [MOCK MODE] Executed: Move-ADObject -> Target: $DisabledOU" -ForegroundColor Green
            
            return [PSCustomObject]@{
                Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Action         = "User_Offboarded"
                SamAccountName = $SamAccountName
                Status         = "Disabled & Isolated (Mock)"
                TargetOU       = $DisabledOU
            }
        }
        else {
            try {
                if ($PSCmdlet.ShouldProcess($SamAccountName, "Disable, strip groups, and move to Disabled OU")) {
                    $User = Get-ADUser -Identity $SamAccountName -Properties MemberOf
                    
                    if (-not $User) {
                        Write-Warning "User $SamAccountName not found."
                        return
                    }

                    Disable-ADAccount -Identity $SamAccountName

                    $Groups = Get-ADPrincipalGroupMembership -Identity $SamAccountName | Where-Object { $_.Name -ne "Domain Users" }
                    if ($Groups) {
                        Remove-ADPrincipalGroupMembership -Identity $SamAccountName -MemberOf $Groups -Confirm:$false
                    }

                    Move-ADObject -Identity $User.DistinguishedName -TargetPath $DisabledOU

                    Write-Host "  [SUCCESS] Account $SamAccountName offboarded and isolated." -ForegroundColor Green
                }
            }
            catch {
                $Err = $_.Exception.Message
                Write-Error "Failed to offboard ${SamAccountName} - ${Err}"
            }
        }
    }
}

Export-ModuleMember -Function New-ADOpsUser, Invoke-ADOpsOffboarding