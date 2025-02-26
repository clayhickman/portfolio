<#
.SYNOPSIS
    This PowerShell script checks for and disables SMBv1 using "Disable-WindowsOptionalFeature".

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000160

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-00-000160.ps1 
#>

# Function to check SMBv1 status
function Check-SMBv1Status {
    $smbState = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -eq "SMB1Protocol"
    if ($smbState.State -eq "Enabled") {
        Write-Output "SMBv1 is currently ENABLED. Proceeding with remediation..."
        return $true
    } else {
        Write-Output "SMBv1 is already DISABLED. No action needed."
        return $false
    }
}

# Function to disable SMBv1
function Disable-SMBv1 {
    Write-Output "Disabling SMBv1 protocol..."
    
    # Disable SMBv1 using Windows Features
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue

    # Disable SMBv1 in the registry (backup method)
    Write-Output "Updating registry settings for additional security..."
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force

    # Disable SMBv1 client-side support
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord -Force

    Write-Output "SMBv1 has been disabled. A restart is required to fully apply the changes."
}

# Main Execution
if (Check-SMBv1Status) {
    Disable-SMBv1
    # Prompt for restart
    $restart = Read-Host "A restart is required to complete the process. Restart now? (Y/N)"
    if ($restart -match "[Yy]") {
        Restart-Computer -Force
    } else {
        Write-Output "Please remember to restart the system manually."
    }
}
