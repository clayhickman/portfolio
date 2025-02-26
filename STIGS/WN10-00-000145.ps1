<#
.SYNOPSIS
    This PowerShell script enforces DEP (Data Execution Prevention) compliance.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000145

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-00-000145.ps1 
#>

# Function to check the current DEP configuration
function Check-DEPStatus {
    $depStatus = bcdedit /enum "{current}" | Select-String "nx"

    if ($depStatus -match "OptOut") {
        Write-Output "DEP is already set to 'OptOut'. No action needed."
        return $false
    }
    elseif ($depStatus -match "AlwaysOn") {
        Write-Output "DEP is set to 'AlwaysOn'. This is a more restrictive setting, and it is compliant."
        return $false
    }
    else {
        Write-Output "DEP is NOT configured correctly. Current setting: $depStatus"
        return $true
    }
}

# Function to set DEP to OptOut
function Set-DEPOptOut {
    Write-Output "Setting DEP to 'OptOut'..."
    bcdedit /set "{current}" nx OptOut
    Write-Output "DEP has been set to 'OptOut'. A restart is required for the changes to take effect."
}

# Main Execution
if (Check-DEPStatus) {
    Set-DEPOptOut

    # Prompt for restart
    $restart = Read-Host "A restart is required to apply changes. Restart now? (Y/N)"
    if ($restart -match "[Yy]") {
        Restart-Computer -Force
    } else {
        Write-Output "Please remember to restart the system manually."
    }
}
