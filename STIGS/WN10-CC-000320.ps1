<#
.SYNOPSIS
    This PowerShell script requires that Internet Explorer prompts users before allowing web-based programs to install software
    
.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000320

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000320.ps1 
#>

# Define registry path and value
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$RegistryName = "SafeForScripting"

# Check if the registry key exists
if (Test-Path $RegistryPath) {
    $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $RegistryName -ErrorAction SilentlyContinue).$RegistryName

    if ($CurrentValue -eq 1) {
        Write-Output "SafeForScripting is incorrectly set to 1. Fixing the issue..."
        
        # Remove the registry value to restore default behavior
        Remove-ItemProperty -Path $RegistryPath -Name $RegistryName -Force -ErrorAction SilentlyContinue
        Write-Output "SafeForScripting has been removed, restoring the default secure behavior."

    } elseif ($CurrentValue -eq 0) {
        Write-Output "SafeForScripting is correctly set to 0. No action needed."
    } else {
        Write-Output "SafeForScripting is not set to 1. No action needed."
    }

} else {
    Write-Output "Registry path does not exist. The system is compliant by default."
}

# Verify the change
if (!(Test-Path "$RegistryPath\$RegistryName")) {
    Write-Output "Verification: SafeForScripting has been successfully removed or was never set."
} else {
    Write-Output "Verification: SafeForScripting still exists. Please check manually."
}
