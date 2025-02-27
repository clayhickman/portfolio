<#
.SYNOPSIS
    This PowerShell script disables camera access on the lock screen.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000066 

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000066.ps1 
#>

# Define registry path and values
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$RegistryName = "ProcessCreationIncludeCmdLine_Enabled"
$RegistryValue = 1

# Ensure the registry path exists
if (!(Test-Path $RegistryPath)) {
    Write-Output "Creating registry path: $RegistryPath"
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Set the required registry value
Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Type DWord -Force

# Verify the setting
$CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $RegistryName).$RegistryName
if ($CurrentValue -eq $RegistryValue) {
    Write-Output "Process Creation Logging for command-line auditing has been successfully enabled."
} else {
    Write-Output "Failed to configure ProcessCreationIncludeCmdLine_Enabled. Please check manually."
}
