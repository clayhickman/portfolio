<#
.SYNOPSIS
    This PowerShell script disables autorun for all drive types to prevent unauthorized code execution on removable media.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000190

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000190.ps1 
#>

# Define registry path and values
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$RegistryName = "NoDriveTypeAutoRun"
$RegistryValue = 0x000000ff  # 255 in decimal

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
    Write-Output "AutoRun has been successfully disabled for all drive types."
} else {
    Write-Output "Failed to configure NoDriveTypeAutoRun. Please check manually."
}
