<#
.SYNOPSIS
    This PowerShell script requires that domain users be prevented from using PINs for logon.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000370

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000370.ps1 
#>

# Define registry path and values
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
$RegistryName = "AllowDomainPINLogon"
$RegistryValue = 0  # Disable domain PIN logon

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
    Write-Output "Domain PIN logon has been successfully disabled."
} else {
    Write-Output "Failed to configure AllowDomainPINLogon. Please check manually."
}
