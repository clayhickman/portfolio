<#
.SYNOPSIS
    This PowerShell script configures the Windows Telemetry level to limit data collection.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000205

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000205.ps1 
#>

# Define registry path and values
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$RegistryName = "AllowTelemetry"
$RegistryValue = 0  # Default to Security (Most Restrictive)

# Prompt user for telemetry level (0=Security, 1=Basic, 2=Enhanced)
$UserInput = Read-Host "Enter the Telemetry Level (0=Security, 1=Basic, 2=Enhanced - Only if Windows Analytics is used)"
if ($UserInput -match "^[012]$") {
    $RegistryValue = [int]$UserInput
} else {
    Write-Output "Invalid input. Defaulting to Security (0)."
}

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
    Write-Output "Telemetry level has been successfully set to $RegistryValue."
} else {
    Write-Output "Failed to configure AllowTelemetry. Please check manually."
}
