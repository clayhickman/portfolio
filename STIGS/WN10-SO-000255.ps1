<#
.SYNOPSIS
    This PowerShell script prevents standard users from receiving User Account Control (UAC) elevation prompts.
.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000255

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000255.ps1 
#>

# Define registry path and values
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegistryName = "ConsentPromptBehaviorUser"
$RegistryValue = 0  # Automatically deny elevation requests for standard users

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
    Write-Output "UAC elevation prompts for standard users have been successfully disabled."
} else {
    Write-Output "Failed to configure ConsentPromptBehaviorUser. Please check manually."
}
