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
    STIG-ID         : WN10-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000005.ps1 
#>

# Function to check if a camera is present
function Check-CameraPresence {
    $cameras = Get-PnpDevice -Class Camera -Status OK
    if ($cameras) {
        Write-Output "Camera detected. Proceeding with registry update..."
        return $true
    } else {
        Write-Output "No camera detected. This STIG is Not Applicable (NA)."
        return $false
    }
}

# Function to disable camera on the lock screen
function Disable-LockScreenCamera {
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $RegistryName = "NoLockScreenCamera"
    $RegistryValue = 1

    # Ensure the registry path exists
    if (!(Test-Path $RegistryPath)) {
        Write-Output "Creating registry path: $RegistryPath"
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Set the NoLockScreenCamera registry value
    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Type DWord -Force

    Write-Output "Camera on lock screen has been disabled."
}

# Main Execution
if (Check-CameraPresence) {
    Disable-LockScreenCamera
}
