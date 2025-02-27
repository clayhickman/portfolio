<#
.SYNOPSIS
    This PowerShell script ensures that non-privileged groups (Everyone, Users, or Authenticated Users) do not have more than Read permission on critical registry hives.

.NOTES
    Author          : Clay Hickman
    LinkedIn        : linkedin.com/in/clay-h-980ba5262
    GitHub          : github.com/clayhickman
    Date Created    : 2025-02-26
    Last Modified   : 2025-02-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-RG-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-RG-000005.ps1 
#>

# Define registry paths
$RegistryPaths = @(
    "HKLM:\SECURITY",
    "HKLM:\SOFTWARE",
    "HKLM:\SYSTEM"
)

# Define required permissions
$RequiredPermissions = @(
    @{Principal = "SYSTEM"; Rights = "FullControl"},
    @{Principal = "Administrators"; Rights = "FullControl"},
    @{Principal = "CREATOR OWNER"; Rights = "FullControl"},
    @{Principal = "ALL APPLICATION PACKAGES"; Rights = "Read"},
    @{Principal = "Users"; Rights = "Read"}
)

# Function to reset permissions on a registry key
function Set-RegistryPermissions {
    param (
        [string]$RegPath
    )

    Write-Output "Checking and fixing permissions for: $RegPath"

    # Get current ACL
    $Acl = Get-Acl -Path $RegPath

    # Remove any unauthorized entries
    $Acl.Access | ForEach-Object {
        if ($_.IdentityReference -match "Everyone|Authenticated Users|Users" -and $_.FileSystemRights -ne "ReadKey") {
            Write-Output "Removing unauthorized permission: $($_.IdentityReference) from $RegPath"
            $Acl.RemoveAccessRule($_)
        }
    }

    # Apply required permissions
    foreach ($Entry in $RequiredPermissions) {
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $Entry.Principal, $Entry.Rights, "ContainerInherit, ObjectInherit", "None", "Allow"
        )
        $Acl.SetAccessRule($Rule)
    }

    # Apply updated ACL
    Set-Acl -Path $RegPath -AclObject $Acl
    Write-Output "Permissions updated for $RegPath"
}

# Iterate through registry paths and fix permissions
foreach ($Path in $RegistryPaths) {
    if (Test-Path $Path) {
        Set-RegistryPermissions -RegPath $Path
    } else {
        Write-Output "Skipping $Path (Path does not exist or is inaccessible)."
    }
}

Write-Output "Registry permissions have been successfully configured."
