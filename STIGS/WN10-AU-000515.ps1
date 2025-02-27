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
    STIG-ID         : WN10-AU-000515

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AU-000515.ps1 
#>

# Define the log file path
$LogPath = "C:\Windows\System32\winevt\Logs\Application.evtx"

# Function to set correct permissions
function Set-ApplicationLogPermissions {
    # Import required module
    Import-Module NtObjectManager -ErrorAction SilentlyContinue

    # Get the current ACL
    $Acl = Get-Acl -Path $LogPath

    # Define allowed security principals
    $AllowedPrincipals = @(
        "NT SERVICE\Eventlog",
        "NT AUTHORITY\SYSTEM",
        "BUILTIN\Administrators"
    )

    # Remove all current permissions
    $Acl.Access | ForEach-Object {
        $Acl.RemoveAccessRule($_)
    }

    # Grant Full Control to required accounts
    foreach ($Principal in $AllowedPrincipals) {
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, "FullControl", "Allow")
        $Acl.SetAccessRule($AccessRule)
    }

    # Apply the new ACL
    Set-Acl -Path $LogPath -AclObject $Acl

    Write-Output "Permissions on Application.evtx have been corrected."
}

# Execute the function
Set-ApplicationLogPermissions
