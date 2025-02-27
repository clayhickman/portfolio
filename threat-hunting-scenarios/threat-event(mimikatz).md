# Threat Event (Credential Dumping with Mimikatz)
**Unauthorized Execution of Mimikatz**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download Mimikatz:
  - Obtained mimikatz_trunk.zip from a known repository or a malicious link (e.g., http://malicious-example.com/mimikatz_trunk.zip)
  - Extracted it to a temporary folder: C:\Users\<User>\AppData\Local\Temp\mimikatz\
2. Execute Mimikatz:
  - Renamed the binary to mimi64.exe to evade basic file-name detections.
  - Ran Mimikatz with typical arguments to dump credentials from LSASS:
    ```mimi64.exe "privilege::debug" "sekurlsa::logonpasswords" exit```
3. Attempt to Dump Credentials:
  - Mimikatz accesses the LSASS process (lsass.exe) to read privileged memory.
  - Cred dumps might be output to a file, e.g. C:\Users\<User>\AppData\Local\Temp\creddump.txt.
4. Exfiltrate or Store the Dump File:
  - Attacker may copy creddump.txt to a network share or upload it to a remote host.
  - Afterward, the file is often deleted to cover tracks.
5. Cleanup:
  - Clears PowerShell or Windows Event Logs to hide evidence of unauthorized usage.
  - Removes or renames Mimikatz-related artifacts to avoid detection in subsequent scans.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting the download of the Mimikatz ZIP or EXE file, as well as any credential dump files created.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the Mimikatz process creation (mimi64.exe), command-line arguments, and any subsequent processes launched.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| If Mimikatz or a related script attempts to exfiltrate the credential dump file, these logs can detect unusual outbound traffic.|

---

## Related Queries:
```kql
// 1. Detect known Mimikatz file downloads or suspicious file name patterns
DeviceFileEvents
| where FileName has_any ("mimikatz", "mimi64", "mimi.exe", "mimikatz_trunk")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName

// 2. Identify Mimikatz execution via typical file names or rename attempts
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "mimi64.exe", "mimi.exe")
    or ProcessCommandLine has_any ("mimikatz", "mimi64", "sekurlsa::logonpasswords", "privilege::debug")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ActionType

// 3. Detect creation of the credential dump file (e.g. creddump.txt)
DeviceFileEvents
| where FileName has_any("creddump.txt", "dump.txt", "dumplsass.txt")
| project Timestamp, DeviceName, FileName, ActionType, FolderPath, InitiatingProcessCommandLine

// 4. Look for unusual outbound connections that might indicate data exfiltration
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("mimikatz.exe", "mimi64.exe", "mimi.exe", "powershell.exe")
| where RemoteIP != "InternalIPs"  // Adjust for your environment's internal IP ranges
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// 5. Check for event log clearing after Mimikatz usage
DeviceProcessEvents
| where ProcessCommandLine has_any ("wevtutil cl", "Clear-EventLog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ActionType
```

---

## Created By:
- **Author Name**: Clay Hickman
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: February 26, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `February 26, 2025`  | `Clay Hickman`   
