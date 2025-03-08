# Threat Hunt Report (Credential Dumping with Mimikatz)
**Unauthorized Execution of Mimikatz**

## Example Scenario:
During a routine security review, the SOC team received indicators that Mimikatz had been downloaded and executed in the environment. Potential use of Mimikatz poses a significant threat, as it can extract credentials from memory (LSASS), leading to privilege escalation and lateral movement across the domain. Additionally, suspicious commands have been ran that would indicate that an individual is attempting to cover their tracks. The goal is to detect and determine the intention behind any Mimikatz usage. Report any findings to management.

---

## High-Level Mimikatz related IoC Discovery Plan:
1. Check DeviceFileEvents for any mimikatz related events
2. Check DeviceProcessEvents for any signs of Mimikatz installation / execution, or exfiltration related commands.
3. Check DeviceNetworkEvents for any signs of outbound connections to remote hosts that may be used for exfiltration purposes.

---

## Steps Taken

1. Searched the `DeviceFileEvents` table for Mimikatz

Searched for any instances of Mimikatz being downloaded onto the device, and discovered that at '2025-03-01T22:37:51.0340907Z' the InitiatingProcessAccountName "cmh-cyber" had performed the download of "mimikatz-main.zip". At '2025-03-02T00:30:51.3210787Z' the "mimikatz-main.zip" file was extracted into 'C:\Users\cmh-cyber\AppData\Local\Temp'. After extraction, it appears that the executable "mimikatz.exe" was renamed to "mimi64.exe" at '2025-03-02T00:31:13.4321249Z' in an attempt to evade basic signature-based detections.

Query used to locate event:

```kql
DeviceFileEvents
| where DeviceName == "cmh-cyber-vm"
| where FileName contains "mimi"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
```

<img width="1258" alt="CleanShot 2025-03-01 at 19 52 34@2x" src="https://github.com/user-attachments/assets/66a5461b-3699-45b3-90a3-e0f162093e05" />

<img width="1253" alt="CleanShot 2025-03-01 at 19 53 41@2x" src="https://github.com/user-attachments/assets/41a64901-980f-4505-83c6-1b5be772b280" />


2. Searched the `DeviceProcessEvents` Table for Mimikatz execution

Searched for a `FileName` equal to the obfuscated Mimikatz executable "mimi64.exe" and a `ProcessCommandLine` containing options commonly used during Mimikatz command executions such as "sekurlsa::logonpasswords" and "privilege::debug". At '2025-02-27T18:00:34.050118Z', the user "cmh-cyber" successfully executed the Mimikatz command.

Query used to locate events:

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where FileName == "mimi64.exe" and ProcessCommandLine has_any ("mimi64.exe", "sekurlsa::logonpasswords", "privilege::debug")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ActionType
```

<img width="1255" alt="CleanShot 2025-03-01 at 19 57 38@2x" src="https://github.com/user-attachments/assets/6c4f9413-331d-47aa-bcfd-0faa54a4e4f7" />


3. Searched the `DeviceProcessEvents` Table for exfiltration activity

Searched for any potential exfiltration activity within the `ProcessCommandLine` field by suspected keywords and file extension types. At '2025-03-02T01:43:25.6836023Z', an attempt was to secure copy (scp) a file named "creddump.txt" to a remote host at '192.168.0.1' made by user "cmh-cyber".

Query used to locate events:

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where ProcessCommandLine has_any ("cred", "dump", ".txt", ".log")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

<img width="1258" alt="CleanShot 2025-03-01 at 20 21 49@2x" src="https://github.com/user-attachments/assets/b824acfe-424a-4027-8d90-e085e6921e13" />


4. Searched the `DeviceNetworkEvents` Table for exfiltration activity

Searched for network activity at '2025-03-02T01:43:25.6836023Z' to determine the result of the secure copy attempt that was made, and discovered that the connection had failed.

Query used to locate event:

```kql
DeviceNetworkEvents
| where DeviceName == "cmh-cyber-vm"
| where RemoteIP == "192.168.0.1"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort
```

<img width="1262" alt="CleanShot 2025-03-08 at 08 27 33@2x" src="https://github.com/user-attachments/assets/17eef2c5-99f6-421e-8057-1f9a275742cc" />


5. Search `DeviceProcessEvents` for any post-exfiltration activity

Searched for any activity after '2025-03-02T01:43:25.6836023Z' within the `ProcessCommandLine` field that would indicate the actor had made an attempt to clear their tracks post-exfiltration. At '2025-03-02T01:44:39.019939Z', we see three wevtutil commands being executed by user "cmh-cyber" to clear the Application, Security and System logs respectfully.

Query used to locate events:

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where Timestamp >= datetime('2025-03-02T01:43:25.6836023Z')
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

<img width="1260" alt="CleanShot 2025-03-02 at 12 52 15@2x" src="https://github.com/user-attachments/assets/40d92b2a-df74-4d5e-adda-a16ba7f8b404" />


6. Search `DeviceFileEvents` for further post-exfiltration activity

Searched for any evidence of file deletion after '2025-03-02T01:43:25.6836023Z'. At '2025-03-02T01:44:28.1926134Z', the file "ConsoleHost_history.txt" (which logs PowerShell command history on a per-user basis) was deleted by user "cmh-cyber", which suggests an attempt was made by the user to further cover their tracks. No other evidence was found at this time.

Query used to locate events:

```kql
DeviceFileEvents
| where DeviceName == "cmh-cyber-vm"
| where Timestamp >= datetime('2025-03-02T01:43:25.6836023Z')
| where FileName has_any (".txt")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, ActionType
```

<img width="1001" alt="CleanShot 2025-03-02 at 13 43 07@2x" src="https://github.com/user-attachments/assets/364849ef-2fdf-4206-a8bc-7433b2c08145" />

---

## Chronological Events

1. File Download - Mimikatz Installer
   * Timestamp: 2025-03-01T22:37:51.0340907Z
   * Event: The user "cmh-cyber" downloaded a file named "mimikatz-master.zip" to the Downloads folder.
   * Action: File download detected.
   * File Path: C:\Users\cmh-cyber\Downloads\mimikatz-master.zip
  
2. File Creation - Mimikatz Executable Extraction and Rename
   * Timestamp: 2025-03-02T00:30:51.3210787Z
   * Event: The user "cmh-cyber" extracted a file named "mimikatz-master.zip" to C:\Users\cmh-cyber\AppData\Local\Temp, and the executable mimikatz.exe was renamed to mimi64.exe.
   * Action: File creation detected.
   * File Path: C:\Users\cmh-cyber\AppData\Local\Temp\mimikatz\x64\mimi64.exe
  
4. Process Execution - Mimikatz Execution
   * Timestamp: 2025-02-27T18:00:34.050118Z
   * Event: The user "cmh-cyber" ran the "mimi64.exe" executable successfully, and dumped credentials from LSASS into a file named "creddump.txt"
   * Action: Process execution detected.
   * File Path: C:\Users\cmh-cyber\AppData\Local\Temp\creddump.txt
  
5. Data Exfiltration - Secure Copy to Remote Host
   * Timestamp: 2025-03-02T01:43:25.6836023Z
   * Event: The user "cmh-cyber" attempted to secure copy the file "creddump.txt" to a remote host located at "192.168.0.1", but the connection is determined to have failed.
   * Action: Data exfiltration detected.

6. Anti-Forensics - Removal of Logs
   * Timestamp: 2025-03-02T01:43:25.6836023Z
   * Event: The user "cmh-cyber" performed anti-forensic activities by clearing logs through a sequence of "wevtutil cl ..." commands and the removal of "ConsoleHost_history.txt".
   * Action: Log and console history deletion detected.

---

## Summary

The user "cmh-cyber" on the "cmh-cyber-vm" device initiated and completed the download of Mimikatz. They proceeded to extact and rename the Mimikatz executable in an attempt to circumvent signature-based detections. After initial staging was completed, the user executed Mimikatz and dumped credentials from the LSASS into a file that they then failed to exfiltrate to a remote host. No futher attempts to exfiltrate the dumped credentials were detected, and the user seems to have changed course by focusing on clearing their tracks. Multiple commands were ran to clear logs and remove console history. It's unclear whether Mimikatz was deleted, obfuscated or left on the system for futher use at a later date.

---

## Response Taken
Mimikatz usage was confirmed on device "cmh-cyber-vm". The device was isolated, and the user's direct manager was notified.

---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/clay-h-980ba5262
- **Date**: August 31, 2024

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
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
