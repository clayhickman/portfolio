# Threat Event (Unauthorized Cryptominer Installation)
**Malicious Cryptominer Installation and Use**

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:

1. **Download Cryptominer Using Built-In Tools**  
   - The attacker uses a legitimate Windows utility (e.g., `bitsadmin.exe`) to stealthily download a cryptominer binary (`fake-miner.exe`) from a malicious URL (e.g., `https://github.com/clayhickman/portfolio/raw/refs/heads/main/threat-hunting-scenarios/cryptominer/fake-miner.exe`) directly onto the VM.  
   - This download can generate **DeviceFileEvents** logs.

2. **Rename and Move the Cryptominer**  
   - After downloading, the file might be renamed to something less suspicious (e.g., `systemupdate.exe`) and moved into a hidden or system-like directory:  
     ```powershell
     Rename-Item .\miner.exe systemupdate.exe  
     Move-Item .\systemupdate.exe "C:\Users\<User>\AppData\Local\Temp\systemupdate.exe"
     ```
   - These actions also appear in **DeviceFileEvents**.

3. **Execute the Cryptominer**  
   - The attacker (or a malicious script) executes `systemupdate.exe` (the renamed miner).  
   - This event shows in **DeviceProcessEvents** with a suspicious command line referencing a location like `C:\Users\<User>\AppData\Local\Temp\systemupdate.exe`.

4. **Persistence (Optional)**  
   - The attacker creates a scheduled task or modifies a registry Run key to start `systemupdate.exe` automatically on reboot:
     ```powershell
     schtasks /create /tn "SystemUpdate" /tr "C:\Users\<User>\AppData\Local\Temp\systemupdate.exe" /sc onlogon
     ```
   - This can appear in **DeviceProcessEvents** (e.g., `schtasks.exe`) or **DeviceRegistryEvents** if registry keys are modified.

5. **Cryptominer Network Traffic**  
   - Once running, the cryptominer may connect to a mining pool on specific ports (e.g., 3333, 4444, 5555).  
   - These outbound connections are logged in **DeviceNetworkEvents**.

6. **Cleanup and Evasion**  
   - The attacker may delete original files (`miner.exe`) or logs to evade detection, generating file deletion logs in **DeviceFileEvents**.
     ```powershell
     wevtutil cl Application
     wevtutil cl Security
     wevtutil cl System
     ```

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                                                       |
|---------------------|-------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceFileEvents                                                                                      |
| **Info**            | [DeviceFileEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**         | Tracks downloading, renaming, moving, and deleting of cryptominer files.                              |

| **Parameter**       | **Description**                                                                                       |
|---------------------|-------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                                                   |
| **Info**            | [DeviceProcessEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**         | Logs execution of the cryptominer and utilities used to set persistence (e.g., `schtasks.exe`).       |

| **Parameter**       | **Description**                                                                                       |
|---------------------|-------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceNetworkEvents                                                                                   |
| **Info**            | [DeviceNetworkEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**         | Detects mining pool connections from the cryptominer (`systemupdate.exe`).                            |

| **Name**            | DeviceRegistryEvents                                                                                  |
| **Info**            | [DeviceRegistryEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| **Purpose**         | Monitors for Run key modifications if the attacker uses registry-based persistence.                   |

---

## Related Queries

```kql
// 1) Detect cryptominer file download with bitsadmin or suspicious renaming
DeviceFileEvents
| where InitiatingProcessFileName == "bitsadmin.exe"
  or (FileName endswith ".exe" and FileName contains "miner")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName

// 2) Detect suspicious process execution (renamed cryptominer)
DeviceProcessEvents
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("miner", "systemupdate", "temp\\systemupdate.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// 3) Identify new scheduled tasks referencing suspicious files
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has_any ("systemupdate.exe", "miner.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// 4) Check for cryptominer-related or unusual outbound connections
DeviceNetworkEvents
| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessCommandLine has_any ("miner", "systemupdate")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl

// 5) Detect registry-based persistence attempts
DeviceRegistryEvents
| where RegistryKey endswith "Run" 
  or RegistryKey endswith "RunOnce"
| where RegistryValueData has_any ("miner.exe", "systemupdate.exe")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

---

## Created By:
- **Author Name**: Clay Hickman  
- **Author Contact**: https://www.linkedin.com/in/clay-h-980ba5262
- **Date**: March 09, 2025

## Validated By:
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- Cryptominers often trigger high CPU usage. Monitoring resource utilization alongside security logs can help identify anomalies.  
- Defender for Endpoint can block or quarantine known miner executables automatically, but stealthy or custom builds may slip through.

---

## Revision History:
| **Version** | **Changes**                            | **Date**         | **Modified By** |
|-------------|----------------------------------------|------------------|-----------------|
| 1.0         | Initial draft                          | `March 09, 2025` | `Clay Hickman`  |
