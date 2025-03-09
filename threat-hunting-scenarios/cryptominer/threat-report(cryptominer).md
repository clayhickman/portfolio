<img width="786" alt="CleanShot 2025-03-09 at 15 44 48@2x" src="https://github.com/user-attachments/assets/b853fa05-567d-4c6b-a2bd-c8ab723936b6" />

# Threat Hunt Report (Unauthorized Cryptominer Usage)
**Detection of Unauthorized Cryptominer Installation and Use**

---

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

## Scenario:
A sudden spike in CPU and memory usage was observed on a Windows 10 endpoint in Azure. Management suspects illicit cryptomining activity and wants to proactively hunt for any cryptominer-related files or processes that may be running undetected.

---

## High-Level Cryptominer IoC Discovery Plan:
1. Check **DeviceFileEvents** for cryptominer related files (or suspicious renames) and any stealthy utilities (e.g., `bitsadmin.exe`).
2. Check **DeviceProcessEvents** for cryptominer execution or processes configuring persistence (e.g., `schtasks.exe`).
3. Check **DeviceNetworkEvents** for connections to known mining pools or suspicious outbound ports.
4. Review **DeviceRegistryEvents** for unauthorized Run/RunOnce entries referencing miner executables.

---

## Steps Taken

###1. Searched the `DeviceFileEvents` table for downloaded files

Searched for any downloads that may have been initiated by "bitsadmin.exe" and newly created `.exe` files containing “miner” in the name.

```kql
DeviceFileEvents
| where DeviceName == "cmh-cyber-vm"
| where InitiatingProcessFileName == "bitsadmin.exe" or (FileName endswith ".exe" and FileName contains "miner")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName
```

2. **Checked Process Execution**  
   - Investigated **DeviceProcessEvents** for `systemupdate.exe` or other suspicious names referencing a potential cryptominer.  
   - Looked for commands used to set persistence, e.g., `schtasks /create`.

3. **Monitored Outbound Connections**  
   - Searched **DeviceNetworkEvents** for unusual connections to mining pool ports (e.g., 3333, 4444, 5555).

4. **Evaluated Potential Persistence**  
   - Reviewed **DeviceRegistryEvents** to see if the miner had created a registry Run key or similar.

---

## Chronological Events

1. **Cryptominer Downloaded via bitsadmin**  
   - Timestamp: 2025-03-09 09:14 UTC  
   - File `fake-miner.exe` downloaded from a GitHub URL to `C:\Users\<User>\Downloads`.

2. **File Renamed and Moved**  
   - Timestamp: 2025-03-09 09:15 UTC  
   - `fake-miner.exe` renamed to `systemupdate.exe` and moved to `C:\Users\<User>\AppData\Local\Temp\`.

3. **Execution & Scheduled Task Creation**  
   - Timestamp: 2025-03-09 09:16 UTC  
   - `systemupdate.exe` was executed, followed by a `schtasks.exe` command to set up a persistent run on user logon.

4. **High CPU Usage Observed**  
   - Timestamp: 2025-03-09 09:20 UTC  
   - Monitoring tools showed CPU spikes and suspicious outbound network connections to a known mining pool domain over port 4444.

5. **Cleanup Commands**  
   - Timestamp: 2025-03-09 09:25 UTC  
   - DeviceFileEvents indicated deletion of the original `fake-miner.exe` file and attempted event log clearing via `wevtutil`.

---

## Summary
Our threat hunt confirmed an **unauthorized cryptominer** was installed and actively running. Attackers likely used **`bitsadmin.exe`** to download the miner, renamed it to “**systemupdate.exe**,” and set up persistence using Windows **Scheduled Tasks**. The miner established connections to an external mining pool, causing **elevated CPU usage** and **unusual network traffic**.

---

## Response Taken
1. **Endpoint Isolation**: The affected endpoint was isolated from the network to prevent further resource abuse or spread.  
2. **Binary Removal**: The suspicious files (`systemupdate.exe`) were quarantined and removed.  
3. **Log Review**: Full environment review to identify any lateral movement or secondary infections.  
4. **Policy Enforcement**: Additional blocking rules and stricter policies on the use of **`bitsadmin.exe`** were implemented.

---

## MDE Tables Referenced:
| **Parameter**        | **Description**                                                                                                          |
|----------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Name**             | DeviceFileEvents                                                                                                         |
| **Info**             | [DeviceFileEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)         |
| **Purpose**          | Tracks downloading, renaming, moving, and deleting of cryptominer files.                                                 |
| **Name**             | DeviceProcessEvents                                                                                                      |
| **Info**             | [DeviceProcessEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)       |
| **Purpose**          | Logs execution of the cryptominer and utilities used to set persistence (e.g., `schtasks.exe`).                          |
| **Name**             | DeviceNetworkEvents                                                                                                      |
| **Info**             | [DeviceNetworkEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**          | Detects mining pool connections from the cryptominer (`systemupdate.exe`).                                               |
| **Name**             | DeviceRegistryEvents                                                                                                     |
| **Info**             | [DeviceRegistryEvents Table Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| **Purpose**          | Monitors for Run key modifications if the attacker uses registry-based persistence.                                      |

---

## Detection Queries:
```kql
// Detect cryptominer file download with bitsadmin or suspicious renaming
DeviceFileEvents
| where InitiatingProcessFileName == "bitsadmin.exe"
  or (FileName endswith ".exe" and FileName contains "miner")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName

// Detect suspicious process execution (renamed cryptominer)
DeviceProcessEvents
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("miner", "systemupdate", "temp\\systemupdate.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Identify new scheduled tasks referencing suspicious files
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has_any ("systemupdate.exe", "miner.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Check for cryptominer-related or unusual outbound connections
DeviceNetworkEvents
| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessCommandLine has_any ("miner", "systemupdate")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl

// Detect registry-based persistence attempts
DeviceRegistryEvents
| where RegistryKey endswith "Run" or RegistryKey endswith "RunOnce"
| where RegistryValueData has_any ("miner.exe", "systemupdate.exe")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

---

## Created By:
- **Author Name**: Clay Hickman  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/clay-h-980ba5262)  
- **Date**: March 09, 2025

## Validated By:
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- Cryptominers often trigger high CPU usage and can affect performance.  
- Combining logs from **MDE** with performance metrics can help correlate usage spikes with suspicious processes.  
- Further blocking rules on “living off the land” tools like `bitsadmin.exe` can reduce future risk.

---

## Revision History:
| **Version** | **Changes**                    | **Date**         | **Modified By**   |
|-------------|--------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 09, 2025` | `Clay Hickman`    |
