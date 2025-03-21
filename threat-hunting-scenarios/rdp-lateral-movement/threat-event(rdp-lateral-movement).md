# **Threat Event: Unauthorized Use of RDP for Lateral Movement with Persistence and Evasion**  
**Suspicious Remote Desktop Protocol (RDP) Activity Indicating Potential Lateral Movement, Backdoor Persistence, and Evasion Techniques**

---

## **Reason for the Hunt**  
**Unusual System Behavior and Increased Stealth Techniques Observed in Microsoft Defender for Endpoint**  

Following an extended investigation into unauthorized RDP access and persistence mechanisms, security analysts observed that attackers deployed evasion techniques to bypass detection.  

Threat actors are known to:  
- **Modify event logs** to erase traces of their activity.  
- **Disable security features** such as Windows Defender and logging mechanisms.  
- **Use LOLBins (Living-Off-the-Land Binaries)** to execute malicious actions without detection.  
- **Tamper with security tools** to avoid raising alerts.  

Security leadership has mandated a deeper **threat hunt focusing on evasion techniques** to ensure the attacker is fully removed from the environment.

---

## **Steps the "Bad Actor" Took to Evade Detection**  

1. **Cleared Windows Event Logs to Remove Evidence**  
   - The attacker executed the following command to erase all system logs:  
     ```powershell
     wevtutil cl System
     wevtutil cl Security
     wevtutil cl Application
     ```

2. **Disabled Windows Defender and Tampered with Security Features**  
   - Disabled Defender real-time protection to allow malicious activities:  
     ```powershell
     Set-MpPreference -DisableRealtimeMonitoring $true
     ```

   - Stopped Windows Defender services to avoid detection:  
     ```powershell
     sc stop WinDefend
     sc config WinDefend start= disabled
     ```

3. **Enabled Hidden Remote Access via Firewall Rule Modification**  
   - The attacker ensured RDP access remained open by modifying firewall rules:  
     ```powershell
     netsh advfirewall firewall add rule name="RDP Access" dir=in action=allow protocol=TCP localport=3389
     ```

4. **Executed Malicious Commands Using LOLBins (Living-Off-the-Land Binaries)**  
   - Used `rundll32.exe` to execute malicious payloads without triggering alerts:  
     ```powershell
     rundll32.exe C:\Users\Public\malicious.dll,EntryPoint
     ```

   - Used `wmic.exe` for remote execution on other machines:  
     ```powershell
     wmic process call create "cmd.exe /c C:\Users\Public\payload.exe"
     ```

5. **Created a Rogue Security Service to Restart Malicious Processes**  
   - The attacker ensured persistence by creating a fake service that restarts malicious processes:  
     ```powershell
     sc create "FakeSecurityService" binPath= "C:\Windows\System32\cmd.exe /c powershell.exe -c Start-Process C:\Users\Public\backdoor.exe" start= auto
     ```

6. **Exfiltrated Credentials via LSASS Dumping with ProcDump**  
   - Used `procdump.exe` to extract credentials from LSASS without using Mimikatz:  
     ```powershell
     procdump.exe -ma lsass.exe C:\Users\Public\lsass.dmp
     ```

7. **Removed Artifacts to Cover Tracks**  
   - Deleted RDP-related forensic artifacts:  
     ```powershell
     del /F /Q C:\Users\Public\lsass.dmp
     del /F /Q C:\Users\Public\malicious.dll
     ```

---

## **Tables Used to Detect Evasion Techniques**  

### **DeviceEvents**  
| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceEvents |
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| **Purpose** | Used to detect event log clearing, security tool tampering, and Defender disabling. |

---

### **DeviceRegistryEvents**  
| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceRegistryEvents |
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| **Purpose** | Used to detect registry modifications related to security feature tampering. |

---

### **DeviceProcessEvents**  
| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to detect LOLBins execution and unauthorized process creations. |

---

### **DeviceFileEvents**  
| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceFileEvents |
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used to detect deletion of forensic artifacts and malicious payloads. |

---

## **Related Queries**  

### **Detect Clearing of Windows Event Logs**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("wevtutil cl System", "wevtutil cl Security", "wevtutil cl Application")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect Windows Defender Being Disabled**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has "Set-MpPreference -DisableRealtimeMonitoring"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect Firewall Rule Modification for RDP Access**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has "netsh advfirewall firewall add rule"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect Execution of LOLBins (Living-Off-the-Land Binaries)**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("rundll32.exe", "wmic process call create")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect Unauthorized Windows Service Creation for Persistence**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has "sc create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect LSASS Dumping via ProcDump**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has "procdump.exe -ma lsass.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### **Detect Deletion of Artifacts (Evidence Removal)**  
```kql
DeviceFileEvents
| where FileName has_any ("lsass.dmp", "malicious.dll")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath
```

---

## **Mitigation Recommendations**  

### **Prevent Evasion Techniques**  
- **Enable Windows Defender Tamper Protection** to prevent attackers from disabling it.  
- **Monitor for event log clearing** (`Event ID 1102` – Security log cleared).  
- **Restrict execution of LOLBins** using **Windows Defender Application Control (WDAC)**.  
- **Disable PowerShell execution for non-administrators** via Group Policy.  

### **Enhance RDP Security**  
- **Disable RDP if not required**.  
- **Enable RDP session timeouts** to prevent unauthorized persistence.  
- **Enforce strong authentication** (MFA for RDP).  

### **Improve Logging and Detection**  
- **Enable PowerShell logging** (`Module Logging` and `Script Block Logging`).  
- **Monitor for unauthorized firewall rule modifications**.  
- **Block outbound connections to known attacker IPs**.  

---

## **Created By:**  
- **Author Name**: Clay Hickman
- **Author Contact**: N/A  
- **Date**: March 16, 2025  

---

## **Revision History**  
| **Version** | **Changes** | **Date** | **Modified By** |
|------------|------------|----------|----------------|
| 1.0 | Initial draft | March 16, 2025 | Clay Hickman |
