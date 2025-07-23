# Phishing Attack Resulting in C2 Persistent Access

## Malicious C2 Persistent Access after a Phishing Attack  
### A Workstation Forensics Report  
**By Faury A. Abreu**  

---

### Abstract:
An accounting company was victim of a C2 attack, which initial access was granted using email spoofing. The root of the incident was a .doc file (`free_magicules.doc`) that was downloaded from a malicious email message. Once this file was opened, it started a network connection over port 80 using the http protocol. This connection had an encoded embedded command pointing to a URL to download a .zip file. The payload included a file creation in the startup folder to start when the user logs into the computer. 

Virustotal returned an alert once the hash of the file was searched. The downloaded file was implanted to initialize network connections, specifically http requests with base64 encoded commands sent in the “q” parameter. Then, there was a C2 connection established via a reverse R. proxy. Tracing back to the events, the initial downloaded file executed another file, which used the “printspoofer64” service that exploits the SeImpersonate privilege in Windows to escalate privilege which ensured the intruder with the access. Once the intruder had access, two user accounts were created and one of those accounts was added to the administrators group. Finally the intruder executed a command to gain persistence.

---

## Introduction:
One absolute truth about information security, is that the weakest link in the chain of security are human beings. Social engineering is the most effective way to gain initial access to all kinds of assets, in corporate and personal context. In most cases, social engineering is one of the initial steps in the attack process, and it might include (but not limited to) phishing (T1598), email spoofing (T1672), and/or impersonation (T1656) tactics. This report presents the insights of the forensic investigation after analysing endpoint and network logs from a compromised asset.

---

## Details:

The SOC analyst received an alert of a supposed C2 access on one of the machines in the HR department. The analyst contacted me to analyze the artifacts and create a report that maps the events on the machine. The provided assets include: sysmon logs, the windows logs, and a .pcap file with the network traffic during the attack’s time frame.

### Tools used in this investigation:
- **BRIM**: [BRIM GitHub](https://github.com/chandar79/brim)  
- **Event Viewer**
- **Timeline Explorer**: [Timeline Explorer](https://www.sans.org/tools/timeline-explorer/)  
- **Powershell**
- **Wireshark**: [Wireshark Docs](https://www.wireshark.org/docs/)  
- **Sysmon viewer**: [Sysmon Tools](https://github.com/nshalabi/SysmonTools)  
- **EvtxECmd**: [EvtxECmd GitHub](https://github.com/EricZimmerman/evtx)

Related MITRE Tactics:
- https://attack.mitre.org/techniques/T1598/
- https://attack.mitre.org/techniques/T1672/
- https://attack.mitre.org/techniques/T1656/

---

## Investigation Workflow:

### 1. Artifact preparation:
a. Converted `.evtx` to `.csv` using `EvtxECmd`, then loaded into Timeline Explorer.  
b. Timeline Explorer used for filtering and grouping logs faster than Event Viewer.

### 2. Initial phase of Incident response:
- Malicious `.doc` file opened via `WINWORD.EXE`.
- Network connection found in Sysmon logs (EventID=3) over port 80.
- ParentProcessID XML filter used to identify suspicious base64 encoded command.

#### Powershell to decode base64:
```powershell
$base64Encoded = "<string>"
$bytes = [System.Convert]::FromBase64String($base64Encoded)
$decodedText = [System.Text.Encoding]::UTF8.GetString($bytes)
Write-Output $decodedText
```

- Identified CVE: `CVE-2022-30190` (related to `msdt.exe`).
- Decoded command wrote a script to `startup` folder using `Invoke-WebRequest`.

### 3. Stage 2 of incident response:
- Detected downloaded file executing scripts from malicious domain.
- Used Sysmon logs (EventID=22) to monitor DNS queries.
- C2 server communication confirmed from malicious domain.

### 4. Network traffic analysis:
- **BRIM** filter used: `_path=="http" "pishteam[.]xyz"`
- Download URL for payload confirmed.
- C2 commands sent using base64 in `q` parameter via HTTP GET.
- Language used on server: **Nim** (detected via User-Agent).
- `ch.exe` found, created a reverse socks proxy.

### 5. Further actions by attacker:
- `final.exe` executed multiple commands and DNS queries.
- File identified as malicious using **Virustotal**.
- `printspoofer` used for privilege escalation via `SeImpersonatePrivilege`.

### 6. Actions once admin access was granted:
- Windows EventID 4720: two user accounts created.
- Extracted and decoded base64 from HTTP GET requests using CyberChef.
- One user added to "Administrators" group (EventID 4732).
- Persistence established via:
```cmd
C:\Windows\system32\sc.exe \TEMPEST create TempestUpdate2 binpath= C:\ProgramDatainal.exe start= auto
```

---

## Further Actions

### Immediate Actions:

**System Cleanup:**
- Remove malicious service `TempestUpdate2`
- Delete `C:\ProgramDatainal.exe`
- Remove unauthorized accounts
- Clean startup folders
- Scan with updated EDR/AV

**Network Security:**
- Block identified C2 domains/IPs
- Inspect HTTP traffic for base64
- Monitor port 80 from HR
- Restrict `SeImpersonate` privileges

**Access Control:**
- Audit admin group members
- Enforce strict privilege management
- Review Group Policy
- Enable alerts for EventID 4732

---

### Long-term Preventive Measures:

**Email Security:**
- Stricter attachment policies (.doc)
- Advanced filtering/sandboxing
- Block macro-enabled documents
- Enable DMARC, DKIM, SPF

**Endpoint Hardening:**
- Application whitelisting
- Control Windows Script Host
- USB control
- PowerShell logging
- Harden startup folder permissions

**Monitoring Improvements:**
- Log privilege escalation attempts
- Real-time alerts for service creation
- Monitor for base64 in HTTP
- Watch for unusual outbound traffic
- Detect `printspoofer64`

**User Training:**
- Phishing awareness training
- Security awareness programs
- Clear SOPs for suspicious docs
- Efficient incident reporting

**Incident Response Enhancement:**
- Update IR playbooks
- Document IOCs
- Detection rules for similar attacks
- Automate response for future cases

**Policy Updates:**
- Document handling procedures
- Change management updates
- Security baseline improvements
- Stricter software installation policies

**Additional Security Controls:**
- Deploy NAC
- Zero Trust principles
- Web Application Firewall
- File integrity monitoring
- SOAR solutions

---

### References:
- [Tempest Room - TryHackMe](https://tryhackme.com/room/tempestincident)  
- [MITRE ATT&CK](https://attack.mitre.org/)  
- [VirusTotal](https://www.virustotal.com/gui/home/upload)  
- [Ultimate Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)