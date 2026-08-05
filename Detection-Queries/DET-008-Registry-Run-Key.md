
# DET-008 — Registry Run Key Modification

## Objective

Detect modifications to Windows Registry Run Keys, a common persistence mechanism used by attackers to automatically execute malicious programs whenever a user logs on.

---

## Threat Description

The Windows Registry contains several "Run" and "RunOnce" keys that automatically launch programs during user logon.

Adversaries frequently abuse these locations to establish persistence by adding malicious executables or scripts that survive system reboots.

Common malicious uses include:

- Malware persistence
- Remote Access Trojans (RATs)
- Ransomware persistence
- Startup scripts
- Unauthorized software execution

Although legitimate applications also modify Run Keys during installation, unexpected modifications should always be investigated.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1547.001 | Registry Run Keys / Startup Folder |

---

## Attack Simulation

The following command was executed inside the Windows 10 virtual machine.

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run ^
/v Test ^
/t REG_SZ ^
/d "C:\Windows\System32\notepad.exe"
```

This created a new Registry Run Key that launches Notepad whenever the current user signs in.

---

## SPL Detection Query

```spl
index=main EventCode=13
(TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR
TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")
| eval Detection="Registry Run Key Modification"
| eval Severity="High"
| eval MITRE="T1547.001"
| table _time User Image TargetObject Details Detection Severity MITRE
| sort -_time
```

---

## Detection Logic

The query searches Sysmon Registry Value Set events (Event ID 13) for modifications to the Windows Run and RunOnce registry keys.

Monitoring these registry locations helps identify persistence mechanisms commonly used by malware to automatically execute after user logon.

---

## Example Detection

![Registry Run Key Modification](../Screenshots/det-008-registry-run-key.png)

---

## Investigation Notes

Observed modifying process:

```
reg.exe
```

Observed user:

```
labuser
```

Observed registry path:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Observed value:

```
Test
```

Observed data:

```
C:\Windows\System32\notepad.exe
```

The Registry modification successfully generated a Sysmon Registry Value Set (Event ID 13) event that was forwarded to Splunk through the Universal Forwarder.

---

## Possible False Positives

- Software installation
- Enterprise software deployment
- Antivirus products
- Device management software
- Legitimate startup applications

---

## Detection Severity

High

---

## Recommendations

Investigate if:

- Newly created Run Keys reference executables stored in **Temp**, **Downloads**, or **AppData**.
- The modifying process is PowerShell, CMD, Rundll32, Certutil, or another LOLBin.
- The registry modification is immediately followed by scheduled task creation or outbound network activity.
- Unsigned executables are configured to launch automatically at logon.
- Multiple persistence mechanisms are established within a short time period.

Correlating Registry Run Key modifications with process creation, file creation, and network telemetry significantly improves detection confidence.
