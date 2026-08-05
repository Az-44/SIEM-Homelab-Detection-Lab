# DET-001 — Windows System Discovery Commands

## Objective

Detect common Windows discovery commands frequently executed by attackers after obtaining access to a system. These commands help adversaries identify the current user, hostname, operating system details, network configuration, and local accounts.

---

## Threat Description

System discovery is one of the earliest stages of an intrusion. Attackers gather information about the compromised host before moving laterally or escalating privileges.

Examples include:

- whoami
- hostname
- ipconfig
- systeminfo
- net user
- net localgroup administrators

Although administrators execute these commands legitimately, multiple discovery commands executed together can indicate reconnaissance activity.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1033 | System Owner/User Discovery |
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |
| T1087 | Account Discovery |

---

## Attack Simulation

The following commands were executed inside the Windows 10 virtual machine.

```cmd
whoami
hostname
ipconfig /all
systeminfo
net user
net localgroup administrators
```

---

## SPL Detection Query

```spl
index=main EventCode=1
(Image="*\\whoami.exe" OR
Image="*\\hostname.exe" OR
Image="*\\ipconfig.exe" OR
Image="*\\systeminfo.exe" OR
Image="*\\net.exe")
| eval MITRE=case(
match(Image,"whoami"),"T1033 - System Owner/User Discovery",
match(Image,"hostname"),"T1082 - System Information Discovery",
match(Image,"systeminfo"),"T1082 - System Information Discovery",
match(Image,"ipconfig"),"T1016 - System Network Configuration Discovery",
match(Image,"net.exe"),"T1087 - Account Discovery"
)
| table _time User Image CommandLine ParentImage MITRE
| sort -_time
```

---

## Detection Logic

The query searches Sysmon Process Creation (Event ID 1) events for common Windows discovery utilities.

When one of these executables is launched, the event is mapped to its corresponding MITRE ATT&CK technique.

---

## Example Detection

*(Insert the screenshot from your Splunk search here.)*

```md
![DET-001](../Screenshots/DET-001-System-Discovery.png)
```

---

## Investigation Notes

Observed parent process:

```
cmd.exe
```

Observed user:

```
labuser
```

The commands successfully generated Sysmon Process Creation events that were forwarded to Splunk through the Universal Forwarder.

---

## Possible False Positives

- System administrators
- Helpdesk personnel
- IT automation scripts
- Configuration management software

---

## Detection Severity

Medium

---

## Recommendations

Investigate if:

- Multiple discovery commands occur within a short time window.
- The commands originate from unusual users.
- Discovery activity is followed by PowerShell, credential dumping, scheduled tasks, or outbound network connections.

Correlation with additional telemetry significantly improves confidence.
