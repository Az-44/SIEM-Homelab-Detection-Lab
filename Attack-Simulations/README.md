# Attack Simulations

## Overview

This document summarizes every attack simulation performed during the SIEM Homelab Detection Lab.

All simulations were executed inside an isolated Windows 10 virtual machine for defensive security testing and educational purposes.

The generated telemetry was collected by Sysmon, forwarded to Splunk Enterprise through the Splunk Universal Forwarder, and investigated using custom SPL detection queries.

---

## Simulation Summary

| Detection | Attack Simulation | Windows Utility | Detection Documentation |
|-----------|-------------------|-----------------|-------------------------|
| DET-001 | Windows discovery commands | whoami, hostname, ipconfig, systeminfo, net | [DET-001](../Detection-Queries/DET-001-System-Discovery.md) |
| DET-002 | Suspicious PowerShell flags | powershell.exe | [DET-002](../Detection-Queries/DET-002-Suspicious-PowerShell.md) |
| DET-003 | Certutil execution | certutil.exe | [DET-003](../Detection-Queries/DET-003-Certutil.md) |
| DET-004 | Rundll32 execution | rundll32.exe | [DET-004](../Detection-Queries/DET-004-Rundll32.md) |
| DET-005 | CMD spawning PowerShell | cmd.exe → powershell.exe | [DET-005](../Detection-Queries/DET-005-CMD-PowerShell.md) |
| DET-006 | Executable launched from Temp directory | whoami.exe | [DET-006](../Detection-Queries/DET-006-Temp-Execution.md) |
| DET-007 | Executable file creation | cmdcopy.exe / whoami.exe | [DET-007](../Detection-Queries/DET-007-Executable-File-Creation.md) |
| DET-008 | Registry Run Key persistence | reg.exe | [DET-008](../Detection-Queries/DET-008-Registry-Run-Key.md) |
| DET-009 | Scheduled Task creation | schtasks.exe | [DET-009](../Detection-Queries/DET-009-Scheduled-Task.md) |
| DET-010 | Encoded PowerShell command | powershell.exe | [DET-010](../Detection-Queries/DET-010-Encoded-PowerShell.md) |
| DET-011 | Outbound network connection | curl.exe | [DET-011](../Detection-Queries/DET-011-Outbound-Network.md) |

---

## Simulations at a Glance

- ✅ 11 attack simulations
- ✅ Windows 10 endpoint
- ✅ Sysmon telemetry
- ✅ Splunk Enterprise investigation
- ✅ MITRE ATT&CK mapping
- ✅ Custom SPL detections
- ✅ Detection engineering documentation

---

## Attack Categories

The simulations cover several common attacker behaviors observed during endpoint investigations.

| Category | Simulations |
|----------|-------------|
| Discovery | DET-001 |
| PowerShell Abuse | DET-002, DET-005, DET-010 |
| LOLBins (Living-off-the-Land Binaries) | DET-003, DET-004 |
| Execution | DET-006 |
| File Activity | DET-007 |
| Persistence | DET-008, DET-009 |
| Network Activity | DET-011 |

---

## Lab Workflow

Every simulation followed the same workflow:

1. Execute the attack simulation inside the Windows 10 endpoint.
2. Sysmon generates endpoint telemetry.
3. Windows Event Logs store the event.
4. Splunk Universal Forwarder sends the logs to Splunk Enterprise.
5. Custom SPL queries detect the activity.
6. Events are investigated and mapped to MITRE ATT&CK techniques.

---

## Notes

All attack simulations were intentionally executed inside an isolated virtual environment.

No malicious payloads, exploitation frameworks, or unauthorized systems were involved.

The purpose of these simulations was to generate realistic endpoint telemetry for detection engineering, threat hunting, and SOC analyst training.
