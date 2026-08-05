
# MITRE ATT&CK Mapping

## Overview

This document maps each detection developed in this project to the corresponding MITRE ATT&CK technique(s).

MITRE ATT&CK provides a standardized knowledge base of adversary tactics and techniques, allowing defenders to classify malicious behavior, build detections, and communicate findings consistently.

---

## Detection Coverage

| Detection ID | Detection | MITRE Technique | ATT&CK ID | Tactic |
|--------------|-----------|-----------------|-----------|--------|
| DET-001 | Windows System Discovery Commands | System Owner/User Discovery<br>System Information Discovery<br>System Network Configuration Discovery<br>Account Discovery | T1033<br>T1082<br>T1016<br>T1087 | Discovery |
| DET-002 | Suspicious PowerShell Execution | PowerShell | T1059.001 | Execution |
| DET-003 | Certutil Download Activity | Deobfuscate/Decode Files or Information<br>Ingress Tool Transfer | T1140<br>T1105 | Defense Evasion / Command and Control |
| DET-004 | Rundll32 LOLBin Execution | Signed Binary Proxy Execution: Rundll32 | T1218.011 | Defense Evasion |
| DET-005 | CMD Spawning PowerShell | PowerShell | T1059.001 | Execution |
| DET-006 | Executable Launched from Temp Directory | Context-dependent | N/A | Execution / Defense Evasion |
| DET-007 | Executable File Creation | Context-dependent | N/A | Defense Evasion |
| DET-008 | Registry Run Key Persistence | Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| DET-009 | Scheduled Task Creation | Scheduled Task | T1053.005 | Persistence |
| DET-010 | Encoded PowerShell Command | PowerShell | T1059.001 | Execution |
| DET-011 | Outbound Network Connection | Context-dependent | N/A | Command and Control |

---

## ATT&CK Tactic Coverage

The detections in this project cover multiple stages of the cyber attack lifecycle.

| Tactic | Coverage |
|---------|----------|
| Discovery | DET-001 |
| Execution | DET-002, DET-005, DET-006, DET-010 |
| Defense Evasion | DET-003, DET-004, DET-006, DET-007 |
| Persistence | DET-008, DET-009 |
| Command and Control | DET-003, DET-011 |

---

## ATT&CK Coverage Summary

| ATT&CK Technique | Description | Detection |
|------------------|-------------|-----------|
| T1016 | System Network Configuration Discovery | DET-001 |
| T1033 | System Owner/User Discovery | DET-001 |
| T1053.005 | Scheduled Task | DET-009 |
| T1059.001 | PowerShell | DET-002, DET-005, DET-010 |
| T1082 | System Information Discovery | DET-001 |
| T1087 | Account Discovery | DET-001 |
| T1105 | Ingress Tool Transfer | DET-003 |
| T1140 | Deobfuscate / Decode Files or Information | DET-003 |
| T1218.011 | Rundll32 | DET-004 |
| T1547.001 | Registry Run Keys / Startup Folder | DET-008 |

---

## Notes

Not every detection maps directly to a single ATT&CK technique.

Some detections, such as executable creation, execution from temporary directories, and outbound network connections, are behavioral detections that provide valuable investigative context rather than representing a specific ATT&CK technique.

These detections are intended to increase analyst visibility and support threat hunting during investigations.

---

## Project Coverage

This project demonstrates detection engineering across several ATT&CK tactics, including:

- Discovery
- Execution
- Defense Evasion
- Persistence
- Command and Control

The mapping allows analysts to understand which attacker behaviors are currently covered by the implemented detections and identify areas for future expansion.
