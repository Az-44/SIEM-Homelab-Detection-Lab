
# Windows SIEM Lab Setup

## Overview

This document describes the configuration used to build the Windows endpoint monitoring environment for the SIEM Homelab Detection Lab.

The lab was created inside Oracle VirtualBox and uses a Windows 10 virtual machine as the monitored endpoint.

The same virtual machine hosts:

- Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise
- Splunk Add-on for Sysmon

This single-VM design keeps the lab lightweight while still demonstrating the complete telemetry and detection workflow.

---

## Lab Architecture

```text
Windows Activity
      ↓
Sysmon
      ↓
Microsoft-Windows-Sysmon/Operational
      ↓
Splunk Universal Forwarder
      ↓
TCP 9997
      ↓
Splunk Enterprise
      ↓
Field Extraction
      ↓
SPL Detection and Investigation
```

A detailed visual diagram is available in the [`Architecture`](../Architecture/) directory.

---

## Environment

| Component | Configuration |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Endpoint Operating System | Windows 10 |
| Endpoint Type | Virtual machine |
| Telemetry Source | Microsoft Sysmon |
| Log Forwarder | Splunk Universal Forwarder |
| SIEM Platform | Splunk Enterprise |
| Forwarding Destination | `127.0.0.1:9997` |
| Splunk Web Interface | `http://localhost:8000` |
| Splunk Index | `main` |
| Sysmon Event Channel | `Microsoft-Windows-Sysmon/Operational` |
| Splunk Source | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Splunk Sourcetype | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |

---

## 1. Windows 10 Virtual Machine

A Windows 10 virtual machine was created using Oracle VirtualBox.

The virtual machine represents a monitored Windows endpoint in a small security operations environment.

### Initial preparation

The following preparation steps were completed:

- Installed Windows 10
- Applied available Windows updates
- Installed VirtualBox Guest Additions
- Created a local lab user account
- Created a clean VirtualBox snapshot
- Verified internet connectivity
- Created a tools directory at:

```text
C:\Tools
```

The Sysmon files and configuration were stored in:

```text
C:\Tools\Sysmon
```

### Snapshot

A clean snapshot was created before installing security tools.

This provides a recovery point in case the virtual machine becomes unstable or a configuration must be reversed.

---

## 2. Sysmon Installation

Microsoft Sysmon was installed to provide detailed Windows endpoint telemetry.

Sysmon records security-relevant events such as:

- Process creation
- Network connections
- File creation
- Registry changes
- Process relationships
- Command-line activity
- File hashes

The Sysmon executable and configuration file were stored in:

```text
C:\Tools\Sysmon
```

### Files used

```text
Sysmon64.exe
sysmonconfig-export.xml
```

The configuration was based on the SwiftOnSecurity Sysmon configuration and later adjusted to support the lab scenarios.

### Installation command

An Administrator Command Prompt was opened and the following commands were executed:

```cmd
cd C:\Tools\Sysmon
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Verification

Sysmon was verified through Windows Event Viewer at:

```text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
```

Calculator was launched to generate a process-creation event:

```cmd
calc.exe
```

A Sysmon Event ID 1 entry confirmed that process creation logging was working.

---

## 3. Sysmon Configuration Updates

The Sysmon configuration can be updated without reinstalling Sysmon.

The following command was used after configuration changes:

```cmd
cd C:\Tools\Sysmon
Sysmon64.exe -c sysmonconfig-export.xml
```

### Network connection monitoring

Sysmon Event ID 3 was required for the outbound network connection detection.

A narrow `NetworkConnect` rule was enabled for `curl.exe` so the lab could capture controlled outbound HTTPS activity without enabling excessive network telemetry.

The configuration update was then applied using:

```cmd
Sysmon64.exe -c sysmonconfig-export.xml
```

---

## 4. Splunk Enterprise Installation

Splunk Enterprise was installed inside the Windows 10 virtual machine.

Splunk Enterprise acts as the SIEM platform used to:

- Receive forwarded events
- Index telemetry
- Extract Sysmon fields
- Run SPL searches
- Investigate activity
- Develop detections
- Display detection results

The Splunk web interface is accessed locally at:

```text
http://localhost:8000
```

### Receiving port

Splunk Enterprise was configured to receive forwarded data on:

```text
TCP 9997
```

The receiving port can be verified from:

```text
Settings
→ Forwarding and receiving
→ Configure receiving
```

---

## 5. Splunk Universal Forwarder Installation

The Splunk Universal Forwarder was installed on the same Windows virtual machine.

The forwarder monitors the Sysmon Operational event channel and sends the events to Splunk Enterprise.

### Forwarding destination

The Universal Forwarder was configured to send events to:

```text
127.0.0.1:9997
```

Because Splunk Enterprise and the monitored endpoint are hosted on the same VM, the loopback address is used.

### Forwarder verification

The active forwarding destination was verified with:

```cmd
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

Expected result:

```text
Active forwards:
127.0.0.1:9997
```

The forwarder service was verified with:

```cmd
sc query SplunkForwarder
```

The service state should display:

```text
RUNNING
```

---

## 6. Sysmon Input Configuration

The Universal Forwarder was configured to monitor the Sysmon Operational event channel.

Configuration file:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

Configuration:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
start_from = oldest
current_only = 0
renderXml = true
```

### Configuration validation

The effective input configuration was checked with:

```cmd
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list WinEventLog --debug
```

The output confirmed that the Sysmon Operational channel was enabled and assigned to the `main` index.

### Restarting the forwarder

After changing `inputs.conf`, the Universal Forwarder was restarted:

```cmd
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
```

---

## 7. Splunk Add-on for Sysmon

The Splunk Add-on for Sysmon was installed in Splunk Enterprise.

The add-on provides field extraction for Sysmon XML events.

Without the add-on, events were searchable as raw XML, but important fields such as the following were not automatically extracted:

- `EventCode`
- `Image`
- `ParentImage`
- `CommandLine`
- `User`
- `TargetFilename`
- `TargetObject`
- `DestinationIp`
- `DestinationPort`

After the add-on was installed, structured field-based searches became available.

Example:

```spl
index=main EventCode=1
| table _time User ParentImage Image CommandLine
```

---

## 8. Data Ingestion Verification

The first validation step confirmed that the Universal Forwarder could communicate with Splunk Enterprise.

```spl
index=_internal sourcetype=splunkd 9997
```

The second validation step confirmed that Sysmon events were arriving in the `main` index.

```spl
index=main
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

The third validation step confirmed that Sysmon process creation fields were extracted correctly.

```spl
index=main EventCode=1
| table _time User ParentImage Image CommandLine
| sort - _time
```

### Calculator test

Calculator was launched:

```cmd
calc.exe
```

The related event was located with:

```spl
index=main EventCode=1 Image="*\\Calculator.exe"
```

Depending on the Windows version, the executable name may differ. A broader search can also be used:

```spl
index=main EventCode=1 CommandLine="*calc*"
```

---

## 9. Sysmon Event IDs Used

| Event ID | Event Type | Lab Usage |
|---|---|---|
| 1 | Process Creation | PowerShell, discovery commands, LOLBins, scheduled tasks |
| 3 | Network Connection | Outbound connection monitoring |
| 11 | File Create | Executable file creation |
| 12 | Registry Object Create/Delete | Registry investigation |
| 13 | Registry Value Set | Registry Run Key persistence |
| 14 | Registry Object Rename | Registry investigation |

Most project detections rely on Event ID 1 because it provides:

- Process image
- Command line
- Parent process
- User
- Hashes
- Integrity level
- Process identifiers

---

## 10. Example Validation Searches

### All Sysmon telemetry

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

### Process creation

```spl
index=main EventCode=1
| table _time User ParentImage Image CommandLine
| sort - _time
```

### Network connections

```spl
index=main EventCode=3
| table _time User Image Protocol DestinationIp DestinationPort
| sort - _time
```

### Executable file creation

```spl
index=main EventCode=11 TargetFilename="*.exe"
| table _time User Image TargetFilename
| sort - _time
```

### Registry modifications

```spl
index=main (EventCode=12 OR EventCode=13 OR EventCode=14)
| table _time EventCode User Image TargetObject Details
| sort - _time
```

---

## 11. Troubleshooting Notes

Several issues were encountered while building the telemetry pipeline.

### Sysmon events existed in Event Viewer but not Splunk

Checks performed:

1. Confirmed Sysmon was running.
2. Confirmed events existed in the Sysmon Operational channel.
3. Confirmed the Universal Forwarder service was running.
4. Confirmed `127.0.0.1:9997` was listed as an active forward.
5. Confirmed the Sysmon input existed in `inputs.conf`.
6. Confirmed Splunk Enterprise was listening on TCP port `9997`.
7. Restarted the Universal Forwarder.

### Events appeared as raw XML

Initially, events arrived in Splunk but fields such as `EventCode`, `Image`, and `CommandLine` were unavailable.

The raw events could still be validated using:

```spl
index=main
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
```

Installing the Splunk Add-on for Sysmon enabled structured field extraction.

### `index=*` returned no useful endpoint events

Internal Splunk events were visible in:

```spl
index=_internal
```

Endpoint events were later confirmed in:

```spl
index=main
```

This demonstrated that forwarder communication and endpoint data ingestion must be validated separately.

### Event ID 3 returned no results

Network connection logging was not enabled by the original Sysmon configuration.

A narrow network rule was added for `curl.exe`, the Sysmon configuration was updated, and controlled traffic was generated with:

```cmd
curl.exe https://example.com
```

The resulting Event ID 3 was then visible in Splunk.

---

## 12. Security and Safety

All activity was performed inside an isolated and authorized virtual lab.

The simulations used legitimate Windows utilities and harmless commands to generate defensive telemetry.

No real organizational data, production credentials, unauthorized systems, or destructive malware were used.

The VirtualBox snapshot provides a recovery point if the lab must be restored.

---

## Final Validation

The setup was considered successful after the following conditions were confirmed:

- Sysmon generated Windows endpoint telemetry.
- The Universal Forwarder monitored the Sysmon Operational channel.
- Splunk Enterprise received events over TCP port `9997`.
- Events were indexed in `main`.
- Sysmon XML fields were extracted correctly.
- Process, network, file, and registry events were searchable.
- The 11 controlled detections returned the expected results.

The completed environment provided the telemetry required for the detection engineering scenarios documented in the [`Detection-Queries`](../Detection-Queries/) directory.
