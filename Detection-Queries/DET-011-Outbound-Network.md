
# DET-011 — Outbound Network Connection

## Objective

Detect outbound network connections initiated by processes on the monitored Windows endpoint. Correlating network activity with the originating process provides valuable context during investigations and helps identify suspicious communications.

---

## Threat Description

After compromising a system, attackers frequently establish outbound network connections to communicate with command-and-control (C2) servers, download additional payloads, exfiltrate data, or perform reconnaissance.

Monitoring process-generated network connections allows analysts to identify which executable initiated the communication and investigate whether the activity is expected or suspicious.

Examples include:

- Command-and-Control (C2) communication
- Malware beaconing
- Payload downloads
- Data exfiltration
- External reconnaissance

Legitimate software also generates outbound connections, making contextual investigation essential.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| Context-dependent | Outbound network activity alone does not identify a specific ATT&CK technique. Additional investigation is required. |

---

## Attack Simulation

The following command was executed inside the Windows 10 virtual machine.

```cmd
curl.exe https://example.com
```

This generated a Sysmon Network Connection (Event ID 3) event.

---

## SPL Detection Query

```spl
index=main EventCode=3 Image="*\\curl.exe"
| eval Detection="Outbound Network Connection"
| eval Severity="Informational"
| eval MITRE="Context-dependent"
| table _time User Image Protocol SourceIp SourcePort DestinationHostname DestinationIp DestinationPort Detection Severity MITRE
| sort -_time
```

---

## Detection Logic

The query searches Sysmon Network Connection (Event ID 3) events for outbound connections initiated by **curl.exe**.

Rather than assuming malicious activity, the detection provides process, protocol, source, destination, and port information so analysts can determine whether the connection is expected or requires further investigation.

---

## Example Detection

![Outbound Network Connection](../Screenshots/det-011-network-connection.png)

---

## Investigation Notes

Observed process:

```
curl.exe
```

Observed user:

```
labuser
```

Observed protocol:

```
TCP
```

Observed destination:

```
example.com
```

Observed destination port:

```
443
```

The outbound HTTPS connection successfully generated a Sysmon Network Connection (Event ID 3) event that was forwarded to Splunk through the Universal Forwarder.

---

## Possible False Positives

- Web browsers
- Software updates
- Cloud synchronization services
- Package managers
- Administrative scripts
- Legitimate API requests

---

## Detection Severity

Informational

---

## Recommendations

Investigate if:

- Unexpected processes establish outbound network connections.
- Connections target unknown or suspicious IP addresses or domains.
- Multiple outbound connections occur immediately after PowerShell, Certutil, Rundll32, or Registry Run Key activity.
- Executables launched from **Temp**, **Downloads**, or **AppData** initiate network communications.
- Large volumes of outbound traffic or unusual destination ports are observed.

Correlating network connections with process creation, file creation, persistence mechanisms, and command-line activity significantly improves detection confidence and helps identify post-compromise behavior.
