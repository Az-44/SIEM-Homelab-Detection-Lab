# SIEM Homelab Detection Lab

A Windows-based security monitoring and detection engineering lab built using Sysmon, Splunk Enterprise, and the Splunk Universal Forwarder.

The project demonstrates the complete detection lifecycle:

**Endpoint telemetry → Log collection → SIEM ingestion → Investigation → SPL detection → MITRE ATT&CK mapping**

> This lab was created for defensive-security education in an isolated virtual environment.

---

## Project Overview

This project simulates the workflow of a Security Operations Center analyst investigating suspicious activity on a Windows endpoint.

A Windows 10 virtual machine generates endpoint telemetry through Sysmon. The Splunk Universal Forwarder collects the events and sends them to Splunk Enterprise, where the activity is investigated using Search Processing Language queries.

The project includes:

- Windows endpoint telemetry collection
- Sysmon process, network, file, and registry monitoring
- Splunk log ingestion and field extraction
- Controlled attack simulations
- Threat hunting and event investigation
- Custom SPL detection queries
- MITRE ATT&CK technique mapping
- Sigma detection rules
- Investigation screenshots
- Lessons learned and future improvements

---

## Lab Architecture

![SIEM Homelab Architecture](architecture/siem-homelab-architecture.png)

```text
Windows 10 Endpoint
        ↓
      Sysmon
        ↓
Windows Event Logs
        ↓
Splunk Universal Forwarder
        ↓
     TCP 9997
        ↓
Splunk Enterprise
        ↓
SPL Searches and Detections
        ↓
Investigation and MITRE ATT&CK Mapping
