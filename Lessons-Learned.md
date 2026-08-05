# Lessons Learned

## Overview

Building this SIEM Homelab Detection Lab significantly improved my understanding of Windows endpoint monitoring, SIEM administration, and detection engineering.

Although the final environment appears straightforward, developing it required troubleshooting multiple telemetry, forwarding, and field extraction issues. Solving those challenges gave me a much deeper understanding of how endpoint data moves from Windows into a SIEM and how reliable detections are developed.

---

## Technical Skills Gained

Throughout this project I strengthened my understanding of:

- Windows endpoint telemetry collection
- Sysmon configuration and event generation
- Windows Event Logs
- Splunk Enterprise administration
- Splunk Universal Forwarder configuration
- Data ingestion and log forwarding
- SPL (Search Processing Language)
- Detection engineering
- Threat hunting
- Parent-child process relationships
- Windows persistence mechanisms
- LOLBins (Living-off-the-Land Binaries)
- Network connection monitoring
- Registry monitoring
- File creation monitoring
- MITRE ATT&CK mapping
- Security documentation and reporting

---

## Challenges Encountered

This project presented several technical challenges that required investigation and troubleshooting.

### Universal Forwarder Configuration

One of the biggest challenges was configuring the Splunk Universal Forwarder correctly.

Although Sysmon events were present inside Windows Event Viewer, they did not initially appear inside Splunk.

Troubleshooting involved verifying:

- Forwarder service status
- Forwarding destination
- Receiving port configuration
- Event channel configuration
- Input configuration
- Splunk indexes

This reinforced the importance of validating every stage of the telemetry pipeline instead of assuming that data is flowing correctly.

---

### Field Extraction

After telemetry reached Splunk, the events initially appeared as raw XML.

Important fields such as:

- EventCode
- Image
- ParentImage
- CommandLine

were unavailable until the Splunk Add-on for Sysmon was installed.

This taught me that successful log ingestion does not necessarily mean the data is immediately useful for detection engineering.

---

### SPL Query Development

Writing detection queries required learning how to:

- Filter relevant events
- Reduce unnecessary noise
- Select useful investigative fields
- Format analyst-friendly output
- Improve readability

As the project progressed, I became significantly more comfortable writing and refining SPL searches.

---

### Detection Tuning

Another important lesson was understanding that a detection is not simply a query.

Each detection should:

- Detect meaningful behavior
- Minimize false positives
- Provide useful investigation context
- Include MITRE ATT&CK mappings
- Be documented clearly

This changed the way I think about defensive security.

---

## Key Takeaways

Some of the biggest lessons from this project were:

- Successful telemetry collection depends on every component in the data pipeline functioning correctly.
- Sysmon provides valuable endpoint visibility beyond standard Windows logs.
- Parent-child process relationships provide important investigative context.
- Context is often more valuable than individual process names.
- Not every suspicious event is malicious.
- Effective detections balance visibility with false-positive reduction.
- Clear documentation is an important part of detection engineering.

---

## Future Improvements

If I continue expanding this lab, I would like to add:

- Active Directory attack simulations
- Atomic Red Team attack emulation
- PowerShell Script Block Logging (Event ID 4104)
- Windows Security Event Logs
- Sigma detection rules for every SPL query
- Splunk dashboards and visualizations
- Correlation searches across multiple telemetry sources
- Risk-based alerting
- Zeek or Suricata network telemetry
- Wazuh deployment for comparison with Splunk

---

## Final Reflection

This project helped me move beyond simply learning security concepts and apply them in a practical environment.

Building the lab, troubleshooting telemetry issues, creating detections, documenting investigations, and mapping behavior to the MITRE ATT&CK framework gave me a much stronger understanding of how a Security Operations Center monitors Windows endpoints.

More importantly, I gained confidence in investigating problems methodically and documenting the results in a structured and repeatable way—an essential skill for a SOC analyst.
