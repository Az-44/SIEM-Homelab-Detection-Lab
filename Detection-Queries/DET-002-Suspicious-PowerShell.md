
# DET-002 — Suspicious PowerShell Execution

## Objective

Detect PowerShell executions that use suspicious command-line flags commonly associated with malicious activity, including hidden execution, execution policy bypass, encoded commands, and PowerShell launched without a user profile.

---

## Threat Description

PowerShell is one of the most abused tools in Windows environments because it is built into the operating system and provides powerful administrative capabilities.

Attackers frequently use PowerShell to execute malicious payloads directly in memory, download additional malware, establish persistence, or evade traditional antivirus solutions. Suspicious execution flags are commonly observed during post-exploitation activities and are frequently used by ransomware, remote access trojans (RATs), and offensive security frameworks.

Examples include:

- `-nop`
- `-w hidden`
- `-ExecutionPolicy Bypass`
- `-enc`
- `-EncodedCommand`

Although administrators may occasionally use these parameters legitimately, they should always be reviewed within the context of surrounding activity.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1059.001 | PowerShell |

---

## Attack Simulation

The following PowerShell commands were executed inside the Windows 10 virtual machine.

```powershell
powershell.exe -nop -w hidden -Command "Get-Process"

powershell.exe -ExecutionPolicy Bypass -Command "Get-Service"

powershell.exe -EncodedCommand ZQBjAGgAbwAgAEgAZQBsAGwAbwA=
```

---

## SPL Detection Query

```spl
index=main EventCode=1 Image="*\\powershell.exe"
(CommandLine="*-nop*" OR
CommandLine="*-w hidden*" OR
CommandLine="*-ExecutionPolicy*" OR
CommandLine="*-enc*" OR
CommandLine="*-EncodedCommand*")
| eval Detection=case(
like(CommandLine,"%EncodedCommand%"),"Encoded PowerShell",
like(CommandLine,"% -enc %"),"Encoded PowerShell",
like(CommandLine,"%ExecutionPolicy Bypass%"),"ExecutionPolicy Bypass",
like(CommandLine,"% -nop %"),"NoProfile",
like(CommandLine,"% -w hidden %"),"Hidden Window",
true(),"Suspicious PowerShell"
)
| table _time User ParentImage Detection CommandLine
| sort -_time
```

---

## Detection Logic

The query searches Sysmon Process Creation (Event ID 1) events for PowerShell executions containing command-line arguments frequently associated with malicious behavior.

Each matching event is categorized according to the suspicious parameter that triggered the detection, making investigation faster and providing additional context for analysts.

---

## Example Detection

![Suspicious PowerShell](../Screenshots/det-002-suspicious-powershell.png)

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

Observed behaviors:

- Hidden PowerShell window
- Execution Policy Bypass
- NoProfile execution
- Suspicious PowerShell flags

These executions successfully generated Sysmon Process Creation events that were forwarded to Splunk through the Universal Forwarder.

---

## Possible False Positives

- System administrators
- PowerShell automation scripts
- Enterprise management tools
- Software deployment platforms
- Legitimate penetration testing activities

---

## Detection Severity

High

---

## Recommendations

Investigate if:

- PowerShell is executed with multiple suspicious flags simultaneously.
- Encoded commands are observed.
- PowerShell launches immediately after Office documents, web browsers, or scripting engines.
- Additional child processes, scheduled tasks, registry modifications, or outbound network connections follow the execution.

Correlating PowerShell activity with network, registry, and process creation events significantly improves detection confidence.
