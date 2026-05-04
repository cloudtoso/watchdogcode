# KQL Query Package (Advanced Hunting) 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

## Quick recommendations (before running)

- Adjust `TimeRange` and/or filters (`AccountName`, `DeviceName`, `DomainName`) to reduce noise.
- If a table does not exist in your tenant (depends on licensing/ingestion), use the alternative indicated in each query.
- To convert a query into a **Custom Detection**, Microsoft recommends basing it on **Advanced Hunting** and running it regularly.

This document compiles a series of KQL (Kusto Query Language) queries designed for threat detection, triage, and investigation in Microsoft Defender XDR.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano
---

## Table of Contents

- [LOLBins – Suspicious Execution](#lolbins--suspicious-execution)
- [Obfuscated PowerShell / Base64](#obfuscated-powershell--base64)
- [Binary Downloads from the Internet](#binary-downloads-from-the-internet)
- [Persistence – Scheduled Tasks](#persistence--scheduled-tasks)
- [Local User Creation](#local-user-creation)
- [Ransomware-like Activity](#ransomware-like-activity)
- [Credential Dumping](#credential-dumping)
- [Suspicious Connections (C2)](#suspicious-connections-c2)
- [Execution from Unusual Paths](#execution-from-unusual-paths)
- [Service Installation](#service-installation)

---

## LOLBins – Suspicious Execution
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","wscript.exe","cscript.exe"
)
| where ProcessCommandLine has_any (
    "-enc","DownloadString","IEX","Invoke-WebRequest",
    "FromBase64String","http","https"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Obfuscated PowerShell / Base64
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)(-enc\s+[A-Za-z0-9+/=]{20,})"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Binary Downloads from the Internet
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any ("http://","https://")
| where FileName in~ ("powershell.exe","curl.exe","wget.exe","bitsadmin.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

## Persistence – Scheduled Tasks
```kql
DeviceScheduledTaskEvents
| where Timestamp >= ago(14d)
| where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated")
| project Timestamp, DeviceName, TaskName, TaskPath, Author, ActionType
| order by Timestamp desc
```

## Local User Creation
```kql
DeviceEvents
| where Timestamp >= ago(14d)
| where ActionType == "UserAccountCreated"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName
| order by Timestamp desc
```

## Ransomware-like Activity
```kql
DeviceFileEvents
| where Timestamp >= ago(1d)
| where ActionType == "FileRenamed"
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName
| where FileCount > 100
| order by FileCount desc
```

## Credential Dumping
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","lsadump","procdump")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Suspicious Connections (C2)
```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by Timestamp desc
```

## Execution from Unusual Paths
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FolderPath has_any ("\Users\Public\","\AppData\Local\Temp\","\ProgramData\")
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```

## Service Installation
```kql
DeviceEvents
| where Timestamp >= ago(14d)
| where ActionType == "ServiceInstalled"
| project Timestamp, DeviceName, ServiceName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

---

