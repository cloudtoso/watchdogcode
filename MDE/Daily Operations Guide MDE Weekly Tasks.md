# Weekly Operational Security Guide: Microsoft Defender for Endpoint 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes the weekly procedures for analyzing threat trends, executing proactive hunting, managing vulnerabilities, and reviewing endpoint security posture in Microsoft Defender for Endpoint (MDE).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

## Scope
This guide describes **weekly operational activities** for Microsoft Defender for Endpoint (MDE), focused on:

---
## Table of Contents
- [Threat Trend Analysis](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#threat-trend-analysis)
- [Weekly Advanced Hunting](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#weekly-advanced-hunting)
- [Exposure and Vulnerabilities](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#exposure-and-vulnerabilities)
- [Security Configuration Review](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#security-configuration-review)
- [Repeat Offender Devices](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#repeat-offender-devices)
- [Operational / Executive Report](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#operational--executive-report)

---
# Threat Trend Analysis

## Access to Threat Analytics

1. Go to: https://security.microsoft.com/threatanalytics3
2. Review threats marked as **Active** or **Trending**
3. Filter by **Service source:** Microsoft Defender for Endpoint

The panel shows:
* Active and emerging threats
* Exposed vs. mitigated devices
* TTPs used by threat actors
* Associated IOCs

## Identify Recurring Patterns

Review threats from the past week and look for:
* Recurring malware families (Emotet, QakBot, Cobalt Strike, etc.)
* Prevalent techniques (LOLBins, PowerShell abuse, DLL sideloading)
* Detected persistence patterns (RunKeys, Scheduled Tasks, WMI)
* Common entry vectors (phishing → endpoint, USB, exposed RDP)

## Assess Impact and Mitigation Status

For each high-impact threat:

1. Open the **Analyst report** to review:
    * Technical description of the attack
    * TTPs mapped to MITRE ATT&CK
    * Indicators of compromise (IOCs)
2. Review the **Impacted assets** tab:
    * Exposed devices (without mitigation)
    * Mitigated devices
    * Potentially affected users
3. Review the **Mitigations & detections** tab:
    * ASR rule status
    * Antivirus signatures
    * Active EDR detections

## Derived Actions

* If there are exposed devices → Apply the recommended mitigations
* If there are new IOCs → Create indicators in **Settings** → **Endpoints** → **Rules** → **Indicators**
* If there is a growing trend → Notify the team and evaluate ASR hardening
* Document findings in the weekly report

---

# Weekly Advanced Hunting

## Proactive Hunting Objective

Execute weekly KQL queries to detect suspicious activity that did not generate automatic alerts, focusing on evasion and persistence techniques.

1. Go to: https://security.microsoft.com/v2/advanced-hunting

## Anomalous Processes

Detect unusual or suspicious process execution:
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "EncodedCommand", "-enc", "bypass", "hidden")
| summarize ExecutionCount = count(), Devices = dcount(DeviceName) by FileName, ProcessCommandLine
| where ExecutionCount <= 3
| order by ExecutionCount asc
```

Review:
* Commands with Base64 encoding
* Execution from unusual paths (Temp, AppData, ProgramData)
* Legitimate processes used for evasion (LOLBins)

## Persistence (RunKeys and Scheduled Tasks)

Detect persistence mechanisms created in the past week:

```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

```kql
DeviceEvents
| where Timestamp >= ago(7d)
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

Review:
* Scheduled tasks created by non-standard processes
* Registry values pointing to unsigned scripts or binaries
* Persistence patterns associated with known malware families

## Downloads from Suspicious Domains

Detect connections to low-reputation or newly registered domains:

```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl !has_any ("microsoft.com", "windows.com", "office.com", "azure.com", "windowsupdate.com")
| summarize ConnectionCount = count(), Devices = dcount(DeviceName) by RemoteUrl
| where ConnectionCount <= 5
| order by ConnectionCount asc
| take 50
```

Review:
* Domains with DGA (Domain Generation Algorithm) patterns
* Connections to free hosting services (pastebin, discord CDN, etc.)
* Outbound traffic on non-standard ports

## Document Findings

1. Record executed queries and relevant results
2. Create custom alerts (**Custom detection rules**) for recurring findings
3. Include results in the weekly report

> If a finding requires immediate action, escalate as an incident and do not wait for the weekly cycle.

---

# Exposure and Vulnerabilities

## Access to Microsoft Defender Vulnerability Management (MDVM)

1. Go to: https://security.microsoft.com/tvm_dashboard
2. Review the current **Exposure Score** and compare with the previous week

The dashboard shows:
* Exposure Score (tenant exposure score)
* Devices with the highest exposure
* Prioritized security recommendations
* Vulnerable software with known exploits

## Identify Exploitable Vulnerable Software

1. Go to **Vulnerability management** → **Weaknesses**
2. Filter by:
    * **Exploit available:** Yes
    * **Severity:** Critical, High
3. Review CVEs with publicly available exploits
4. Correlate with Threat Analytics to verify if any active threat exploits the vulnerability

For detailed analysis via KQL:

```kql
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical", "High")
| where IsExploitAvailable == 1
| summarize DeviceCount = dcount(DeviceId) by CveId, SoftwareName, VulnerabilitySeverityLevel
| order by DeviceCount desc
| take 25
```

## Devices with Highest Exposure

1. Go to **Vulnerability management** → **Exposed devices**
2. Sort by **Exposure level:** High, Critical
3. For each high-exposure device, review:
    * Unpatched vulnerabilities
    * Insecure configurations
    * EOL (End of Life) software
    * Pending recommendations

## Prioritize Remediations

1. Go to **Vulnerability management** → **Recommendations**
2. Sort by **Exposure impact** and **Remediation type**
3. For critical recommendations:
    * Create a **Remediation request** assigned to the infrastructure team
    * Set a target remediation date
    * Document exceptions with justification if applicable
4. Verify the status of previous remediations in the **Remediation** tab

---

# Security Configuration Review

## Validate Attack Surface Reduction (ASR) Rules

1. Go to: https://security.microsoft.com/asr
2. Review the status of each ASR rule:
    * **Block:** Rule actively blocking
    * **Audit:** Rule logging without blocking
    * **Not configured:** Rule not enabled

Key verifications:
* All recommended rules should be in **Block** mode or at least **Audit**
* Review rules in Audit mode that reported detections → Evaluate migration to Block
* Confirm that no unnecessary exclusions were added

Critical rules that should be in Block:
* Block executable content from email client and webmail
* Block Office applications from creating child processes
* Block credential stealing from LSASS
* Block process creations originating from PSExec and WMI commands
* Use advanced protection against ransomware

## Review Antivirus Configurations

1. Go to **Settings** → **Endpoints** → **Configuration management** → **Device configuration**
2. Verify:
    * **Real-time protection:** Enabled
    * **Cloud-delivered protection:** Enabled
    * **Automatic sample submission:** Enabled
    * **Tamper protection:** Enabled
    * **PUA protection:** Enabled (at least in Audit mode)

## Review Exploit Protection

1. Go to **Settings** → **Endpoints** → **Configuration management** → **Exploit protection**
2. Validate that system protections are active:
    * DEP (Data Execution Prevention)
    * ASLR (Address Space Layout Randomization)
    * SEHOP (Structured Exception Handler Overwrite Protection)
    * CFG (Control Flow Guard)
3. Review per-application overrides and validate they are justified

## Confirm Alignment with Baselines

Compare current configurations against:
* [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-guard/windows-defender-application-control/design/microsoft-recommended-block-rules)
* Policies defined by the security team
* Microsoft Secure Score recommendations

> Document any deviations found and create a remediation plan if applicable.

---

# Repeat Offender Devices

## Identify Endpoints with Repeated Incidents

Search for devices that have generated multiple incidents in the last 7 days:

```kql
AlertInfo
| where Timestamp >= ago(7d)
| where ServiceSource has "Endpoint"
| join kind=inner (AlertEvidence | where Timestamp >= ago(7d) | where EntityType == "Machine") on AlertId
| summarize 
    IncidentCount = dcount(Title),
    AlertCount = count(), 
    Severities = make_set(Severity),
    AlertTitles = make_set(Title)
    by DeviceName
| where IncidentCount >= 3
| order by IncidentCount desc
```

## Evaluate Root Cause

For each repeat offender device, review:

1. **Alert patterns**
    * Are the same alerts recurring? → Possible FP or misconfigured exclusion
    * Are they different alerts? → Possible active compromise or high-risk user
2. **Device status**
    * Risk and exposure level
    * Outdated or vulnerable software
    * Configured antivirus exclusions
3. **User activity**
    * High-risk behavior (downloads, browsing, USBs)
    * Unnecessary elevated permissions

## Corrective Actions

Based on the identified root cause:

* **Misconfigured exclusion:** Adjust or remove the exclusion and monitor
* **Vulnerable software:** Prioritize patch or update with infrastructure
* **Active compromise:** Isolate device, collect evidence, initiate investigation
* **Reimage required:** Coordinate with infrastructure for device reimage
* **Additional hardening:** Apply ASR, AppLocker, or WDAC policies
* **High-risk user:** Notify, train, and consider additional restrictions

> Document each case and the action taken. Include in the weekly report.

---

# Operational / Executive Report

## Consolidate Weekly Information

Compile the week's data to generate the report:

## Incidents by Severity

Go to **Incidents** and filter by the last 7 days:
* Total incidents: Critical, High, Medium, Low, Informational
* Resolved vs. pending incidents
* Mean Time to Resolution (MTTR)

## Affected Devices

From the device inventory and Advanced Hunting:
* Total devices with alerts during the week
* Isolated devices or devices with containment actions
* Devices with High/Critical risk level

## Detected Threats

From Threat Analytics and the alert queue:
* Detected malware families
* Most frequent MITRE ATT&CK techniques
* Active campaigns relevant to the environment

## Executed and Pending Actions

From the Action Center and incidents:
* Response actions executed (isolations, scans, investigations)
* AIR actions approved/rejected
* Vulnerability remediations completed
* Pending actions with justification

## Key Metrics for the Report

| Metric | Description |
|---|---|
| Total Incidents | Number of incidents by severity |
| MTTD (Mean Time to Detect) | Average time from first alert to detection |
| MTTR (Mean Time to Respond) | Average time from detection to resolution |
| Devices at Risk | Number of endpoints with Risk Level High/Critical |
| Exposure Score | Tenant exposure score (compare week over week) |
| Sensor Coverage | Percentage of devices with active and reporting sensor |
| ASR Rules in Block | Percentage of ASR rules in Block mode vs. Audit |
| Critical Vulnerabilities | Critical CVEs with available exploit unpatched |

## Generate and Distribute the Report

1. Use the `New-DefenderXDRWeeklyReport.ps1` script to generate the automated report
2. Supplement with manual hunting findings and trend analysis
3. Distribute to:
    * **CISO / Security Director:** Executive summary with key metrics
    * **Infrastructure Team:** Pending remediations and problematic devices
    * **SOC Team:** Lessons learned and detection adjustments
4. Archive the report for auditing and baseline purposes

> The weekly report is the primary input for security decision-making and continuous improvement of the endpoint protection posture.
---
