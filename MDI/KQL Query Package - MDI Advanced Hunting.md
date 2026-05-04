# 🛡️ KQL Query Package (Advanced Hunting)

## *Technology enables security, but discipline ensures its effectiveness.*

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

## Quick recommendations (before running)

- Adjust `TimeRange` and/or filters (`AccountName`, `DeviceName`, `DomainName`) to reduce noise.
- If a table does not exist in your tenant (depends on licensing/ingestion), use the alternative indicated in each query.
- To convert a query into a **Custom Detection**, Microsoft recommends basing it on **Advanced Hunting** and running it regularly.

This document compiles a series of KQL (Kusto Query Language) queries designed for threat detection, triage, and investigation in Microsoft Defender XDR.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano
---

## Table of Contents

1. [Microsoft Defender for Identity Alerts (last X days)](#1-microsoft-defender-for-identity-alerts-last-x-days)
2. [Incidents with identity evidence (quick view)](#2-incidents-with-identity-evidence-quick-view)
3. [Password spraying – multiple failures per account](#3-password-spraying--multiple-failures-per-account)
4. [Privileged accounts with multiple authentication failures](#4-privileged-accounts-with-multiple-authentication-failures)
5. [Anomalous LDAP / SAM-R enumeration](#5-anomalous-ldap--sam-r-enumeration)
6. [AD object enumeration (users / groups)](#6-ad-object-enumeration-users--groups)
7. [Lateral movement – successful logons on multiple machines](#7-lateral-movement--successful-logons-on-multiple-machines)
8. [sAMAccountName spoofing / noPac](#8-samaccountname-spoofing--nopac)
9. [Suspicious UPN changes](#9-suspicious-upn-changes)
10. [PowerShell activity on Domain Controllers](#10-powershell-activity-on-domain-controllers)
11. [DNS tunneling / exfiltration](#11-dns-tunneling--exfiltration)

---

## 1. Microsoft Defender for Identity Alerts (last X days)
```kql
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has_any ("MicrosoftDefenderForIdentity", "Defender for Identity", "MDI")
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, ProviderName
| order by Timestamp desc
```

---

## 2. Incidents with identity evidence (quick view)
```kql
let TimeRange = 7d;
IncidentInfo
| where Timestamp >= ago(TimeRange)
| project Timestamp, IncidentId, Title, Severity, Status, Classification, Determination
| order by Timestamp desc
```

---

## 3. Password spraying – multiple failures per account
```kql
let TimeRange = 1d;
let FailureThreshold = 15;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("LogonFailed", "InvalidPassword", "UserLoginFailed", "Failure")
| summarize FailedLogons = count(), SrcIPs = dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| where FailedLogons >= FailureThreshold and SrcIPs >= 3
| order by FailedLogons desc
```

---

## 4. Privileged accounts with multiple authentication failures
```kql
let TimeRange = 1d;
let FailureThreshold = 8;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "Fail"
| summarize Failures = count() by AccountUpn, AccountName
| where Failures >= FailureThreshold
| join kind=leftouter IdentityAccountInfo on AccountUpn
| where IsPrivileged == true
| project AccountUpn, AccountName, Failures, IsPrivileged
| order by Failures desc
```

---

## 5. Anomalous LDAP / SAM-R enumeration
```kql
let TimeRange = 1d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("SamR query", "Ldap query")
| summarize QueryCount = count() by DeviceName, AccountUpn, bin(Timestamp, 1h)
| where QueryCount > 500
| order by QueryCount desc
```

---

## 6. AD object enumeration (users / groups)
```kql
let TimeRange = 7d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| summarize Events = count(), SrcIPs = dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| order by Events desc
```

---

## 7. Lateral movement – successful logons on multiple machines
```kql
let Lookback = 1d;
let Window = 1h;
let MinDevices = 6;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType in ("LogonSuccess", "LogonAttempted")
| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 25), TotalLogons = count() 
    by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc
```

---

## 8. sAMAccountName spoofing / noPac
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType contains "Account"
| extend OldSamAccount = tostring(parse_json(AdditionalFields).OldValue)
| extend NewSamAccount = tostring(parse_json(AdditionalFields).NewValue)
| where OldSamAccount != NewSamAccount and NewSamAccount endswith "$"
| project Timestamp, AccountUpn, TargetAccountUpn, OldSamAccount, NewSamAccount, DeviceName
| order by Timestamp desc
```

---

## 9. Suspicious UPN changes
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("UPN", "User principal name", "UserPrincipalName")
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields, DeviceName
| order by Timestamp desc
```

---

## 10. PowerShell activity on Domain Controllers
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "PowerShell"
| project Timestamp, AccountUpn, ActionType, AdditionalFields, DeviceName, DestinationDeviceName
| order by Timestamp desc
```

---

## 11. DNS tunneling / exfiltration
```kql
let TimeRange = 1d;
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where RemotePort == 53
| summarize DNSQueries = count(), DistinctDomains = dcount(RemoteUrl) 
    by DeviceName, InitiatingProcessAccountName
| where DNSQueries > 1000 or DistinctDomains > 500
| order by DNSQueries desc
```

---

**Total unique queries**: 11  
**Ready for**: Daily/weekly hunting, Custom Detections, ITDR, SOC Runbooks