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

- [OAuth – New Consents Granted](#oauth--new-consents-granted)
- [Shadow IT – Cloud Applications by Usage Volume](#shadow-it--cloud-applications-by-usage-volume)
- [OAuth – New Consents (last 7 days)](#oauth--new-consents-last-7-days)
- [OAuth – Apps with Potentially High-Risk Permissions](#oauth--apps-with-potentially-high-risk-permissions)
- [General Usage – Top Cloud Applications by Activity](#general-usage--top-cloud-applications-by-activity)
- [Discovery – Newly Detected Applications (7d vs 60d)](#discovery--newly-detected-applications-7d-vs-60d)
- [Governance – Administrative Operations in Cloud Apps](#governance--administrative-operations-in-cloud-apps)
- [Risk – Mass Object Deletions](#risk--mass-object-deletions)
- [Exfiltration – Mass Downloads from Cloud Apps](#exfiltration--mass-downloads-from-cloud-apps)
- [Collaboration – Excessive External Sharing](#collaboration--excessive-external-sharing)
- [Geolocation – Activity from Unusual Countries](#geolocation--activity-from-unusual-countries)
- [Geolocation – Impossible Travel (<2h between countries)](#geolocation--impossible-travel-2h-between-countries)

---

## Operational Queries 

### OAuth – New Consents Granted

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### Shadow IT – Cloud Applications by Usage Volume

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
```

---

## MDA Catalog – Advanced Hunting (10 detections)

### OAuth – New Consents (last 7 days)

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### OAuth – Apps with Potentially High-Risk Permissions

> **Note:** This query is functionally equivalent to OAuth – New Consents.
> To identify *actual high risk*, enrichment with OAuth permissions (e.g., `Permissions`, `OAuthAppId`, `Scope`) is required.

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### General Usage – Top Cloud Applications by Activity

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 25 by Events desc
```

### Discovery – Newly Detected Applications (7d vs 60d)

```kusto
let Lookback = 7d;
let Baseline = 60d;
let recent = CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize FirstSeen=min(Timestamp), Events=count() by Application;
let historical = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(Lookback))
| summarize PrevEvents=count() by Application;
recent
| join kind=leftanti historical on Application
| order by Events desc
```

### Governance – Administrative Operations in Cloud Apps

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where IsAdminOperation == true
| summarize Events=count(), IPs=make_set(IPAddress, 20) by Application, ActionType, AccountDisplayName
| order by Events desc
```

### Risk – Mass Object Deletions

```kusto
let TimeRange = 7d;
let DeletionThreshold = 10;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Delete","Remove","Purge")
| summarize Deletions=count(), Users=dcount(AccountId) by Application, ActionType
| where Deletions > DeletionThreshold
| order by Deletions desc
```

### Exfiltration – Mass Downloads from Cloud Apps

```kusto
let TimeRange = 7d;
let DownloadThreshold = 50;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Download","FileDownloaded","Export")
| summarize Downloads=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Downloads > DownloadThreshold
| order by Downloads desc
```

### Collaboration – Excessive External Sharing

```kusto
let TimeRange = 14d;
let ShareThreshold = 20;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("SharingSet","SharingInvitationCreated","Anonymous")
| summarize Shares=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Shares > ShareThreshold
| order by Shares desc
```

### Geolocation – Activity from Unusual Countries

```kusto
let TimeRange = 7d;
let Baseline = 60d;
let known = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(TimeRange))
| where isnotempty(CountryCode)
| summarize KnownCountries=make_set(CountryCode, 200) by AccountId;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where isnotempty(CountryCode)
| summarize RecentCountries=make_set(CountryCode, 50), Events=count() by AccountId, AccountDisplayName
| join kind=leftouter known on AccountId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountDisplayName, NewCountries, Events
| order by array_length(NewCountries) desc
```

### Geolocation – Impossible Travel (<2h between countries)

```kusto
let TimeRange = 1d;
let Window = 2h;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where isnotempty(CountryCode)
| summarize Countries=make_set(CountryCode, 10), MinTime=min(Timestamp), MaxTime=max(Timestamp)
  by AccountId, AccountDisplayName, bin(Timestamp, Window)
| where array_length(Countries) >= 2
| project AccountDisplayName, Countries, MinTime, MaxTime
| order by MaxTime desc
```

---

## Operational Notes

- **Time windows**:
  - `1d`: high-immediacy detections (impossible travel).
  - `7d`: standard anomalous behavior.
  - `14d`: gradual collaboration patterns.
- **Thresholds** defined as variables to facilitate per-environment tuning.
