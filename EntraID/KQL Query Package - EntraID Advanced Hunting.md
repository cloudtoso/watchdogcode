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
- [1) Detection – Users (EntraIdSignInEvents)](#1-detection--users-entraidsigninevents)
  - [1.1) Top sign-in failures by user](#11-top-sign-in-failures-by-user)
  - [1.2) Top failures by IP (brute force / spray)](#12-top-failures-by-ip-brute-force--spray)
  - [1.3) Password spraying (one IP → many users)](#13-password-spraying-one-ip--many-users)
  - [1.4) Attempts against a single user from many IPs (distributed spray)](#14-attempts-against-a-single-user-from-many-ips-distributed-spray)
  - [1.5) Failure spikes per window (burst detection)](#15-failure-spikes-per-window-burst-detection)
  - [1.6) High-risk sign-ins (RiskLevelAggregated)](#16-high-risk-sign-ins-risklevelaggregated-lowmediumhigh)
  - [1.7) Risk: "at risk" or "confirmed compromised" (RiskState)](#17-risk-at-risk-or-confirmed-compromised-riskstate)
  - [1.8) Sign-in without MFA when MFA was expected](#18-sign-in-without-mfa-when-mfa-was-expected-authenticationrequirement)
  - [1.9) Sign-in with MFA required but CA not applied / failed](#19-sign-in-with-mfa-required-but-ca-not-applied--failed)
  - [1.10) Token issuer ADFS (TokenIssuerType)](#110-token-issuer-adfs-tokenissuertype)
  - [1.11) Sign-ins from new countries by user](#111-sign-ins-from-new-countries-by-user-simple-baseline)
  - [1.12) New devices (EntraIdDeviceId) by user](#112-new-devices-entraiddeviceid-by-user)
  - [1.13) Access from unmanaged or non-compliant devices](#113-access-from-unmanaged-or-non-compliant-devices)
  - [1.14) Guests / external users with activity](#114-guests--external-users-with-activity-isguestuser--isexternaluser)
  - [1.15) Sign-ins with unusual UserAgent](#115-sign-ins-with-unusual-useragent-top-user-agents-by-user)
- [2) Detection – Workload Identities (EntraIdSpnSignInEvents)](#2-detection--workload-identities-entraidspnsigninevents)
  - [2.1) Authentication failures for Service Principals / Managed Identity](#21-authentication-failures-for-service-principals--managed-identity)
  - [2.2) One SPN with many IPs (possible abuse / token theft)](#22-one-spn-with-many-ips-possible-abuse--token-theft)
  - [2.3) New countries for an SPN (baseline)](#23-new-countries-for-an-spn-baseline)
  - [2.4) Managed identity sign-ins (quick inventory)](#24-managed-identity-sign-ins-quick-inventory)
- [3) Detection – Microsoft Graph Abuse (GraphApiAuditEvents)](#3-detection--microsoft-graph-abuse-graphapiauditevents)
  - [3.1) 401/403 failures in Microsoft Graph](#31-401403-failures-in-microsoft-graph-enumerationpermission-abuse)
  - [3.2) Anomalous volume of Graph calls per identity](#32-anomalous-volume-of-graph-calls-per-identity-discovery)
  - [3.3) "Read-heavy" (high GET ratio)](#33-read-heavy-high-get-ratio)
  - [3.4) Sensitive scopes](#34-sensitive-scopes-adjust-your-list)
- [4) Triage – Quick "Pivots" (from signal to context)](#4-triage--quick-pivots-from-signal-to-context)
  - [4.1) Pivot by CorrelationId](#41-pivot-by-correlationid-specific-sign-in)
  - [4.2) Pivot by RequestId](#42-pivot-by-requestid-sign-in)
  - [4.3) Pivot by AccountUpn (24h timeline)](#43-pivot-by-accountupn-24h-timeline)
  - [4.4) Pivot by IP](#44-pivot-by-ip-all-impacted-accounts-and-apps)
  - [4.5) Pivot by Device (EntraIdDeviceId)](#45-pivot-by-device-entraiddeviceid)
- [5) Investigation – Useful Correlations (Entra ↔ Graph ↔ UEBA)](#5-investigation--useful-correlations-entra--graph--ueba)
  - [5.1) High-risk sign-ins → Graph activity within ±30 min](#51-high-risk-sign-ins--graph-activity-within-30-min)
  - [5.2) Password spraying detected (1.3) → check for subsequent successes](#52-password-spraying-detected-13--check-for-subsequent-successes)
  - [5.3) CA not applied → which apps and which users](#53-ca-not-applied-conditionalaccessstatus2--which-apps-and-which-users)
  - [5.4) "New country" (1.11) → enrich with UEBA](#54-new-country-111--enrich-with-ueba-behavioranalytics)
  - [5.5) Behaviors (BehaviorInfo) associated with identity](#55-behaviors-behaviorinfo-associated-with-identity-accountupn)
- [6) Investigation – "Checklist" per entity](#6-investigation--checklist-per-entity)
  - [6.1) "Account under investigation" (comprehensive 7-day view)](#61-account-under-investigation-comprehensive-7-day-view)
  - [6.2) "Service principal under investigation" (7 days)](#62-service-principal-under-investigation-7-days)
  - [6.3) "Graph activity by AccountObjectId" (7 days)](#63-graph-activity-by-accountobjectid-7-days)
- [7) Entra Management Events via CloudAppEvents](#7-entra-management-events-config--administration-via-cloudappevents-if-you-have-defender-for-cloud-apps)
  - [7.1) Discover how Entra is "named" in your tenant](#71-discover-how-entra-is-named-in-your-tenant-application--actiontype)
  - [7.2) Top administrative actions (IsAdminOperation)](#72-top-administrative-actions-isadminoperation-for-the-entra-app-adjust-appname)
  - [7.3) Search for "consent / permission / role" actions](#73-search-for-consent--permission--role-actions-string-match-adjust-terms)
  - [7.4) "New IP" for admin operations](#74-new-ip-for-admin-operations-simple-baseline)
- [References (tables)](#references-tables)

---

# 1) Detection – Users (EntraIdSignInEvents)

## 1.1) Top sign-in failures by user
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Apps=dcount(Application), IPs=dcount(IPAddress) by AccountUpn
| order by Failures desc
```

## 1.2) Top failures by IP (brute force / spray)
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by IPAddress, Country
| order by Users desc, Failures desc
```

## 1.3) Password spraying (one IP → many users)
```kql
let Lookback = 1d;
let MinUsers = 15;
let MinFailures = 50;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 20) by IPAddress, Country
| where Users >= MinUsers and Failures >= MinFailures
| order by Users desc, Failures desc
```

## 1.4) Attempts against a single user from many IPs (distributed spray)
```kql
let Lookback = 1d;
let MinIPs = 10;
let MinFailures = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 20) by AccountUpn
| where IPs >= MinIPs and Failures >= MinFailures
| order by IPs desc, Failures desc
```

## 1.5) Failure spikes per window (burst detection)
```kql
let Lookback = 1d;
let Window = 10m;
let Spike = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count() by IPAddress, AccountUpn, bin(Timestamp, Window)
| where Failures >= Spike
| order by Failures desc
```

## 1.6) High-risk sign-ins (RiskLevelAggregated: low/medium/high)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50, 100)   // medium, high
| project Timestamp, AccountUpn, RiskLevelAggregated, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

## 1.7) Risk: "at risk" or "confirmed compromised" (RiskState)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskState in (4, 5)
| project Timestamp, AccountUpn, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

## 1.8) Sign-in without MFA when MFA was expected (AuthenticationRequirement)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn
| order by SignIns desc
```

## 1.9) Sign-in with MFA required but CA not applied / failed
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ConditionalAccessStatus in (1,2)   // 1=failed to apply; 2=not applied
| project Timestamp, AccountUpn, Application, ConditionalAccessStatus, ConditionalAccessPolicies, IPAddress, Country
| order by Timestamp desc
```

## 1.10) Token issuer ADFS (TokenIssuerType)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where TokenIssuerType == 1
| summarize SignIns=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by Application, ResourceDisplayName
| order by SignIns desc
```

## 1.11) Sign-ins from new countries by user (simple baseline)
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountUpn, NewCountries, RecentIPs
| order by array_length(NewCountries) desc
```

## 1.12) New devices (EntraIdDeviceId) by user
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownDevices=make_set(EntraIdDeviceId, 500) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentDevices=make_set(EntraIdDeviceId, 100), SampleApps=make_set(Application, 20) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewDevices = set_difference(RecentDevices, KnownDevices)
| where array_length(NewDevices) > 0
| project AccountUpn, NewDevices, SampleApps
```

## 1.13) Access from unmanaged or non-compliant devices
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManaged == 0 or IsCompliant == 0
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn, IsManaged, IsCompliant
| order by SignIns desc
```

## 1.14) Guests / external users with activity (IsGuestUser / IsExternalUser)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsGuestUser == true or IsExternalUser == 1
| summarize SignIns=count(), Apps=make_set(Application, 20), Countries=make_set(Country, 20) by AccountUpn
| order by SignIns desc
```

## 1.15) Sign-ins with unusual UserAgent (top user agents by user)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count() by AccountUpn, UserAgent
| top 200 by SignIns
```

---

# 2) Detection – Workload Identities (EntraIdSpnSignInEvents)

## 2.1) Authentication failures for Service Principals / Managed Identity
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), Countries=dcount(Country) by ServicePrincipalName, ServicePrincipalId, IsManagedIdentity
| order by Failures desc
```

## 2.2) One SPN with many IPs (possible abuse / token theft)
```kql
let Lookback = 7d;
let MinIPs = 10;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 25) by ServicePrincipalName, ServicePrincipalId
| where IPs >= MinIPs
| order by IPs desc, SignIns desc
```

## 2.3) New countries for an SPN (baseline)
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSpnSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by ServicePrincipalId;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by ServicePrincipalId, ServicePrincipalName
| join kind=leftouter historical on ServicePrincipalId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project ServicePrincipalName, ServicePrincipalId, NewCountries, RecentIPs
```

## 2.4) Managed identity sign-ins (quick inventory)
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManagedIdentity == true
| summarize SignIns=count(), Resources=make_set(ResourceDisplayName, 50) by ServicePrincipalName, ServicePrincipalId
| order by SignIns desc
```

---

# 3) Detection – Microsoft Graph Abuse (GraphApiAuditEvents)

## 3.1) 401/403 failures in Microsoft Graph (enumeration/permission abuse)
```kql
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where ResponseStatusCode in ("401","403")
| summarize Attempts=count(), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, IPAddress, Scopes
| order by Attempts desc
```

## 3.2) Anomalous volume of Graph calls per identity (discovery)
```kql
let Lookback = 1d;
let Spike = 500;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Requests=count(), DistinctUris=dcount(RequestUri) by AccountObjectId, ApplicationId
| where Requests >= Spike
| order by Requests desc
```

## 3.3) "Read-heavy" (high GET ratio)
```kql
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Total=count(), Gets=countif(RequestMethod == "GET"), Ratio=round(todouble(Gets)/todouble(Total), 3) by AccountObjectId, ApplicationId
| where Total > 200 and Ratio > 0.9
| order by Total desc
```

## 3.4) Sensitive scopes (adjust your list)
```kql
let Lookback = 7d;
let HighRiskScopes = dynamic([
  "Mail.Read", "Mail.ReadWrite", "Mail.ReadWrite.All",
  "Files.Read", "Files.ReadWrite", "Files.ReadWrite.All",
  "Sites.Read.All", "Sites.ReadWrite.All",
  "Directory.Read.All", "Directory.ReadWrite.All",
  "User.Read.All", "Group.Read.All"
]);
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where Scopes has_any (HighRiskScopes)
| summarize Requests=count(), IPs=dcount(IPAddress), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, Scopes
| order by Requests desc
```

---

# 4) Triage – Quick "Pivots" (from signal to context)

## 4.1) Pivot by CorrelationId (specific sign-in)
```kql
let Correlation = "<paste-correlation-id>";
EntraIdSignInEvents
| where CorrelationId == Correlation
| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, City,
          LogonType, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, ConditionalAccessPolicies,
          RiskLevelAggregated, RiskState, RiskDetails, UserAgent, ClientAppUsed, EntraIdDeviceId, DeviceName
| order by Timestamp desc
```

## 4.2) Pivot by RequestId (sign-in)
```kql
let ReqId = "<paste-request-id>";
EntraIdSignInEvents
| where RequestId == ReqId
| project *
```

## 4.3) Pivot by AccountUpn (24h timeline)
```kql
let User = "user@contoso.com";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| project Timestamp, Application, ResourceDisplayName, IPAddress, Country, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelAggregated
| order by Timestamp desc
```

## 4.4) Pivot by IP (all impacted accounts and apps)
```kql
let Ip = "1.2.3.4";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IPAddress == Ip
| summarize Events=count(), Users=make_set(AccountUpn, 50), Apps=make_set(Application, 50), Errors=make_set(tostring(ErrorCode), 20)
```

## 4.5) Pivot by Device (EntraIdDeviceId)
```kql
let DeviceId = "<entra-device-id>";
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where EntraIdDeviceId == DeviceId
| project Timestamp, AccountUpn, DeviceName, OSPlatform, DeviceTrustType, IsManaged, IsCompliant, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

---

# 5) Investigation – Useful Correlations (Entra ↔ Graph ↔ UEBA)

## 5.1) High-risk sign-ins → Graph activity within ±30 min
```kql
let Lookback = 7d;
let PivotWindow = 30m;
let risky = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50,100) or RiskState in (4,5)
| project SignInTime=Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, Application, CorrelationId;
GraphApiAuditEvents
| join kind=inner (risky) on AccountObjectId
| where Timestamp between (SignInTime - PivotWindow .. SignInTime + PivotWindow)
| project SignInTime, Timestamp, AccountUpn, ApplicationId, IPAddress, RequestMethod, RequestUri, Scopes, ResponseStatusCode
| order by SignInTime desc, Timestamp desc
```

## 5.2) Password spraying detected (1.3) → check for subsequent successes
```kql
let Lookback = 1d;
let Window = 1h;
let MinUsers = 15;
let suspects = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn) by IPAddress
| where Users >= MinUsers
| project IPAddress;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| join kind=inner (suspects) on IPAddress
| summarize Failures=countif(ErrorCode!=0), Success=countif(ErrorCode==0), Users=dcount(AccountUpn) by IPAddress, bin(Timestamp, Window)
| order by Success desc
```

## 5.3) CA not applied (ConditionalAccessStatus=2) → which apps and which users
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ConditionalAccessStatus == 2
| summarize Events=count(), Users=dcount(AccountUpn) by Application, ResourceDisplayName
| order by Events desc
```

## 5.4) "New country" (1.11) → enrich with UEBA (BehaviorAnalytics)
> Example of UEBA for failures from a "first time" country and uncommon among peers citeturn7search157
```kql
BehaviorAnalytics
| where ActivityType == "FailedLogOn"
| where ActivityInsights.FirstTimeUserConnectedFromCountry == True
| where ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True
```

## 5.5) Behaviors (BehaviorInfo) associated with identity (AccountUpn)
```kql
let Lookback = 14d;
BehaviorInfo
| where Timestamp >= ago(Lookback)
| where isnotempty(AccountUpn)
| project Timestamp, Title, Categories, AttackTechniques, AccountUpn, ServiceSource, DetectionSource, StartTime, EndTime
| order by Timestamp desc
```

---

# 6) Investigation – "Checklist" per entity

## 6.1) "Account under investigation" (comprehensive 7-day view)
```kql
let User = "user@contoso.com";
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), HighRisk=countif(RiskLevelAggregated in (50,100) or RiskState in (4,5)),
          Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Apps=make_set(Application, 50)
```

## 6.2) "Service principal under investigation" (7 days)
```kql
let SpId = "<service-principal-id>";
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ServicePrincipalId == SpId
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Resources=make_set(ResourceDisplayName, 50)
```

## 6.3) "Graph activity by AccountObjectId" (7 days)
```kql
let ObjId = "<account-object-id>";
let Lookback = 7d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where AccountObjectId == ObjId
| summarize Requests=count(), Methods=make_set(RequestMethod, 10), Targets=make_set(TargetWorkload, 20), URIs=make_set(RequestUri, 50) by ApplicationId, IPAddress
| order by Requests desc
```

---



---

# 7) Entra Management Events (config / administration) via CloudAppEvents (if you have Defender for Cloud Apps)

> The `CloudAppEvents` table is fed from **Microsoft Defender for Cloud Apps** and requires the connector to be enabled; if it is not deployed, the queries will not return data. citeturn7search194

## 7.1) Discover how Entra is "named" in your tenant (Application / ActionType)
```kql
let Lookback = 30d;
CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize Events=count(), SampleActions=make_set(ActionType, 20) by Application
| order by Events desc
```

## 7.2) Top administrative actions (IsAdminOperation) for the Entra app (adjust AppName)
```kql
let Lookback = 14d;
let AppName = "Azure Active Directory";   // change according to G1
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where IsAdminOperation == true
| summarize Events=count(), Actors=make_set(AccountDisplayName, 20), IPs=make_set(IPAddress, 20) by ActionType
| order by Events desc
```

## 7.3) Search for "consent / permission / role" actions (string match, adjust terms)
```kql
let Lookback = 30d;
let AppName = "Azure Active Directory";   // change according to G1
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where ActionType has_any ("consent", "permission", "role", "grant", "app")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, RawEventData, AdditionalFields
| order by Timestamp desc
```

## 7.4) "New IP" for admin operations (simple baseline)
```kql
let Lookback = 60d;
let Recent = 3d;
let AppName = "Azure Active Directory";   // change according to G1
let hist = CloudAppEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| where Application == AppName and IsAdminOperation == true
| summarize KnownIPs=make_set(IPAddress, 500) by AccountObjectId;
CloudAppEvents
| where Timestamp >= ago(Recent)
| where Application == AppName and IsAdminOperation == true
| summarize RecentIPs=make_set(IPAddress, 100), Actions=make_set(ActionType, 25) by AccountObjectId, AccountDisplayName
| join kind=leftouter hist on AccountObjectId
| extend NewIPs = set_difference(RecentIPs, KnownIPs)
| where array_length(NewIPs) > 0
| project AccountDisplayName, AccountObjectId, NewIPs, Actions
```

## References (tables)
- Entra sign-ins (`EntraIdSignInEvents`) citeturn7search172
- Entra SPN sign-ins (`EntraIdSpnSignInEvents`) citeturn7search176
- Graph API audit (`GraphApiAuditEvents`) citeturn7search166
- Schema tables overview (to validate columns in your tenant) citeturn7search177

  > Internal Tools 2026
