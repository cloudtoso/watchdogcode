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
- [Requirements and Notes](#-requirements-and-notes)
- [Spoofing and Authentication](#-spoofing-and-authentication)
  - [1. Spoofing: From (Header) ≠ MailFrom (Envelope)](#1-spoofing-from-header--mailfrom-envelope)
  - [2. Spoofing: Internal Header From vs External MailFrom](#2-spoofing-internal-header-from-vs-external-mailfrom)
  - [3. Spoofing: Authentication Failures (SPF/DKIM/DMARC)](#3-spoofing-authentication-failures-spfdkimdmarc)
  - [4. Spoofing: Campaign Analysis](#4-spoofing-campaign-analysis)
- [Impersonation & Brand Protection](#️-impersonation--brand-protection)
  - [5. Impersonation: Typosquat Domains (Levenshtein)](#5-impersonation-typosquat-domains-levenshtein)
  - [6. Impersonation: Homoglyph / Punycode](#6-impersonation-homoglyph--punycode)
  - [7. Impersonation: VIP User](#7-impersonation-vip-user)
  - [8. Impersonation: Look-alike Domains (Simple Heuristic)](#8-impersonation-look-alike-domains-simple-heuristic)
- [Phishing, BEC & Social Engineering](#-phishing-bec--social-engineering)
  - [9. BEC: Urgency and Payment Signals](#9-bec-urgency-and-payment-signals)
  - [10. Spear-phishing to VIPs](#10-spear-phishing-to-vips)
  - [11. Light BEC: Reply-To Mismatch](#11-light-bec-reply-to-mismatch)
  - [12. "Quasi-QRCode" / Image Only Technique](#12-quasi-qrcode--image-only-technique)
  - [13. Phishing Kits (Forms)](#13-phishing-kits-forms)
- [URL & Attachment Analysis](#-url--attachment-analysis)
  - [14. Pivot by Suspicious URLs](#14-pivot-by-suspicious-urls)
  - [15. Low-Value URLs / Risky TLDs](#15-low-value-urls--risky-tlds)
  - [16. Active Campaign: Multiple Clicks on Same URL](#16-active-campaign-multiple-clicks-on-same-url)
  - [17. Safe Links Blocks](#17-safe-links-blocks)
  - [18. Risky Attachments (Executables/Scripts)](#18-risky-attachments-executablesscripts)
  - [19. HTML/HTA Attachments with Data URI](#19-htmlhta-attachments-with-data-uri)
- [Anomaly & Behavior Detection](#-anomaly--behavior-detection)
  - [20. "Recently Seen" Sender Domain](#20-recently-seen-sender-domain)
  - [21. Users with High Volume of Reports](#21-users-with-high-volume-of-reports)
  - [22. Top Targets (Risk Pareto)](#22-top-targets-risk-pareto)
  - [23. "Post-Compromise" Inbox Rules](#23-post-compromise-inbox-rules)
  - [24. Clicks from Atypical Locations](#24-clicks-from-atypical-locations)
  - [25. Top Active Campaigns](#25-top-active-campaigns)
- [Defense Effectiveness & Post-Delivery](#️-defense-effectiveness--post-delivery)
  - [26. Post-Delivery Remediated Messages (ZAP)](#26-post-delivery-remediated-messages-zap)
  - [27. Initial Evasion + Subsequent ZAP](#27-initial-evasion--subsequent-zap)
  - [28. Bypass by Allow/Override](#28-bypass-by-allowoverride)
- [Validation of Delivered Emails with Threats](#-validation-of-delivered-emails-with-threats)
  - [29. Emails delivered with some type of threat (Base query)](#29-emails-delivered-with-some-type-of-threat-base-query)
  - [30. Confirm if it was Safe Attachments or Safe Links](#30-confirm-if-it-was-safe-attachments-or-safe-links)
  - [31. Tracking Opened Malicious Attachments from Delivered Emails](#31-tracking-opened-malicious-attachments-from-delivered-emails)
  - [32. Tracking URL Clicks from Delivered Emails with Threats](#32-tracking-url-clicks-from-delivered-emails-with-threats)
  
---

## 📋 Requirements and Notes

*   **Required tables:** These queries use standard tables such as `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents`, `CloudAppEvents`.
*   **Customization:** Some fields may vary depending on tenant configuration. Look for comments in the code (e.g., `// <-- Change to your domains`) to adjust variables.
*   **Suggested use:** Use these queries for proactive detection and triage. Pivot results by `NetworkMessageId`, `SenderFromAddress`, or `RecipientEmailAddress` to dig deeper.

---

## 🎭 Spoofing and Authentication

### 1. Spoofing: From (Header) ≠ MailFrom (Envelope)
Detects messages where the visible domain ("From") does not match the real SMTP envelope domain ("MailFrom"). Useful for classic spoofing and misconfigured "send on behalf" setups.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where isempty(SenderFromDomain) == false and isempty(SenderMailFromDomain) == false
| where SenderFromDomain != SenderMailFromDomain
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 2. Spoofing: Internal Header From vs External MailFrom
Very effective for detecting corporate identity spoofing attempts ("I'm pretending to be from your org").

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain in ("contoso.com","contoso.mx")
| where SenderMailFromDomain !in ("contoso.com","contoso.mx")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 3. Spoofing: Authentication Failures (SPF/DKIM/DMARC)
Analyzes authentication details when available in `AuthenticationDetails`.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| where SPF has_any ("fail","softfail","temperror","permerror") or DKIM has_any ("fail","none","temperror","permerror") or DMARC has_any ("fail","none","temperror","permerror")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, SPF, DKIM, DMARC, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 4. Spoofing: Campaign Analysis
Groups by sender and domain to determine if it is an isolated event or a mass campaign.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SenderFromDomain, SenderMailFromDomain, SenderFromAddress
| order by Msgs desc, Recipients desc
```
---

## 🕵️ Impersonation & Brand Protection

### 5. Impersonation: Typosquat Domains (Levenshtein)
Detects domains "similar" to a VIP or partner domain using edit distance (e.g., `contoso.com` -> `cont0so.com`).

```kql
let protectedDomains = dynamic(["contoso.com","fabrikam.com"]);
EmailEvents
| where Timestamp >= ago(7d)
| where isnotempty(SenderFromDomain)
| where SenderFromDomain !in (protectedDomains)
| mv-expand ProtectedDomain = protectedDomains
| extend ProtectedDomain = tostring(ProtectedDomain)
//
// Approximate root: second-to-last label (better than [0] if there are subdomains)
//
| extend SenderParts = split(SenderFromDomain, ".")
| extend ProtectedParts = split(ProtectedDomain, ".")
| extend SenderRoot = tostring(SenderParts[array_length(SenderParts)-2])
| extend ProtectedRoot = tostring(ProtectedParts[array_length(ProtectedParts)-2])
| where isnotempty(SenderRoot) and isnotempty(ProtectedRoot)
//
// Basic normalization
//
| extend LenDiff = abs(strlen(SenderRoot) - strlen(ProtectedRoot))
| extend NormalizedSenderRoot = SenderRoot
| extend NormalizedSenderRoot = replace(@"0","o", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"1","l", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"3","e", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"5","s", NormalizedSenderRoot)
//
// Score
//
| extend Score = 0
| extend Score = Score + iif(LenDiff <= 1, 2, iif(LenDiff <= 2, 1, 0))
| extend Score = Score + iif(strlen(ProtectedRoot) >= 6 and (SenderRoot contains ProtectedRoot or ProtectedRoot contains SenderRoot), 1, 0)
| extend Score = Score + iif(strlen(ProtectedRoot) >= 6 and (NormalizedSenderRoot contains ProtectedRoot or ProtectedRoot contains NormalizedSenderRoot), 1, 0)
| where Score >= 2
| summarize
    Msgs        = count(),
    Recipients  = dcount(RecipientEmailAddress),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp),
    ExampleFrom = any(SenderFromAddress)
  by 
    SenderFromDomain, 
    ProtectedDomain,
    SenderRoot, 
    ProtectedRoot, 
    LenDiff, 
    NormalizedSenderRoot,
    Score
| order by Score desc, Msgs desc
```

### 6. Impersonation: Homoglyph / Punycode
Searches for domains that include `xn--` or non-ASCII characters.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain has "xn--" or SenderFromDomain matches regex @"[^\u0000-\u007F]" // non-ASCII
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by SenderFromDomain
| order by Msgs desc
```

### 7. Impersonation: VIP User
Compares the left part of the email (alias) against a VIP list to detect subtle variations (e.g., `michelle` vs `rnichell`).

```kql
// Define the display name list of your VIPs
let VIPNames = dynamic(["Satya Nadella", "Nombre Apellido1", "Director General"]);
EmailEvents
| where Timestamp > ago(7d)
// 1. Filter only emails coming from outside the organization
| where EmailDirection == "Inbound"
// 2. Search for exact or partial matches in the Display Name
| where SenderDisplayName has_any (VIPNames)
// 3. Exclude if the sender domain is yours (avoid false positives from legitimate emails)
// Replace 'tu-dominio.com' with your actual domain
| where SenderFromDomain !endswith "tu-dominio.com"
| project Timestamp, Subject, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, NetworkMessageId
| join kind=inner (
    EmailUrlInfo // Join to see if they also carry suspicious URLs
    | project NetworkMessageId, Url
) on NetworkMessageId
| summarize ScanCount = count(), UniqueUrls = make_set(Url) by Timestamp, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Subject
| order by Timestamp desc
```

### 8. Impersonation: Look-alike Domains (Simple Heuristic)
Searches for specific brand variations in the sender domain.

```kql

let brand = "contoso.com";
EmailEvents
| where Timestamp > ago(7d)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where FromDomain != brand
| extend Dist = abs(strlen(FromDomain) - strlen(brand))
| where Dist <= 3
| where FromDomain contains "cont0so" or FromDomain contains "c0ntoso" or FromDomain contains "contoso-sec" or FromDomain contains "contoso-support"
| summarize count(), Victims=dcount(RecipientEmailAddress) by FromDomain
| order by count_ desc
```

---

## 🎣 Phishing, BEC & Social Engineering

### 9. BEC: Urgency and Payment Signals
Searches for financial pressure keywords in emails with spoofing indicators.

```kql

let becKeywords = dynamic(["urgent","wire","payment","invoice","transfer","bank","remittance","pago","transferencia","factura","urgente"]);
EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain or SenderFromDomain has "xn--"
| where Subject has_any (becKeywords)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 10. Spear-phishing to VIPs
Detects delivered emails to VIPs that have authentication failures or were later detected as Phishing.

```kql

let vip_list = dynamic(["ceo@contoso.com","cfo@contoso.com","board.alias@contoso.com"]);
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress in (vip_list)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| extend AuthFail = not( AuthenticationDetails has "dmarc=pass" and AuthenticationDetails has "spf=pass" )
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress), WithAuthIssues=countif(AuthFail), HighConfidencePhish=countif(ThreatTypes has "Phish" and DetectionMethods has "ZAP" or DetectionMethods has "PhishFilter") by RecipientEmailAddress
| order by HighConfidencePhish desc, WithAuthIssues desc
```

### 11. Light BEC: Reply-To Mismatch
Detects emails where the reply address (`Reply-To`) differs from the sender domain, a common BEC tactic.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where DeliveryLocation in ("Inbox","Folder")
| extend ReplyToDomain = tostring(parse_json(AdditionalFields).ReplyToDomain)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where isnotempty(ReplyToDomain) and ReplyToDomain != FromDomain
| summarize count(), DistinctSenders=dcount(SenderFromAddress) by ReplyToDomain, FromDomain
| order by count_ desc
```

### 12. "Quasi-QRCode" / Image Only Technique
Identifies emails with heavy images, without explicit text/URLs, that result in external clicks (possible QR scanning or image link).

```kql

let delivered_images = EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryLocation in ("Inbox", "Folder")
    // Anti-join to exclude emails that have URLs (per your original logic)
    | join kind=leftanti (
        EmailUrlInfo 
        | where Timestamp > ago(7d) 
        | project NetworkMessageId
    ) on NetworkMessageId
    // Join to filter emails that ONLY have image attachments
    | join kind=inner (
        EmailAttachmentInfo 
        | where Timestamp > ago(7d)
        | where FileType has "image" or FileName matches regex @".*\.(png|jpg|jpeg|gif)$"
        | project NetworkMessageId
    ) on NetworkMessageId
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, EmailTimestamp = Timestamp;
// Cross-reference with URL clicks (Note: if the email has no URLs due to leftanti, this join may return zero results)
delivered_images
| join kind=inner (
    UrlClickEvents 
    | where Timestamp > ago(7d)
    // In UrlClickEvents, the field is usually AccountUpn
    | project ClickTimestamp = Timestamp, RecipientEmailAddress = AccountUpn 
) on RecipientEmailAddress
// Filter so the click happened AFTER receiving the email
| where ClickTimestamp > EmailTimestamp
| summarize MensajesImagenes = count(), DistinctRecipients = dcount(RecipientEmailAddress)
```

### 13. Phishing Kits (Forms)
Detects links to legitimate form services abused for credential theft.

```kql

let form_kits = dynamic(["forms.office.com", "forms.gle", "formcrafts.com", "typeform.com", "smartsheet.com", "airtable.com", "notion.site", "forms.google.com", "formulario.link"]);
EmailUrlInfo
| where Timestamp > ago(7d)
// 1. Filter URLs that match form service domains
| where UrlDomain has_any (form_kits) or Url has_any (form_kits)
// 2. Join with EmailEvents to get who received the email
| join kind=inner (
    EmailEvents 
    | where Timestamp > ago(7d)
    | project NetworkMessageId, RecipientEmailAddress
) on NetworkMessageId
// 3. Now we can use RecipientEmailAddress for the count
| summarize 
    EmailCount = count(), 
    Victims = dcount(RecipientEmailAddress) 
    by UrlDomain
| order by EmailCount desc
```

---

## 🔗 URL & Attachment Analysis

### 14. Pivot by Suspicious URLs
Correlates spoofing events with the URLs contained in them.

```kql

let suspicious = EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain
| project NetworkMessageId, Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject;
suspicious
| join kind=inner (
    EmailUrlInfo
    | where Timestamp >= ago(7d)
    | project NetworkMessageId, Url, UrlDomain
) on NetworkMessageId
| summarize UrlCount=count(), Recipients=dcount(RecipientEmailAddress), Examples=make_set(Url, 10) by SenderFromDomain, SenderFromAddress, Subject
| order by UrlCount desc
```

### 15. Low-Value URLs / Risky TLDs
Identifies domains with unusual TLDs (e.g., `.xyz`, `.top`) that have been delivered and clicked.

```kql

let risky_tlds = dynamic([".top",".xyz",".click",".monster",".fit",".rest",".lol",".casa"]);
let delivered_urls = EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryLocation in ("Inbox","Folder","JunkFolder")
    | join kind=inner (EmailUrlInfo | where Timestamp > ago(7d)) on NetworkMessageId
    | extend Tld = tostring(extract(@"(\.[A-Za-z0-9\-]{2,})$", 1, UrlDomain))
    | where Tld in (risky_tlds)
    | project Timestamp, RecipientEmailAddress, SenderFromAddress, Url, UrlDomain, NetworkMessageId;
delivered_urls
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(7d) | project NetworkMessageId) on NetworkMessageId
| summarize Clics=count() by UrlDomain
| order by Clics desc
```

### 16. Active Campaign: Multiple Clicks on Same URL

```kql

UrlClickEvents
| where Timestamp > ago(7d)
// In UrlClickEvents the user is 'AccountUpn'
| summarize DistinctVictims=dcount(AccountUpn), FirstClick=min(Timestamp), LastClick=max(Timestamp) by Url
| where DistinctVictims >= 3
| order by DistinctVictims desc, LastClick desc
```

### 17. Safe Links Blocks

```kql

UrlClickEvents
| where Timestamp > ago(7d)
// 1. Use ActionType to filter blocks (as in the previous step)
| where ActionType has "Block" 
// 2. Extract the domain from the 'Url' column
| extend ParsedUrl = parse_url(Url)
| extend Domain = tostring(ParsedUrl.Host)
// 3. Now summarize using the new 'Domain' column and 'AccountUpn'
| summarize 
    BlockedClicks = count(), 
    Victims = dcount(AccountUpn) 
    by Domain
| where isnotempty(Domain)
| order by BlockedClicks desc
```

### 18. Risky Attachments (Executables/Scripts)

```kql

let risky_ext = dynamic([".html",".htm",".hta",".js",".vbs",".wsf",".lnk",".iso",".img",".dll",".exe",".ps1",".bat",".cmd",".jar"]);
EmailAttachmentInfo
| where Timestamp > ago(7d)
| extend Ext = tolower(tostring(extract(@"\.[^.]+$", 0, FileName)))
| where Ext in (risky_ext)
| join kind=inner (EmailEvents | where DeliveryLocation in ("Inbox","Folder","JunkFolder")) on NetworkMessageId
| summarize count(), DistinctRecipients=dcount(RecipientEmailAddress) by Ext, SenderFromAddress
| order by count_ desc
```

### 19. HTML/HTA Attachments with Data URI
Detects HTML attachments that use `data:text/html` to obfuscate malicious content.

```kql

EmailAttachmentInfo
| where Timestamp > ago(7d)
| where tolower(FileName) matches regex @"\.(html|htm|hta)$"
| join kind=inner (EmailEvents) on NetworkMessageId
| join kind=leftouter (EmailUrlInfo) on NetworkMessageId
| extend IsDataUri = iif(isnotempty(Url) and Url startswith "data:text/html", true, false)
| summarize Total=count(), DataUri=countif(IsDataUri) by SenderFromAddress
| order by DataUri desc, Total desc
```

---

## 📊 Anomaly & Behavior Detection

### 20. "Recently Seen" Sender Domain
Compares recent traffic against a 45-day historical baseline to detect new domains.

```kql

let Baseline = 45d;
let recent = EmailEvents
  | where Timestamp > ago(7d)
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Cnt=count() by SenderDomain;
let historical = EmailEvents
  | where Timestamp between (ago(Baseline) .. ago(7d))
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize PrevCnt=count() by SenderDomain;
recent
| join kind=leftouter (historical) on SenderDomain
| where isnull(PrevCnt) or PrevCnt == 0
| order by Cnt desc, LastSeen desc
```

### 21. Users with High Volume of Reports
Identifies users who are reporting a lot of phishing (possibly under sustained attack).

```kql

AlertInfo
| where Timestamp > ago(7d)
// 1. Filter by the alert title generated by Microsoft when a user reports
| where Title has "User reported" or ServiceSource == "Microsoft Defender for Office 365"
| join kind=inner (
    AlertEvidence
    | where EntityType == "User"
    // 2. In AlertEvidence, the column is usually AccountUpn or UserPrincipalName
    | project AlertId, ReportingUser = AccountUpn
) on AlertId
| summarize Reports = count() by ReportingUser
| where isnotempty(ReportingUser)
| order by Reports desc
```

### 22. Top Targets (Risk Pareto)
Users who receive the most threats vs. users who click the most.

```kql

// 1. Identify emails with detected threats
let delivered_threats = EmailEvents
    | where Timestamp > ago(7d)
    | where ThreatTypes has_any ("Phish", "Malware", "CredentialPhish")
    | summarize Delivered = count(), DistinctSenders = dcount(SenderFromAddress) by RecipientEmailAddress;
// 2. Identify clicks (using AccountUpn and renaming it for the join)
let clicked = UrlClickEvents
    | where Timestamp > ago(7d)
    | summarize Clicks = count() by RecipientEmailAddress = AccountUpn; 
// 3. Join both tables by email address
delivered_threats
| join kind=leftouter clicked on RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0)
| project RecipientEmailAddress, Delivered, DistinctSenders, Clicks
| order by Delivered desc, Clicks desc
```

### 23. "Post-Compromise" Inbox Rules
Detects forwarding rules to external addresses created recently.

```kql

CloudAppEvents
| where Timestamp > ago(7d)
// 1. Search for specific rule operations in Exchange Online
| where ActionType in ("New-InboxRule", "Set-InboxRule")
// 2. Extract rule details from the RawEventData column
| extend RuleDetails = parse_json(RawEventData).Parameters
| extend RuleName = tostring(parse_json(RawEventData).ObjectId)
// 3. Search for forwarding parameters (ForwardTo or ForwardAsAttachmentTo)
| mv-expand RuleDetails // Expand parameters to find the forwarding one
| where RuleDetails.Name in ("ForwardTo", "ForwardAsAttachmentTo")
| extend FwdTo = tostring(RuleDetails.Value)
// 4. Filter forwarding that is NOT to your domain (change @tu-dominio.com)
| where isnotempty(FwdTo) and not(FwdTo endswith "@tu-dominio.com")
| project Timestamp, AccountUpn, ActionType, RuleName, FwdTo, IPAddress, CountryCode
| order by Timestamp desc
```

### 24. Clicks from Atypical Locations
Compares the current click country against the user's historical baseline.

```kql

// 1. Create location map using the Beta Sign-ins table (richer in geo data)
let ip_location_map = AADSignInEventsBeta
    | where Timestamp > ago(60d)
    | where isnotempty(IPAddress) and isnotempty(Country)
    | summarize LastKnownCountry = take_any(Country) by IPAddress;
// 2. Baseline of usual countries per user
let user_baseline = AADSignInEventsBeta
    | where Timestamp between (ago(60d) .. ago(7d))
    | summarize BaselineCountries = make_set(Country) by AccountUpn;
// 3. Cross-reference with Clicks
UrlClickEvents
| where Timestamp > ago(7d)
| join kind=inner ip_location_map on IPAddress
| join kind=leftouter user_baseline on AccountUpn
// 4. Anomaly detection logic
| extend IsNewCountry = not(set_has_element(BaselineCountries, LastKnownCountry))
| where IsNewCountry == true
| summarize 
    TotalClicks = count(), 
    NewCountryFound = any(LastKnownCountry), 
    EvidenceIP = any(IPAddress),
    ClickedUrl = take_any(Url)
    by AccountUpn
| order by TotalClicks desc
```

### 25. Top Active Campaigns
Summary view similar to "Threat Explorer" grouped by subject and domain.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| summarize Msgs=count(), Victims=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress) by SenderFromDomain, Subject
| order by Msgs desc
```

---

## 🛡️ Defense Effectiveness & Post-Delivery

### 26. Post-Delivery Remediated Messages (ZAP)

```kql

EmailPostDeliveryEvents
| where Timestamp >= ago(7d)
| where ActionType in ("ZAP","Quarantine","SoftDelete","HardDelete")
| project Timestamp, NetworkMessageId, ActionType, ActionResult, RecipientEmailAddress
| order by Timestamp desc
```

### 27. Initial Evasion + Subsequent ZAP
Detects messages that entered clean (no initial detection) but were remediated later.

```kql

EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType in ("SoftDelete","MoveToQuarantine","ZAP")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where DetectionMethods !has "PhishFilter" and ThreatTypes == ""
) on NetworkMessageId
| project Timestamp, ActionType, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| order by Timestamp desc
```

### 28. Bypass by Allow/Override
Reviews emails allowed by organization policies or user/admin overrides.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where OrgLevelAction in ("Allow","DeliverToInbox") or (DetectionMethods has "UserOverride" or DetectionMethods has "AdminOverride")
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress) by OrgLevelAction, DetectionMethods
| order by Total desc
```

---

## 📧 Validation of Delivered Emails with Threats

### 29. Emails delivered with some type of threat (Base query)
Essential query to identify all emails that reached the mailbox with some type of detected threat. Starting point for any investigation of delivered malicious emails.

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction == "Delivered"
| where ThreatTypes has_any ("Malware", "Phish", "Spam")
| project
    EventTimestamp = Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    AuthenticationDetails,
    ConfidenceLevel,
    DeliveryLocation,
    EmailClusterId,
    ReportId
| join kind=leftouter (
    EmailPostDeliveryEvents
    | where Timestamp >= ago(7d)
    | project
        NetworkMessageId,
        PostDeliveryTimestamp = Timestamp,
        ActionType,
        ActionResult
) on NetworkMessageId
```

**Validate by specific threat type:**

Add any of the following filters to the base query to segment by threat category:

#### Malware
```kql
| where ThreatTypes has "Malware"
```

#### Phishing
```kql
| where ThreatTypes has "Phish"
```

#### High-risk spam
```kql
| where ThreatTypes has "Spam"
```

### 30. Confirm if it was Safe Attachments or Safe Links
Verifies if detected attachments were processed by Safe Attachments and what the malware filter verdict was.

```kql
EmailEvents
| where Timestamp > ago(14d)
| project NetworkMessageId,
          SenderFromAddress,
          SenderDisplayName,
          RecipientEmailAddress,
          Subject,
          EmailTimestamp = Timestamp
// ---- SAFE ATTACHMENTS ----
| join kind=leftouter (
    EmailAttachmentInfo
    | where Timestamp > ago(14d)
    | where isnotempty(MalwareFilterVerdict) and MalwareFilterVerdict != "Clean"
    | project NetworkMessageId,
              FileName,
              SHA256,
              MalwareFilterVerdict,
              AttachmentTimestamp = Timestamp
) on NetworkMessageId
// ---- SAFE LINKS ----
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(14d)
    | where ActionType in ("ClickBlocked", "ClickAllowedBlocked")
    | project NetworkMessageId,
              Url,
              UrlDomain,
              SafeLinksAction = ActionType,
              UrlTimestamp = Timestamp
) on NetworkMessageId
// ---- ONLY MESSAGES THAT HAVE SOME PROTECTION TRIGGERED ----
| where isnotempty(MalwareFilterVerdict) or isnotempty(SafeLinksAction)
| project
      EmailTimestamp,
      SenderFromAddress,
      SenderDisplayName,
      RecipientEmailAddress,
      Subject,
      FileName,
      MalwareFilterVerdict,
      Url,
      UrlDomain,
      SafeLinksAction
| order by EmailTimestamp desc
```

### 31. Tracking Opened Malicious Attachments from Delivered Emails
Correlates delivered emails with threats (Malware/Phish) that contain attachments, and verifies if those attachments were opened on devices, using DeviceFileEvents to track post-delivery activity.

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction == "Delivered"
| where ThreatTypes has_any ("Malware", "Phish")
| project
    EmailTimestamp = Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    EmailClusterId
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp >= ago(7d)
    | project NetworkMessageId, FileName, SHA256
) on NetworkMessageId
| join kind=inner (
    DeviceFileEvents
    | where Timestamp >= ago(7d)
    | where ActionType == "FileOpened"
    | project
        SHA256,
        FileOpenTimestamp = Timestamp,
        AccountUpn = InitiatingProcessAccountUpn,
        DeviceName
) on SHA256
| project
    EmailTimestamp,
    FileOpenTimestamp,
    AccountUpn,
    DeviceName,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    ThreatTypes,
    FileName,
    EmailClusterId
| order by FileOpenTimestamp desc
```

### 32. Tracking URL Clicks from Delivered Emails with Threats
Correlates delivered emails with threats (Malware/Phish/Spam) with included URLs and associated clicks, to identify exposed users and the action outcome.

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction == "Delivered"
| where ThreatTypes has_any ("Malware", "Phish", "Spam")
| project
    EmailTimestamp = Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    EmailClusterId
| join kind=inner (
    EmailUrlInfo
    | where Timestamp >= ago(7d)
    | project
        NetworkMessageId,
        Url,
        UrlDomain
) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(7d)
    | project
        NetworkMessageId,
        Url,
        ClickTimestamp = Timestamp,
        ActionType,
        AccountUpn
) on NetworkMessageId, Url
| project
    EmailTimestamp,
    ClickTimestamp,
    AccountUpn,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    ThreatTypes,
    Url,
    UrlDomain,
    ActionType,
    EmailClusterId
| order by ClickTimestamp desc
```


  > Internal Tools 2026
