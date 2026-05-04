# Weekly Operational Security Guide: Microsoft Defender for Office 365 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes the weekly procedures for analyzing trends, identifying high-risk users, and managing threat campaigns in Microsoft Defender for Office 365 (MDO).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Table of Contents
- [Review Email Detection Trends in Microsoft Defender for Office 365](#review-email-detection-trends-in-microsoft-defender-for-office-365)
- [Identify Users Most Targeted by Malware and Phishing](#identify-users-most-targeted-by-malware-and-phishing)
- [Review Malware and Phishing Campaigns](#review-malware-and-phishing-campaigns)
- [Validate delivered emails with threats](#validate-delivered-emails-with-threats)

---
# Review Email Detection Trends in Microsoft Defender for Office 365

### Email & Collaboration Reporting

### Access to the main report
1. Go to: https://security.microsoft.com/emailandcollabreport
2. Select **Threat protection status report**

The panel displays trend charts for:
- Malware detections
- Phishing detections
- Spam detections
- URL and attachment verdicts
- Policy actions (blocked, delivered, ZAP)

---

## Adjust Filters to Analyze Trends

Use the top filter bar:
- **Time range**: 24 hours, 7 days, 30 days, 90 days (for weekly tasks, at least 15 days is recommended)
- **Detection type**: Malware, Phish, Spam, High‑confidence Phish
- **Delivery location**: Inbox, Junk, Quarantine, Removed
- **Workload**: Exchange Online, Teams, SharePoint, OneDrive

This allows you to isolate anomalies and compare periods.

---

## Drill Down into Specific Categories

Selecting a data point on the chart shows detail including:
- Message IDs
- Sender IP / domain
- Triggered policies
- Actions taken (Blocked, Quarantine, ZAP)
- Impacted users

Useful for identifying campaigns and configuration failures.

---

## Review Email Security Reports

From **Email & collaboration reports**:

### Mail Latency Report
- Aggregated view of delivery and detonation latency.

### Post-delivery Activities Report
- Messages deleted after delivery via ZAP.

### Threat Protection Status Report
- Unified view of detected and blocked threats.

### Top Senders and Recipients Report
- Top senders and recipients.

### URL Protection Report
- Safe Links trends and actions.

---

## Other Reports via PowerShell

- **Top senders / recipients**: [Get-MailTrafficSummaryReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficsummaryreport?view=exchange-ps)
- **Top malware**: [Get-MailTrafficSummaryReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficsummaryreport?view=exchange-ps)
- **Threat protection status**: [Get-MailTrafficATPReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficatpreport?view=exchange-ps)
- **Threat protection status**: [Get-MailDetailATPReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-maildetailatpreport?view=exchange-ps)
- **Safe Links**: [Get-SafeLinksAggregateReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinksaggregatereport?view=exchange-ps)
- **Safe Links**: [Get-SafeLinksDetailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinksdetailreport?view=exchange-ps)
- **Compromised users**: [Get-CompromisedUserAggregateReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-compromiseduseraggregatereport?view=exchange-ps)
- **Compromised users**: [Get-CompromisedUserDetailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-compromiseduserdetailreport?view=exchange-ps)
- **Mail flow status**: [Get-MailflowStatusReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailflowstatusreport?view=exchange-ps)
- **Spoofed users**: [Get-SpoofMailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-spoofmailreport?view=exchange-ps)
- **Post-delivery activity**: [Get-AggregateZapReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-aggregatezapreport?view=exchange-ps)
- **Post-delivery activity**: [Get-DetailZapReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-detailzapreport?view=exchange-ps)

Reference: [*View Defender for Office 365 reports in the Microsoft Defender portal*](https://learn.microsoft.com/en-us/defender-office-365/reports-defender-for-office-365)

---

## Export Data for Analysis

Reports allow you to:
- Export to CSV
- Export charts as images
- Open in Advanced Hunting (KQL)

Common uses:
- Weekly SOC reviews
- KPIs
- Executive summaries
- Trend baselines

---

# Identify Users Most Targeted by Malware and Phishing

## Threat Protection Status Report

1. Go to: https://security.microsoft.com/emailandcollabreport
2. Select **Threat Protection Status Report**

Shows:
- Detected malware
- Phishing attempts
- Spoofing / impersonation
- Blocked or quarantined messages
- ZAP actions

---

## Filter by Threat Type

### Malware
- Threat Type → Malware
- Review columns: Recipient, Detection Technology, and Action Taken

### Phishing
- Threat Type → Phishing
- Review spoofing, impersonation, and actions

---

## Identify Top Targets

1. Go to **Top targeted recipients**
2. Sort by number of detections
3. Export results if needed

---

## Correlation with Other Reports

- **Compromised Users Report**
- **Top Malware Report**
- **Spoof / Impersonation Reports**

---

## Recommended SOC Analysis

For each user:
- Validate sensitive role
- Review clicks, reports, and authentication failures
- Verify protection policies and MFA
- Review correlated incidents

---

## Derived Actions (Quick Runbook)

- Notify the user
- Targeted anti-phishing training
- Review suspicious rules
- Harden policies
- Investigate domains and URLs

---

# Review Malware and Phishing Campaigns

## Access to Campaigns

1. Go to: https://security.microsoft.com/threatexplorerv3
2. Select **Campaigns** (Plan 2)

---

## Campaign Analysis

Microsoft groups campaigns based on:
- Attack source
- Message content
- Relationship between recipients
- Malicious payloads

---

## Top Malware Campaigns

- Filter by Threat Type: Malware
- Sort by impact
- Review attachments, families, origin, and automated actions

---

## Top Phishing Campaigns

- Filter by Phishing
- Analyze narrative, payload, and target users

---

## Detailed Campaign View

Includes:
- Attack source
- Payload
- Recipients
- Timeline

---

## SOC Actions from Campaigns

- Correlate incidents
- Prioritize response
- Harden defensive posture
- Review subsequent movements
---

# Validate delivered emails with threats

## Access Advanced Hunting
1. Go to https://security.microsoft.com/v2/advanced-hunting

### Adjust Filters to Analyze Trends

Use the top filter bar:
- **Time range**: 15 days, 30 days, 90 days (for weekly tasks, at least 15 days is recommended)
---

## Identify delivered emails with threat detection
**Objective:** confirm emails that **were NOT blocked** and reached the user's mailbox.

### Base query (essential)
```kql
EmailEvents
| where DeliveryAction == "Delivered"
| where ThreatTypes != ""
| project
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    ConfidenceLevel,
    DeliveryLocation
| order by Timestamp desc
```

### 🔍 What this query validates
- ✅ The email **was delivered**
- ✅ Defender detected **some type of threat**
- ✅ You can see **what type** and **how it was detected**

---

## Validate delivered threat type
To understand what escaped, filter by type:

### Malware
```kql
| where ThreatTypes has "Malware"
```

### Phishing
```kql
| where ThreatTypes has "Phish"
```

### High-risk spam
```kql
| where ThreatTypes has "Spam"
```

---

## Confirm if it was Safe Attachments or Safe Links

### Malicious attachments delivered
```kql
EmailAttachmentInfo
| where MalwareFilterVerdict != "Clean"
| project
    Timestamp,
    NetworkMessageId,
    FileName,
    MalwareFilterVerdict,
    DetectionMethods
```

### Malicious links delivered
```kql
EmailUrlInfo
| where UrlThreatType != "None"
| project
    Timestamp,
    NetworkMessageId,
    Url,
    UrlThreatType,
    DetectionMethods
```

  > Internal Tools 2026
