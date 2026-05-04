# Daily Operational Security Guide: Microsoft Defender for Office 365 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes the daily procedures for analyzing trends, identifying high-risk users, and managing threat campaigns in Microsoft Defender for Office 365 (MDO).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Alert Monitoring](#alert-monitoring)
- [Incident Monitoring](#incident-monitoring)
- [Validate delivered emails with some type of threat](#validate-delivered-emails-with-some-type-of-threat)
- [Triage of Teams Messages Reported by Users](#triage-of-teams-messages-reported-by-users)
- [Review and act on AIRs (Automated Investigation and Response)](#review-and-act-on-airs-automated-investigation-and-response)
- [Review Email Detection Trends in Microsoft Defender for Office 365](#review-email-detection-trends-in-microsoft-defender-for-office-365)
- [Review Phishing and Malware Campaigns That Resulted in Delivered Emails](#review-phishing-and-malware-campaigns-that-resulted-in-delivered-emails)
- [Top Targeted Users Review](#top-targeted-users-review)

---
# Alert Monitoring

## Review active alerts

Go to the portal [Alerts - Microsoft Defender](https://security.microsoft.com/alerts)
Select an alert to open the details panel, where you can review:
* Alert severity
* Detection source
* Impacted users or assets
* Recommended actions

Use the **Filter** option to filter alerts by severity, service, or status.

## Investigate alerts

From the alert details, select **View full details**.
Review:
* **Alert Storyline** (timeline of related events)
* Email or file involved
* Status of the automated investigation (if enabled)

Select **Investigate** to initiate an automatic or manual investigation.

> Automated investigations are part of the Microsoft Defender threat protection flow (a general capability of the Defender ecosystem).

---

# Incident Monitoring

Go to the portal **[Incidents - Microsoft Defender](https://security.microsoft.com/incidents)**
In the Incidents panel, configure the following filters:
* **Period:** 1 Day
* **Status:** New and In progress
* **Alert severity:** Sort descending (High → Medium → Low)
* **Bookmark priority:** 15-100
* **Workspaces:** Any

Save the custom view for future use

Review key columns:
* **Severity**
* **Status**
* **Assigned to**
* **Tags**

---

# Validate delivered emails with some type of threat

## 1. Portal access
- Go to: https://security.microsoft.com/v2/advanced-hunting
- Sign in with a user that has at least **Security Reader** permission


## 2. Execute KQL query
Paste the following query in the **Query** panel:

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

## 3. Run the query
- Click **Run query**.

## 4. Review the results
- Navigate to the **Results** tab to view the events found.

> Key to understand why emails with some type of threat are being delivered

## 5. User clicks on delivered emails with some type of threat
Paste the following query in the **Query** panel:

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
## 6. Review the results
- Navigate to the **Results** tab to view the events found.
- Column: ActionType == "ClickAllowed"

> Key to identify potentially compromised users

## 7. User opened an attachment from delivered emails with some type of threat (MDE Deployed)
> **Essential requirement**
>
> This query **ONLY works** if your tenant has:
>
> - **Microsoft Defender for Endpoint (MDE)** enabled
>
> - **Onboarded** devices
>
> - Access to **Device*** tables in Advanced Hunting
>
> If DeviceFileEvents **does not exist, it is NOT possible** to detect attachment opens (this is a real limitation of Defender).


Paste the following query in the **Query** panel:

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

## 8. Review the results
- Navigate to the **Results** tab to view the events found.
- Column: FileOpenTimestamp Impact confirmation

> Key to identify potentially compromised users

---

# Triage of Teams Messages Reported by Users

## Verify that reporting is enabled

1. Go to **[Messaging policies - Microsoft Teams admin center](https://security.microsoft.com/incidents)**
2. Open the **Global (Org‑wide default)** policy.
3. Confirm that **Report inappropriate content** and **Report a security concern** are enabled.
4. Go to **[Email & collaboration - Microsoft Defender](https://security.microsoft.com/securitysettings/userSubmission)**
5. Scroll to the **Microsoft Teams** section.
6. Verify that **Monitor reported messages in Microsoft Teams** is selected.

> **Note:** These settings must be enabled in both Teams Admin Center and the Defender portal for the triage process to work correctly.

## Locate Teams messages reported by users

### Option A: From the Submissions page

1. Go to: [https://security.microsoft.com/reportsubmission?viewid=user](https://security.microsoft.com/reportsubmission?viewid=user)
2. Select the **User reported** tab.
3. Filter by **Teams messages** to view the reported content.

### Option B: From the Defender XDR incidents queue

1. Go to the portal **[Incidents - Microsoft Defender](https://security.microsoft.com/incidents)**
2. Search for alerts with the names:
    * `Teams message reported by user as a security risk`
    * `Teams message reported by user as not a security risk`
3. Open the corresponding incident to begin triage.

## Review the reported message details

Within the incident or submission, select **View submission**.
Review:
* Sender
* Message content
* URLs
* Attachments
* Indicators of compromise (IoCs)
* Threat intelligence and Defender verdicts

Consult the Teams message entity panel for additional metadata.

## Execute Triage actions

### Classify and notify the reporting user

Administrators can classify the message as:
* Phishing
* Spam
* Malware
* Not malicious

And send a notification to the user who reported it.

### Submit the message to Microsoft for analysis

1. In the **User reported** tab, select the message.
2. Choose **Submit to Microsoft for analysis**.

> This is necessary because Teams messages cannot be submitted directly from the Teams messages tab; only user-reported messages are eligible.

### Add blocks as needed

From the **Tenant Allow/Block List**, you can block:
* Suspicious URLs
* Malicious domains
* Dangerous sender addresses

### Review and manage quarantined messages

If ZAP for Teams is enabled and the message was quarantined:
> Only administrators can manage these messages.

### Document and close the triage

1. Add notes to the incident in Defender XDR.
2. Resolve the incident with the corresponding classification (e.g.: true positive, false positive).
3. Confirm user notification (if configured).

---

# Review and act on AIRs (Automated Investigation and Response)

1. Go to **[Action center - Microsoft Defender](https://security.microsoft.com/action-center/pending)**
2. Review actions pending approval:
    * Soft delete email
    * Hard delete email
    * Block URL
    * Block sender
    * Turn off external mail forwarding
3. For each pending action:
    * Click on the action to view details and review:
        * **Investigation details:** Reason for the action
        * **Evidence:** Screenshots, detonation analysis, IOCs
        * **Affected items:** Number of impacted messages/users
4. Make a decision
    * **Approve:** If the evidence is conclusive
    * **Reject:** If it is a false positive
5. Check the "History" tab to confirm execution
6. Document approved/rejected actions for audit

---

# Review Email Detection Trends in Microsoft Defender for Office 365

## Mailflow Status Summary Report

This report provides visibility into:
* Allowed email (good)
* Malware detections
* Phishing detections
* Spam detections

1. Go to **[Threat protection status - Microsoft Defender](https://security.microsoft.com/reports/TPSAggregateReportATP)**
2. Review general trends by category:
    * Malware
    * Phishing
    * Spam
    * Good email
3. Scroll down to view detailed tables with volumes and filtering layers (anti-malware engine, Safe Attachments, Safe Links, anti-spam, ZAP, etc.).

## Open the Threat Protection Status Report

This report consolidates Defender detections across all protection layers.

1. In **Reports**, select **Threat protection status report**
2. Review indicators such as:
    * Threat types (malware, phishing, spam)
    * Detection technology (detonation, Safe Links, Safe Attachments, impersonation, DMARC/SPOOF filtering)
3. Select any row to open the detail panel (flyout).
4. Apply filters such as:
    * Inbound
    * Outbound
    * Date range
    * Email direction

For more specific analysis.

## Compare Trends Over Time

The goal is to identify:
* Increases in phishing or malware
* Sudden spam spikes
* Decrease in detection effectiveness
* Changes in attack patterns or techniques

> These reports are designed to show long-term patterns, not just daily events.

## Export or Schedule Reports (Recommended)

This optimizes governance and continuous visibility.

From any of the reports, use the options:
* **Create schedule** to generate automatic weekly deliveries
* **Request report** for a one-time full export
* **Export** to download in CSV/Excel for offline analysis

> Microsoft recommends scheduling TPS reports to maintain consistent oversight.

## Dive Deeper into Specific Threats (Optional)

If you observe anomalies or suspicious increases:

1. Open **Threat Explorer (Plan 2)**: https://security.microsoft.com/threatexplorerv3
2. Or use **Real‑Time Detections (Plan 1)**: https://security.microsoft.com/realtimereportsv3
3. Filter by category (Malware, Phish, Campaigns).
4. Investigate senders, URLs, detonation results, and affected users.

## Adjust Security Policies Based on Findings

With the identified patterns, you may need to modify:
* Anti-phishing policies
* Anti-malware policies
* Safe Attachments / Safe Links configurations
* Tenant Allow/Block List
* Transport rules

> The weekly review is designed to determine whether these adjustments are necessary.

---

# Review Phishing and Malware Campaigns That Resulted in Delivered Emails

## Step 1: Filter by Delivered Emails

1. Go to **Explorer - Microsoft Defender**: https://security.microsoft.com/threatexplorerv3
2. Apply the following filters:
    * **Delivery action:** Delivered
    * **Campaign Type:** Phish & Malware, or All Threat Types
    * **Time range:** Select the relevant period (default: 7 days)
3. Select **Refresh** to update the view.

## Step 2: Identify High-Risk Campaigns

Sort campaigns by:
* Number of impacted users
* Threat type severity
* Phishing confidence level
* Malware family or indicators associated with threat actors
* Ratio between delivered and blocked messages

Prioritize campaigns with:
* High number of delivered emails
* High threat severity
* Multiple recipients who are priority accounts
* Multiple associated URLs or domains

## Step 3: Open a Campaign Summary

1. Select a campaign from the list.
2. Review the campaign summary panel:
    * Threat type (Phishing / Malware)
    * Impacted users
    * Total messages sent and delivered
    * Detections across MDO filters (ZAP, Safe Links, Safe Attachments)
    * Campaign timeline

> This provides an overview of the attack pattern.

## Step 4: Review "Impacted Users"

1. Go to the **Impacted assets / mailboxes** section.
2. Identify:
    * High-risk users who were repeatedly targeted
    * Priority accounts (executives, finance, administrators)
    * Lateral attack patterns
3. Can be exported with: **Export → CSV**

## Step 5: Analyze Email Samples

Within the same campaign:

1. Open any delivered email and review:
    * Header information
    * Sender domain and SPF/DKIM/DMARC validation
    * URL reputation (Malicious, Suspicious, Unknown)
    * Attachment behavior
    * Authentication failures
    * Email path (how it was routed and delivered)

> This reveals why the message evaded protections.

## Step 6: Review ZAP (Zero‑Hour Auto Purge) Actions

Verify if:
* ZAP removed the email after delivery
* ZAP failed to remove it
* A policy prevented the ZAP action

> This helps validate whether post-delivery remediation worked.

## Step 7: Identify Configuration Gaps

In the campaign summary, review:
* Policies that did not trigger
* Safe Links/Safe Attachments that were evaded
* User overrides
* Tenant Allow/Block List entries

> This determines why the campaign succeeded.

## Step 8: Execute Response Actions

From the campaign details, actions available include:
* Purge emails from all impacted mailboxes
* Block sender or domain
* Block URL from MDO or Microsoft Defender XDR
* Block file hash / detonate in sandbox
* Submit sample for analysis (false positive / false negative)
* Create or harden anti-phishing or anti-malware policies

## Step 9: Document and Track the Threat

For SOC and compliance records:

1. Export campaign details (CSV, Excel)
2. Record:
    * Campaign ID
    * Impacted users
    * Threat vectors (URLs, IPs, attachment types)
    * Identified security gaps
    * Actions taken

> Optional: Send findings to Microsoft Sentinel for additional correlation.

## Step 10: Execute User Remediation

Depending on the impact:
* Notify affected users
* Reset compromised credentials via Entra ID
* Trigger an Automated Investigation and Response (AIR)
* Educate users if they interacted with malicious content

## Step 11: Strengthen Preventive Controls

Based on findings:
* Review anti-phishing policies
* Enable advanced phishing protection levels
* Update Safe Links / Safe Attachments
* Remove risky Allow List entries
* Enable MFA and phishing-resistant credentials

---

# Top Targeted Users Review

----------------------------------------------------------------------
1. Go to https://security.microsoft.com/threatexplorer
2. Select **Phishing** or **All email** Tab
3. Configure filters as follows:
    * **Period:** Last 24 hours
    * **Select:** `Recipient domain -> Equal any of -> domain.com`
4. In the bottom section of Explorer select **Top targeted users**
5. Click on the user to view details and review:
    * Threat types received
    * Delivery vs. block rate
    * Whether they clicked on malicious links
6. Preventive actions:
    * If the user is VIP/Executive:
        * Add to "Priority Accounts"
    * If there are signs of compromise:
        * Force password change
        * Review activity in Azure AD Sign-ins
        * Verify mailbox rules (forwarding rules)

Document critical users for continuous monitoring
