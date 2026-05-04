# Monthly/Ad-Hoc Operational Security Guide: Microsoft Defender for Office 365 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes the monthly/ad-hoc procedures for analyzing trends, identifying high-risk users, and managing threat campaigns in Microsoft Defender for Office 365 (MDO).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Access to Hunting Tools](#access-to-hunting-tools)
- [Spoofing and Impersonation Management](#spoofing-and-impersonation-management)
- [Delete Suspicious Emails in Exchange Online (Ad-Hoc)](#delete-suspicious-emails-in-exchange-online-ad-hoc)
- [Historical Direct Send Detection (Ad-Hoc)](#historical-direct-send-detection-ad-hoc)
- [Review Microsoft Defender for Office 365 Policies](#review-microsoft-defender-for-office-365-policies)

---

# Access to Hunting Tools

You will use two main portals for investigation:

### A. Threat Explorer
*   **URL:** [security.microsoft.com/threatexplorer](https://security.microsoft.com/threatexplorer)
*   **Use:** Visualize real-time detections, malicious emails, post-delivery activities, and threat patterns.

### B. Advanced Hunting
*   **URL:** [security.microsoft.com/v2/advanced-hunting](https://security.microsoft.com/v2/advanced-hunting)
*   **Use:** Query-based hunting environment using **KQL (Kusto Query Language)** for deep analysis.

---

## Perform Manual Threat Hunting

### Search for Indicators of Compromise (IoCs)
In **Threat Explorer** you can:
*   Filter emails or artifacts by sender, file, URL, malware family, campaigns, or delivery time.
*   Adjust the date range (up to 30 days) to identify patterns.

### Use Advanced Hunting Queries
In **Advanced Hunting**, execute KQL queries to identify:
*   Anomalous email flows.
*   Suspicious URLs or attachments.
*   User compromise behaviors.
*   Deviations in historical trends.

---

## Use Threat Trackers

Use **Threat Trackers** to monitor:
*   Emerging malware campaigns.
*   Zero-day exploits.
*   Industry-specific threats.

> **Tip:** This helps guide hunting and properly prioritize SOC efforts.

---

## Share and Reuse Queries

To improve security team efficiency:
*   Share frequently used KQL queries.
*   Build a team hunting library.
*   Use the **Shared Queries** feature within Advanced Hunting.

---

## Create Custom Detection Rules

Convert your manual hunting findings into automated alerts.

1.  **Navigate to Custom Detections:** [security.microsoft.com/custom_detection](https://security.microsoft.com/custom_detection)
2.  **Build a Rule:**
    *   Paste your validated Advanced Hunting query.
    *   Define the alert logic (frequency, threshold, affected entities).
    *   Assign automatic actions (e.g., isolate device, suspend user, delete email).

---

## Review and Remediation with AIR

If hunting reveals suspicious activity:
*   Trigger **Automated Investigation and Response (AIR)** alerts.
*   AIR evaluates the evidence, expands the investigation scope, and suggests remediation actions.

---

# Spoofing and Impersonation Management

Procedures for reviewing and adjusting spoofing intelligence policies.

## 1. Review Spoofing Detections (Spoof Intelligence Insight)

Microsoft 365 automatically detects senders that appear to be from your organization or external domains but fail SPF/DKIM/DMARC validations.

### Review Steps:
1.  **Open Insight:** Go to [Spoof Intelligence Insight](https://security.microsoft.com/spoofintelligence) and review the last 7 days.
2.  **Analyze each sender:**
    *   **Legitimate:** Internal apps, authorized vendors, mailing lists.
    *   **Malicious:** Unknown domains, authentication failures without justification.
3.  **Decision (Action):**
    *   ✅ **Allow:** If legitimate (avoids false positives).
    *   🚫 **Block:** If malicious or suspicious.
4.  **Document:** Record date, sender, reason, and expected impact.

> **Note:** Actions are reflected in the *Tenant Allow/Block List*.

## 2. Analyze Impersonation Insight

### Review Steps:
1.  **Open Insight:** Go to [Impersonation Insight](https://security.microsoft.com/impersonationinsight).
2.  **Domain Impersonation:**
    *   Look for subtle domain changes (typosquatting).
    *   Review volume and target users.
3.  **User Impersonation:**
    *   Evaluate differences in aliases vs. real names.
    *   Identify high-value targets (VIPs: Executives, Finance, HR).
4.  **Validate Policies:**
    *   Ensure affected domains and users are covered by Anti-Phishing policies.

## 3. Recommended Actions

### For Spoofing
*   **Allow** if it is a legitimate sender.
*   **Block** if there is risk (BEC, compromised accounts).
*   **Remediation:** Strengthen DNS records (SPF/DKIM/DMARC) for the affected domain.

### For Impersonation
*   **Adjust Anti-Phishing Policy:**
    *   Add trusted domains.
    *   Add protected users (VIPs).
    *   Adjust the phishing threshold.
*   **Additional Hunting:** Search for domain variations and anomalous activity on targeted users.
---

# Delete Suspicious Emails in Exchange Online (Ad-Hoc)

## Option A (RECOMMENDED): Microsoft 365 Defender Portal

### Prerequisites
- Role: Security Administrator / Compliance Administrator / Global Administrator

### Steps
1. https://security.microsoft.com/threatexplorerv3
2. Define date range
3. Search by Subject, Sender, IP, Message ID, URL, Hash
4. Validate results
5. **Take action** → Move or delete
6. Soft Delete (recommended) or Hard Delete
7. Monitor:
   - https://security.microsoft.com/action-center/history

### Post-action prevention
- Block sender
- Block URLs
- Adjust policies
- Verify SPF / DKIM / DMARC

---

## Option B: PowerShell (Compliance Search)
### Useful for advanced IR, scripting, or automation

### Connect
```
Connect-IPPSSession
```

### Create search
```
New-ComplianceSearch  -Name "Purge-Phishing-25022026"  -ExchangeLocation All  -ContentMatchQuery 'Subject:"Factura pendiente"'
```

### Execute
```
Start-ComplianceSearch -Identity "Purge-Phishing-25022026"
```

### Purge
**Soft Delete**
```
New-ComplianceSearchAction  -SearchName "Purge-Phishing-25022026"  -Purge -PurgeType SoftDelete
```

**Hard Delete (critical cases)**
```
New-ComplianceSearchAction  -SearchName "Purge-Phishing-25022026"  -Purge -PurgeType HardDelete
```

---

## Key Best Practices
- Use SoftDelete first
- Validate results
- Document criteria, date, and impact
- Combine with blocks and DMARC enforcement
- Do not purge without validation
- HardDelete only with IR/Legal approval

---


# Historical Direct Send Detection (Ad-Hoc)

## 1. Anonymous internal emails (Direct Send indicator)

```kql
EmailEvents
| where SenderFromDomain == RecipientEmailDomain
| where isempty(ConnectorId)
| where isempty(AuthenticationDetails)
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, SenderIPv4, Subject
```

## 2. Attempts blocked by RejectDirectSend

```kql
EmailEvents
| where ActionType == "Reject"
| where ErrorCode has "5.7.68"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, SenderIPv4, ErrorCode
```

## 3. Top IPs attempting Direct Send

```kql
EmailEvents
| where SenderFromDomain == RecipientEmailDomain
| where isempty(ConnectorId)
| summarize Attempts=count() by SenderIPv4
| order by Attempts desc
```

---
# Review Microsoft Defender for Office 365 Policies

## Option 1, run the validation script: [MDO/Scripts/Validate-MDOPolicies.ps1](https://github.com/watchdogcode/gol2026/blob/main/MDO/Scripts/Validate-MDOPolicies.ps1)

## Option 2, step by step:

### 1. Access the correct Microsoft Defender for Office 365 (MDO) portal

1. Open the Microsoft Defender portal:
   - https://security.microsoft.com

2. Navigate to the following path:
   - **Email & collaboration**
   - **Policies & rules**
   - **Threat policies**
   - **Safe Attachments**

👉 **Direct link:**
- https://security.microsoft.com/safeattachmentv2

---

## 2. Identify all existing Safe Attachments policies

In the main **Safe Attachments** view, review the following fields:

- **Name**: Policy name
- **Status**: On / Off
- **Priority**: Application order

### Available actions:
- Search policies by name
- Export the policy list to CSV
- Open the **Threat protection status report**

---

## 3. Distinguish policy types (critical for the review)

Validate what types of policies exist in the tenant:

### Policy types:
1. **Preset Security Policies**
   - Strict Preset Security Policy
   - Standard Preset Security Policy

2. **Built‑in protection (Microsoft)**

3. **Custom Safe Attachments policies**

⚠️ **Important:**
- **Preset** and **Built-in** policies **cannot be edited directly** from Safe Attachments.
- **Only Custom policies** can be modified from this section.

Reference:
- Microsoft Learn – Set up Safe Attachments policies

---

## 4. Review the detail of a specific policy

1. Click on the **policy name** (not the checkbox).
2. The **details flyout panel** will open.

Carefully review the following sections:

---

### a) Scope (Users and domains)

Verify who the policy applies to:

- Users
- Groups
- Domains
- Exclusions (**exceptions**)

✅ Key validations:
- Whether the policy applies to **all users**
- Whether there are **critical exceptions** (e.g.: executives, unlicensed accounts, technical accounts)

---

### b) Protection configuration (Settings)

Explicitly validate the following parameters:

- **Safe Attachments unknown malware response**
  - Off
  - Monitor
  - Block *(default and recommended value in Standard / Strict)*

- **Dynamic Delivery**

- **Quarantine policy**
  - Default value: `AdminOnlyAccessPolicy`

- **Redirect messages**
  - Only available if the policy is in **Monitor**

---

## 5. Verify the precedence order (Priority)

Review the exact application order of the policies:

1. **Strict Preset Security Policy** (if enabled)
2. **Standard Preset Security Policy**
3. **Custom policies**
   - *Priority 0 = highest priority*
4. **Built‑in protection (Microsoft)**
   - *Lowest priority, not modifiable*

⚠️ **Critical note:**
- Safe Attachments **stops at the first policy that applies to the recipient**.

---

## 6. Confirm enablement status

### For Custom policies:
- Verify that the **Status** is **On**
- From the details panel:
  - **Turn on / Turn off**
- From the list view:
  - **More actions > Enable / Disable selected policies**

### For Preset policies:
- Managed exclusively from:
  - https://security.microsoft.com/presetSecurityPolicies

    > Internal Tools 2026
