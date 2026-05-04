# Priority Account Protection in Microsoft 365 Defender 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## 1. Priority Account Protection 

It is a classification mechanism for high-value identities (High Value Targets – HVT) within Microsoft 365 Defender.

It is not just a "visual label" — when marking a user as a Priority account, the detection engine modifies the risk model, increases detection sensitivity, and automatically elevates the severity of alerts and incidents related to email, identity, and collaboration.

The goal is to reduce dwell time and the impact of targeted attacks (phishing, BEC, account takeover) against users critical to the business.

All organizations have high-value accounts, such as executives and senior management who, due to their access to sensitive or high-priority information, have a higher attack rate. Some of these accounts may be highly visible (for example, listed on a public website) and therefore easier for an attacker to research and target using increasingly sophisticated techniques. 

Applying a "Priority account" label to these accounts will allow Defender for Office 365 to scan emails sent to these accounts with additional heuristics that are specifically designed for company executives to detect these threats, while minimizing false positives.

Applying a user tag such as "Priority account" also allows security teams to prioritize their focus when dealing with investigations and alerts.

---

## 2. Recommended Best Practice

- Organizations should NOT treat all identities equally
- Attackers prioritize executives and roles with decision-making power

The recommended control is:

- Identify HVT
- Explicitly classify them
- Apply differentiated detection logic

Microsoft implements this practice through:

- Priority Account Protection
- Integration with:
  - Defender for Office 365
  - Microsoft 365 Defender Incidents
  - Identity, Email, and Collaboration signals

> This control supports:
>
> - Zero Trust → Assume Breach
> - NIST SP 800‑53 → IA‑2, IR‑4, IR‑5
> - MITRE ATT&CK → TA0001 (Initial Access), TA0006 (Credential Access)

## 3. Complete Step-by-Step Implementation (with technical depth)

### Phase 1 – Enable the feature at the organization level
**Path:**
Microsoft 365 Defender → Settings → Email & collaboration → Priority account protection

**What happens internally:**

- An organizational flag is enabled
- Defender begins evaluating userTags in the detection pipeline

Without this flag:

- The tags exist
- But they do NOT affect detections or severity

This step is mandatory and frequently forgotten

### Phase 2 – Formally define what a Priority Account is
**Real (not theoretical) best practices:**

| Category | Example | Reason |
|---------|--------|--------|
| Executives | CEO, CFO, CIO | Classic BEC target |
| Management | Managers, Heads | Operational authority |
| Finance | AP, AR, Payroll | Payment capability |
| Legal / HR | Legal Counsel, HR BP | Sensitive data |
| Assistants | Executive Assistants | Bridge to executives |

Do not confuse with privileged accounts

A Priority Account:

- May not be an admin
- But its compromise impact is high

### Phase 3 – Assign the "Priority account" tag

**Option A – Microsoft 365 Defender Portal**
Settings → Email & collaboration → User tags

https://security.microsoft.com/securitysettings/userTags

**Option B – Microsoft 365 Admin Center**
Users → Active users → Manage priority accounts

https://admin.microsoft.com/Adminportal/#/priorityaccounts

**What happens technically:**

- The user receives an internal logical tag
- That tag is consumed by:
  - Anti‑Phishing engine
  - Incident correlation engine
  - Alert prioritization logic

**Note: It is not an attribute visible in Entra ID or standard Graph**

### Phase 4 – What actually changes when a user is a Priority Account

#### 1 More sensitive detections

- **Targeted phishing:**
  - Lower threshold to generate an alert
- **BEC:**
  - Greater weight on sender/content anomalies
- **Spoofing:**
  - Increases risk score

#### 2 Automatic severity elevation

Example:

- Normal user → Alert = Medium
- Priority Account → Alert = High

This affects:

- Alerts
- Incidents
- Automated playbooks

#### 3 Preferential correlation in Incidents

- Defender correlates Priority Account events first
- Reduces the risk that an attack goes unnoticed among noise

#### 4️ SOC Visibility

- Highlighted incidents
- Higher probability of:
  - Auto‑investigation
  - Auto‑remediation
  - Automatic escalation

## 4. Script, Query, and Automation Examples

**Important note:** Microsoft does not yet expose the Priority Account tag via Graph, so monitoring is indirect, via incidents and signals.

### a) PowerShell – List users with Priority Account

```powershell
# Requires Microsoft Graph
Connect-MgGraph -Scopes User.Read.All

Get-MgUser -All |
Where-Object {
    $_.SecurityIdentifier -ne $null
} |
Select DisplayName, UserPrincipalName, UserType
```

**Note:** The Priority Account tag is not yet visible via standard Graph; it is validated via the portal and Defender signals.


### b) KQL – Incidents involving Priority Accounts
```kql
SecurityIncident
| where Entities has "Priority"
| project TimeGenerated, IncidentNumber, Title, Severity, Status, Classification
```

Usage:

- SOC Dashboard
- SOA Evidence
- HVT Tracking

### C) KQL – Phishing targeted at executives
```kql
EmailEvents
| where ThreatTypes has "Phish"
| where RecipientEmailAddress in (
    "ceo@contoso.com",
    "cfo@contoso.com"
)
| project TimeGenerated, SenderFromAddress, Subject, ThreatTypes
```

### d) KQL – Detect alerts related to Priority Accounts

```kql
SecurityIncident
| where Title has_any ("Phish", "BEC", "Email", "Compromise")
| where Entities has "Priority"
| project TimeGenerated, Title, Severity, Status, IncidentNumber
```



### e) KQL – High-risk sign‑ins for Priority Accounts
```kql
SigninLogs
| where UserPrincipalName in (
    "ceo@contoso.com",
    "cfo@contoso.com"
)
| where RiskLevelDuringSignIn in ("medium","high")
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn
```

### f) Automated alert example (Sentinel)

**Name:** Priority Account – High Risk Activity

**Condition:**

- HVT User
- Medium/High Risk
- Phishing or anomalous sign‑in

**Actions:**

- Create incident
- Notify SOC
- Force password reset
- Require MFA
- Block session (Conditional Access)

**Useful for:**

- SOC Dashboards
- SOA Audits
- Control evidence


## 5. Critical Notes and Warnings

- Does not replace MFA or Conditional Access
- Does not protect service accounts
- Do not over‑tag (SOC fatigue)
- Review list every quarter
- Document HVT criteria (audit)

**Common mistakes:**

- Thinking it is only "visual"
- Not enabling the feature
- Not correlating it with SOC processes

## 6. Official References

- https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/introducing-differentiated-protection-for-priority-accounts-in-microsoft-defende/3283838
- https://learn.microsoft.com/microsoft-365/security/defender/priority-account-protection
- https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies
- https://learn.microsoft.com/microsoft-365/security/defender/incidents-overview
- https://learn.microsoft.com/security/zero-trust/
- https://learn.microsoft.com/en-us/defender-office-365/priority-accounts-turn-on-priority-account-protection?view=o365-worldwide

---
