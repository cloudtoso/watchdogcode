# 🛡️ Daily Operational Security Guide: Microsoft Defender for Identity

## *Technology enables security, but discipline ensures its effectiveness.*

The daily MDI guide ensures that identity threats are detected and contained before they impact business operations.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Review ITDR Dashboard (Identities > Dashboard)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#review-itdr-dashboard-identities--dashboard)
- [Incident triage by priority (Incidents & alerts)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#incident-triage-by-priority-incidents--alerts)
- [Configure tuning for benign / false positives (Advanced hunting)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#configure-tuning-for-benign--false-positives-advanced-hunting)
- [Proactive hunting (daily or weekly, based on maturity)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#proactive-hunting-daily-or-weekly-based-on-maturity)
- [Review Health issues (Global and Sensor)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#review-health-issues-global-and-sensor)

Official guide:
https://learn.microsoft.com/en-us/defender-for-identity/ops-guide/ops-guide-daily

---

## Review ITDR Dashboard (Identities > Dashboard)

**Purpose:** Take the daily pulse of identity risk and prioritize work.

### Step by step

1. Go to https://security.microsoft.com/identities/dashboard and sign in.
2. Specifically review the recommended widgets:
   - Top insights
   - Identity related incidents
   - Entra ID users at risk
3. Document in your log / ITSM:
   - New insights or relevant changes vs. yesterday.
   - Identity incidents that require immediate attention.

### Output / Definition of Done (DoD)

- The "ITDR status of the day" and a brief priority list were recorded.

---

## Incident triage by priority (Incidents & alerts)

**Purpose:** Prioritize, classify, and route investigation with XDR correlation.

### Step by step

1. Open **Incidents & alerts**: https://security.microsoft.com/incidents
2. Apply recommended filters:
   - Status: New, In progress
   - Severity: High, Medium, Low
   - Service source: keep all for maximum correlation; optionally filter to Defender for Identity if focus is needed.
3. For each relevant incident:
   1. Open it and review all tabs + Activity log + Advanced hunting.
   2. In **Evidence and response**, open each piece of evidence (user / host / IP).
   3. For each piece of evidence use **… > Investigate** and choose *Activity log* or *Go hunt* as needed.
4. Classify the incident:
   - True positive
   - False positive
   - Informational / expected activity
5. If it is a **True positive**:
   - Specify *threat type*.
   - Assign to an analyst and change status to **In progress**.
6. If already remediated:
   - **Resolve** the incident to close related alerts and leave final classification.

### Output / DoD

- No *High* incidents remain unreviewed/unactioned; *In progress* incidents are assigned with next steps.

---

## Configure tuning for benign / false positives (Advanced hunting)

**Purpose:** Reduce noise and align alerts to risk appetite.

### Where (direct URL)

- Advanced hunting: https://security.microsoft.com/advanced-hunting

> Note: the official article indicates **Hunting > Advanced hunting**.

### Step by step

1. Go to **Hunting > Advanced hunting**.
2. Use incident/evidence data to define tuning conditions (by entity, behavior, origin, etc.).
3. Create or adjust the corresponding tuning rule to reduce unnecessary triage.
4. Document: objective, scope, owner, date, and reversion criteria.

### Concrete example (very realistic)

**Scenario**

Defender for Identity generates *Suspicious authentication attempts* alerts that always involve:

- Account: `svc_sqlbackup`
- Hosts: `DC01`, `DC02`
- Time: 02:00–03:00 AM
- Frequency: every day

You use **Advanced Hunting** to validate the pattern:

```kql
IdentityLogonEvents
| where AccountName == "svc_sqlbackup"
| summarize Count=count() by ActionType, DeviceName
```
[MDI KQL Queries](https://github.com/watchdogcode/gol2026/blob/main/MDI/KQL%20Query%20Package%20-%20MDI%20Advanced%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)

**Result**
- 100% expected events
- No indication of compromise

Confirmed: *Benign true positive*

---

## Proactive hunting (daily or weekly, based on maturity)

**Purpose:** Find early signals in raw/correlated data (last 30 days).

### Step by step

1. Open **Advanced hunting**: https://security.microsoft.com/v2/advanced-hunting
2. If you are a beginner, use *guided advanced hunting* (query builder).
3. Execute focused hunts, for example:
   - Users with anomalous activity
   - Suspicious lateral movements
   - Repetitive patterns in credentials / NTLM / Kerberos (based on existing detections)
4. Create *cases* (work items) with findings:
   - Indicator
   - Entity
   - Evidence
   - Suggested severity
   - Action

### Exit criteria

- At least 1–3 high-value hunts executed (based on capacity).
- Actionable findings recorded.

### KQL Example – Proactive Hunting

**Account authenticating on too many machines (possible lateral movement)**

- **What it detects:** users with successful logons on many devices within a 1-hour window.
- **Why it's useful:** common pattern of lateral movement or use of compromised credentials.

```kql
// Proactive hunt: a single account with successful logons on many devices in a short time
let Lookback = 1d;
let Window = 1h;
let MinDevices = 6;
DeviceLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType in ("LogonSuccess", "Logon", "LogonAttempted")
| summarize
    Devices = dcount(DeviceName),
    DeviceList = make_set(DeviceName, 25),
    TotalLogons = count(),
    SrcIPs = make_set(RemoteIP, 25)
  by AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc, TotalLogons desc
```

[MDI KQL Queries](https://github.com/watchdogcode/gol2026/blob/main/MDI/KQL%20Query%20Package%20-%20MDI%20Advanced%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)


---

## Review Health issues (Global and Sensor)

**Purpose:** Avoid coverage gaps due to sensor failures or connectivity issues.

### Step by step

1. Go to **Identities > Health issues**:
   https://security.microsoft.com/identities/health-issues
2. Review the tabs:
   - Global
   - Sensor (per DC / server)
3. For each issue:
   - Evaluate impact (does it affect collection or detection?).
   - Assign owner and open ticket if it depends on AD / Infrastructure.
4. Verify that email notifications exist for service issues (if applicable).

### Output / DoD

- No critical issues without an owner or plan; daily health status is recorded.