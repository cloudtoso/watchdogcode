# 🛡️ Weekly Operational Security Guide: Microsoft Defender for Identity

## *Technology enables security, but discipline ensures its effectiveness.*

The weekly MDI guide enables proactive identification and adjustment of emerging identity risks before they become critical business incidents.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Review Secure Score recommendations (by product)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#review-secure-score-recommendations-by-product)
- [Review and respond to emerging threats (custom detections)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#review-and-respond-to-emerging-threats-custom-detections)
- [Custom Detection Example: Password spraying / distributed brute force (early signal)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#custom-detection-example-password-spraying--distributed-brute-force-early-signal)

---

## Review Secure Score recommendations (by product)
**Purpose:** Improve identity and on-premises infrastructure posture.

### Step by step
1. Open Secure Score: https://security.microsoft.com/securescore
2. Go to **Recommended actions** and group by **Product**.
3. Prioritize actions related to **Defender for Identity / identities**.
4. For each priority action:
   - Define **owner** (SOC / Identity / AD).
   - Create task/plan with **target date**.

### Output / DoD
- Prioritized and assigned backlog; measurable weekly progress.

---

## Review and respond to emerging threats (custom detections)
**Purpose:** Create and operate custom detections based on Advanced Hunting.

### Step by step
1. Review **emerging risk topics** relevant to your organization (internal input).
2. In **Advanced Hunting**, create or adjust queries that cover those scenarios:
   https://security.microsoft.com/advanced-hunting
3. Configure **custom detection rules** based on those queries to generate alerts/actions.
4. Execute and validate that the rules work as expected and document adjustments.

### Output
- Active rules, documented and regularly validated.

---

## Custom Detection Example: Password spraying / distributed brute force (early signal)

### What it looks for
Detects accounts receiving multiple sign-in failures from **multiple IPs** in a short window, typical of:
- Password spraying
- Automated attempts with leaked credentials

Useful as an **emerging threat**, since these attacks tend to increase during active campaigns and after recent leaks.

### KQL (adjustable to your environment)
```kql
// Custom detection candidate: Password spraying against identities
let Lookback = 7d;
let Window = 30m;
let MinFailures = 25;
let MinSrcIPs = 8;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType has_any ("Fail", "LogonFailed", "InvalidPassword", "UserLoginFailed")
| summarize
    Failures = count(),
    SrcIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 25),
    Apps = make_set(Application, 15)
  by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Failures >= MinFailures and SrcIPs >= MinSrcIPs
| project Timestamp, AccountUpn, AccountName, AccountDomain, Failures, SrcIPs, IPList, Apps
| order by Failures desc, SrcIPs desc
```
[MDI KQL Query Package](https://github.com/watchdogcode/gol2026/blob/main/MDI/KQL%20Query%20Package%20-%20MDI%20Advanced%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)