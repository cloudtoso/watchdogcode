# Daily Operational Security Guide: Microsoft EntraID 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

Effective operation of Microsoft Entra ID requires continuous monitoring, change control, and periodic privilege review to reduce identity risks and ensure business continuity.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Monitor sign-in and authentication events](#monitor-sign-in-and-authentication-events)
- [Review of Risky Users (High / Medium)](#review-of-risky-users-high--medium)
- [Review of Risky Sign-ins](#review-of-risky-sign-ins)
- [Review Microsoft Entra Connect Health alerts (hybrid environments)](#review-microsoft-entra-connect-health-alerts-hybrid-environments)
- [Validate hybrid component status](#validate-hybrid-component-status)

---

### Monitor sign-in and authentication events

**Objective**  
Detect anomalous access or failures that may impact business continuity.

**Operational steps**
1. Go to https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView and sign in
2. Identify:
   - Spikes in authentication failures.
   - Sign-ins from unusual locations.
   - Changes in MFA patterns.
3. Correlate findings with **Identity Protection** alerts (if applicable).

**Impact of not doing this**  
- Unauthorized access.
- Identity fraud.
- Security control bypass.

---

### Review of Risky Users (High / Medium)

**Step 1 – Access**
Microsoft Entra Portal  
`Protection > Identity Protection`

**Step 2 – Risky Users**
Direct URL: https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers

**Step 3 – Recommended filters**
- Risk level: **High, Medium**
- Risk state: **Active**
- (Optional) Risk type, location, date

**Step 4 – Per-user analysis**
Review:
- Current risk level
- Risk type:
  - Password Spray
  - Anonymous IP
  - Impossible Travel
  - Leaked Credentials
- Last risky activity
- State: Active / Remediated / Dismissed

**Step 5 – Operational actions**
- Force password change
- Require MFA
- Confirm activity with the user
- Mark as **Remediated** if mitigated

---

### Review of Risky Sign-ins

**Step 1 – Risky Sign-ins**
Direct URL: https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns


**Step 2 – Filters**
- Risk level: **High, Medium**
- State: Active
- Application, IP, Location

**Step 3 – Event analysis**
Review:
- Affected user
- Target application
- IP address / Country
- Risk type
- Result: Success / Failure / Interrupted

---
### Review Microsoft Entra Connect Health alerts (hybrid environments)

**Objective**  
Ensure a healthy synchronization between **on-premises Active Directory** and **Microsoft Entra ID**.

**Operational steps**
- Go to https://entra.microsoft.com and sign in
- In the left menu, select: Identity → Hybrid management
- Click on: Microsoft Entra Connect Health
- Or go to https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Health/ConnectHealthMenuBlade/~/overview

**Review the overall service status**
1. In the Overview, validate:
   - Overall status (Healthy / Warning / Critical).
   - Registered components (Sync, AD FS, PTA, etc.).   
2. If the status is not Healthy, continue with detailed analysis.


**Verify synchronization alerts (Sync errors)**
1. Select the service: **Azure AD Connect Sync**
2. Review the **Alerts** section
3. Identify alerts related to:
   - Object synchronization errors.
   - Export / Import errors. 
   - Connector space issues

**Immediate action:**

- Open each alert and review:
    - Start time
    - Number of affected objects
    - Severity


**Validate synchronization latency**
1. Within Azure AD Connect Sync, review:
   - Last successful synchronization
   - Time since last synchronization

2. Confirm that:
   - Synchronization occurs within the expected interval (e.g., < 30 min).

**Warning signal:**
   - Synchronizations delayed or stopped for several hours


**Review agent failures (Agents health)**

1. Return to Entra Connect Health.
2. Review the status of:
   - Entra Connect Sync Agent
   - Pass-Through Authentication Agents (if applicable)
   - AD FS / other hybrid agents

Confirm that:
   - All agents are Active
   - There are no disconnection or lost heartbeat alerts


**Confirm no persistent errors exist**

1. Review the age of alerts:
  - Identify alerts older than 24–48 hours

Verify if:
  - The error has already been mitigated
  - The error keeps reoccurring

Mark as **high priority:**
  - Repetitive errors
  - Errors impacting productive users

**Impact of not doing this**  
- Users without access.
- Identity inconsistencies.
- Increased support incidents.

---

### Validate hybrid component status

**Applies if the following components are used**
- Pass-Through Authentication Agents.
- Private Network Connectors.
- Password Writeback.
- MFA NPS Extension.

**Daily action**
- Confirm that all agents are **active**, **healthy**, and **reporting correctly**.

**Impact of not doing this**  
- Hybrid authentication failures.
- Interruptions in MFA or application access.
- Elevated operational and security risks.
