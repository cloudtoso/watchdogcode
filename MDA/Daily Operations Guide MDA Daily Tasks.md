# Daily Operational Security Guide: Microsoft Defender for Cloud Apps 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes daily procedures to analyze trends, identify high-risk users, and manage threat campaigns in Microsoft Defender for Cloud Apps.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Objective
Establish clear operational routines for SOC analysts that enable:

- Detecting threats in **SaaS and OAuth applications**
- Governing applications and **Shadow IT**
- Maintaining **security posture (SSPM)**
- Ensuring **traceability and auditing**

---
## Table of Contents
- [Review Alerts and Incidents](#review-alerts-and-incidents)
- [Triage from Microsoft Defender XDR](#triage-from-microsoft-defender-xdr)
- [Review Threat Detection Data](#review-threat-detection-data)
- [Application Governance – OAuth Risk](#application-governance--oauth-risk)
- [App Governance – Overview](#app-governance--overview)
- [Review OAuth App Data](#review-oauth-app-data)
- [App Governance Policies](#app-governance-policies)
- [Conditional Access App Control](#conditional-access-app-control)
- [Shadow IT – Cloud Discovery](#shadow-it--cloud-discovery)
- [Cloud Discovery Dashboard](#cloud-discovery-dashboard)

---

## Review Alerts and Incidents

### Objective
Detect and prioritize active threats related to Cloud Apps.

### Procedure
1. Go to https://security.microsoft.com/alerts
2. Navigate to **Incidents & Alerts > Incidents**
3. Apply filters:
   - Status: `New`, `In progress`
   - Service source: `Defender for Cloud Apps`
   - Severity: `High`, `Medium`

4. Open each incident and review:
   - Timeline
   - Evidence and response
   - Correlated alerts

### Classification
- True Positive
- False Positive
- Informational

### Actions
- Assign owner
- Change status:
  - `In progress` (if analysis is required)
  - `Resolved` (if contained)

---

## Triage from Microsoft Defender XDR

Go to https://security.microsoft.com/incidents

### Objective
XDR correlation to understand cross-cutting impact.

### Procedure
- Review:
  - Affected users
  - Impacted Cloud Apps
- Evidence and Response → **Investigate**
- Use:
  - Activity Log
  - Advanced Hunting (if applicable)

### Record
- Document hypothesis, evidence, and conclusion

---

## Review Threat Detection Data

Go to https://security.microsoft.com/threatanalytics3

### Objective
Analyze MDCA detections (anomalies, malware, OAuth).

### Procedure
- Cloud Apps > Alerts
- Filters:
  - Category: `Threat detection`
  - Status: `Open`

### Validate
- Alert type
- Affected application
- Involved user

### Remediation
- Disable app
- Revoke OAuth consent

---

## Application Governance – OAuth Risk

Go to https://security.microsoft.com/cloudapps/governance-log

### Objective
Control OAuth application risk.

### Procedure
- Cloud Apps > App Governance
- Review:
  - **High Risk** apps
  - Anomalous activity

### Key validations
- Permissions (Graph scopes)
- Publisher
- Activity timeline

---

## App Governance – Overview

Go to https://security.microsoft.com/cloudapps/governance-log

### Objective
Global visibility into OAuth abuse.

### Review dashboards
- Active apps
- Alerts
- Compliance posture
- Sign-in activity

### Action
- Identify recent changes and anomalous spikes

---

## Review OAuth App Data

Go to https://security.microsoft.com/cloudapps/oauth-apps

### Objective
Detect consent phishing and OAuth persistence.

### Review
- Consent timestamps
- Permission level (Mail.Read, Files.ReadWrite)
- Users who granted access

### Response
- Disable app
- Revoke permissions

---

## App Governance Policies

Go to https://security.microsoft.com/cloudapps/policies/management

### Objective
Automate OAuth detection and response.

### Procedure
- Settings > Cloud Apps > App governance policies
- Validate predefined policies:
  - Suspicious OAuth App

### Confirm
- Scope
- Alerting
- Automatic remediation

---

## Conditional Access App Control

Go to https://security.microsoft.com/cloudapps/policies/management?tab=conditionalAccessPolicies

### Objective
Validate real-time session control.

### Review
- Active sessions
- Blocked activities

### Validation
- Alignment with Conditional Access policies

---

## Shadow IT – Cloud Discovery

Go to https://security.microsoft.com/cloudapps/discovery

### Objective
Identify unsanctioned applications.

### Procedure
- Cloud Apps > Cloud Discovery
- Review:
  - Newly discovered apps
  - Risk score

### Classification
- Sanctioned
- Unsanctioned

---

## Cloud Discovery Dashboard

Go to https://security.microsoft.com/cloudapps/discovery

### Objective
Identify usage and SaaS risk trends.

### Review
- High-level usage
- Top risky apps
- Discovery alerts

### Investigation
- Apps with high usage and low compliance

---

## Daily SOC Checklist
- Incidents reviewed
- OAuth alerts validated
- Risky apps mitigated
- Evidence documented

---

## Auditing and Traceability
- All incidents must:
  - Have an assigned owner
  - Attached evidence
  - Clear closing comments
