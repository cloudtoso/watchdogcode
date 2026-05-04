# Monthly Operational Security Guide: Microsoft Defender for Cloud Apps 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes monthly procedures to analyze trends, identify high-risk users, and manage threat campaigns in Microsoft Defender for Cloud Apps.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

> **General objective:** Ensure continuous security posture, operational health of integrations, and alignment with product changes.
>
> **Roles:**
> - **L1:** Basic review and validation
> - **L2:** Impact analysis and remediation coordination
> - **L3:** Architecture, governance, and runbook adjustments

---
## Table of Contents
- [Review SaaS Security Posture Management (SSPM)](#review-saas-security-posture-management-sspm)
- [Health Check – App Connectors, Log Collectors and SIEM](#health-check--app-connectors-log-collectors-and-siem)
- [Review Governance Log](#review-governance-log)
- [Track New Changes – Defender XDR & MDCA](#track-new-changes--defender-xdr--mdca)

---

## Review SaaS Security Posture Management (SSPM)

### Objective
Maintain a secure posture for SaaS applications monitored by MDCA.

### Procedure
1. Go to https://security.microsoft.com/cloudapps
2. Navigate to **Cloud Apps > SaaS security posture**
3. Review active recommendations
4. Validate impact on:
   - Secure Score
   - Affected controls
5. Identify recurring configuration gaps

### Actions
- Prioritize **High / Medium impact** recommendations
- Coordinate remediation with:
  - SaaS teams
  - Identity / Platform teams

### Evidence
- Record applied changes
- Document risk acceptance if not remediated

---

## Health Check – App Connectors, Log Collectors and SIEM

### Objective
Ensure continuous and reliable data ingestion into MDCA and SIEM.

### Procedure
1. Go to https://security.microsoft.com/cloudapps/settings?tabid=appConnectors
2. Navigate to **Settings > Cloud Apps > App connectors**
3. Validate:
   - Status: `Connected`
   - Last synchronization
4. Review **Log collectors**:
   - Active
   - Error-free
4. Confirm integration with **Microsoft Sentinel**

### Actions
- Escalate connectors in `Error` or `Disconnected` state
- Validate impact of incomplete ingestion

---

## Review Governance Log

### Objective
Audit administrative and governance actions.

### Procedure
1. Go to https://security.microsoft.com/cloudapps/governance-log
2. Navigate to **Cloud Apps > Governance log**
3. Review recent actions:
   - App disable/enable
   - Permission revocations
   - Policy changes

### Actions
- Validate that actions align with approved changes
- Identify unauthorized modifications

---

## Track New Changes – Defender XDR & MDCA

### Objective
Stay current with product updates and new capabilities.

### Procedure
1. Review Microsoft 365 Message Center
2. Check Defender XDR release notes
3. Evaluate impact of new features on:
   - Existing policies
   - Alert configurations
   - Integration points

### Actions
- Document relevant changes
- Plan adoption of new capabilities
- Update runbooks as needed
