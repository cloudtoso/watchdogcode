# Weekly Operational Security Guide: Microsoft EntraID 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

Effective operation of Microsoft Entra ID requires continuous monitoring, change control, and periodic privilege review to reduce identity risks and ensure business continuity.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Administrative change review](#administrative-change-review)
- [Identity Secure Score tracking](#identity-secure-score-tracking)
- [Review of old synchronization errors](#review-of-old-synchronization-errors)

---

## Administrative change review

### Objective
Detect risky configurations or unplanned changes that may affect the identity security posture.

### Operational steps
1. Access the **Audit Logs** in Microsoft Entra ID:
   - https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView
2. Specifically review:
   - Changes to **administrative roles**.
   - Changes to **Conditional Access policies**.
3. Validate that all changes:
   - Are **approved**.
   - Are **documented** according to internal processes.

### Impact of not doing this
- Privilege escalation.
- Exposure of critical resources.
- Loss of administrative control.

---

## Identity Secure Score tracking

### Objective
Measure the identity security posture and prioritize continuous improvement actions.

### Operational steps
1. Access **Identity Secure Score**:
   - https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraRecommendationsIdentitySecureScore.ReactView
2. Review active recommendations.
3. Prioritize key actions, such as:
   - Enable **MFA for privileged roles**.
   - Protect **break-glass** accounts.
4. Record progress or regressions compared to previous weeks.

### Impact of not doing this
- Stagnation in security posture.
- Prolonged exposure to known risks.
- Lack of risk-based prioritization.

---

## Review of old synchronization errors

### Objective
Avoid **technical debt** in identities and persistent synchronization problems.

### Recommended action
1. Access the synchronization configuration:
   - https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/CrossTenantSynchronizationConfiguration.ReactView
2. Identify:
   - Synchronization errors older than **90–100 days**.
3. Execute corrective actions:
   - Clean up obsolete objects.
   - Fix problematic objects.

### Impact of not doing this
- Identity inconsistencies.
- Recurring access errors.
- Increased operational incidents.
