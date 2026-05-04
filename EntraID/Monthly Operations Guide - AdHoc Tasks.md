# Monthly/Ad-Hoc Operational Security Guide: Microsoft EntraID 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

Effective operation of Microsoft Entra ID requires continuous monitoring, change control, and periodic privilege review to reduce identity risks and ensure business continuity.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Privileged role review](#privileged-role-review)
- [Conditional Access policy validation](#conditional-access-policy-validation)
- [On-premises component updates](#on-premises-component-updates)
- [Testing significant changes (Ad-Hoc)](#testing-significant-changes-ad-hoc)

---

## Privileged role review

### Objective
Apply the **principle of least privilege** to reduce the risk associated with highly privileged accounts.

### Operational steps
1. Review who has the following roles assigned:
   - **Global Administrator**
   - **Privileged Role Administrator**
   - **Security Administrator**
2. Validate for each assignment:
   - Use of **Privileged Identity Management (PIM)**.
   - Documented justification for **permanent** access.

### Recommended tool
Running the following script is recommended: [Get-M365RoleReport](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Scripts/Get-M365RoleReport.ps1)

### Output / DoD
- Updated list of privileged roles.
- Evidence of PIM usage or formal justification for permanent access.

---

## Conditional Access policy validation

### Objective
Ensure that **Conditional Access** policies remain aligned with the current risk posture of the environment.

### Operational steps
1. Access the Conditional Access portal:
   - https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/menuId//fromNav/Identity

### Key actions
- Review **exclusions** (users, groups, locations).
- Remove **obsolete policies**.
- Evaluate the impact of:
  - New applications.
  - New locations or countries.

### Output / DoD
- Policies validated and aligned to risk.
- Changes documented.

---

## On-premises component updates

### Objective
Maintain **compatibility**, **performance**, and **security** in hybrid environments.

### Components to validate
- Microsoft Entra Connect.
- Pass-Through Authentication Agents.
- Connect Health Agents.

### Recommendations
- Use **auto-upgrade** whenever possible.
- Verify supported versions.

Official reference:
- [Microsoft Entra Connect – Version release history](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history)

### Output / DoD
- Components updated or update plan defined.

---

## Testing significant changes (Ad-Hoc)

### Objective
Reduce operational risk when implementing significant authentication or access changes.

### Common scenarios
- Authentication method change (**Federated ↔ PHS / PTA**).
- Implementation of new access policies.

### Best practices
- **Staged rollout**.
- Use of **pilot groups**.
- Use of **test tenant** when applicable.

### Output / DoD
- Evidence of controlled testing.
- Rollback plan defined.
