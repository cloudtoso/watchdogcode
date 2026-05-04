# Principle of Least Privilege 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

**Microsoft Entra ID / Microsoft 365**

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Table of Contents
1. [No more than four permanent Global Administrators](#1-no-more-than-four-permanent-global-administrators)
2. [Separate user and administrative accounts](#2-separate-user-and-administrative-accounts)
3. [Use named accounts, avoiding shared accounts](#3-use-named-accounts-avoiding-shared-accounts)
4. [Use cloud-only accounts for any privileged role](#4-use-cloud-only-accounts-for-any-privileged-role)
5. [Require multifactor authentication (MFA) for all privileged accounts](#5-require-multifactor-authentication-mfa-for-all-privileged-accounts)
6. [Semi-annual validation of privileged accounts](#6-semi-annual-validation-of-privileged-accounts)
7. [Executive Summary](#executive-summary)

---

## 1. No more than four permanent Global Administrators

The organization must maintain **a maximum of four (4) accounts with the Global Administrator role permanently assigned**.  
These accounts are distributed as follows:

- **Two must be emergency accounts (Break Glass / Emergency Access Accounts)**  
- **Two may be permanent named administrative accounts**, assigned to highly trusted personnel

No additional accounts with permanent Global Administrator should exist outside this model.  
Any additional Global Administrator privilege requirements must be managed **exclusively through temporary access (Just-In-Time)** using **Privileged Identity Management (PIM)**.

---

### Emergency Accounts (Break Glass Accounts)

Accounts dedicated exclusively to emergency scenarios, such as:
- Conditional Access lockouts
- MFA failures
- Federation or identity outages
- Configuration errors preventing administrative access

**Mandatory requirements:**
- Cloud-only (not synchronized from on-premises Active Directory)
- **Global Administrator** role permanently assigned
- Excluded from all Conditional Access policies
- Use strictly limited to emergencies
- Monitoring and alerts for any sign-in

---

### Global Administrators

Administrative accounts associated with specific individuals, responsible for critical tenant operations.

**Characteristics:**
- May be **permanent**
- Use is **controlled and exceptional**
- Preferably managed through **Privileged Identity Management (PIM)**
- Activity subject to auditing and periodic review

---

## 2. Separate user and administrative accounts

All personnel with administrative responsibilities must have:
- **A standard user account** for daily activities (email, Teams, browsing)
- **A separate administrative account**, used solely for privileged tasks

User accounts **must not have administrative roles assigned**.

### Justification
Daily-use accounts are exposed to phishing, malware, and social engineering.  
Separating identities prevents a common compromise from leading to administrative access.

---

## 3. Use named accounts, avoiding shared accounts

All accounts with administrative privileges must be **named accounts**, associated with a specific individual.  
The use of **shared accounts is prohibited**.

### Justification
Shared accounts eliminate traceability, prevent action attribution, and hinder forensic investigations and audits.

---

## 4. Use cloud-only accounts for any privileged role

All accounts with privileged roles (Global Admin, Privileged Role Admin, Security Admin, etc.) must be **cloud-only**:
- Not synchronized from on-premises Active Directory
- Not federated with local infrastructure

### Justification
A compromise of on-premises AD can propagate to the cloud environment if privileged accounts are synchronized.  
Cloud-only accounts isolate the tenant's control plane.

---

## 5. Require multifactor authentication (MFA) for all privileged accounts

**All privileged accounts** must have **MFA mandatorily enabled**, including:
- Global Administrators
- Break Glass Accounts
- Privileged Role Administrators
- Security, Exchange, and Compliance Administrators

Whenever possible, **Phishing-Resistant MFA** should be used as the preferred method.

---

### Recommended authentication methods

**Order of preference:**
1. Phishing-resistant MFA  
   - FIDO2 / Passkeys  
   - Certificate-based authentication  
2. Microsoft Authenticator with number matching  
3. Legacy methods (SMS, calls) **not recommended**

---

### Considerations for Break Glass Accounts
- At least one account must guarantee access even during Conditional Access failures
- MFA must not depend on personal devices
- Credentials must be stored securely
- All usage must generate high-severity alerts

---

## 6. Semi-annual validation of privileged accounts

All accounts with administrative roles must be reviewed **at least every six (6) months** to verify they remain necessary and appropriate.

During each review, the following must be confirmed:

| Criterion | Description |
|----------|-------------|
| **The administrator still exists in the organization** | The person associated with the account is still an active employee or collaborator. Accounts of personnel who no longer belong to the organization must be revoked immediately. |
| **The role is still relevant** | The administrator's job function still justifies the assigned privilege level. Position or responsibility changes may make the role unnecessary. |
| **They still need the access (prevent privilege creep)** | Confirm that the administrator actively uses the privileges. Accumulation of unused roles creates unnecessary risk. |
| **No lower-privilege role is available** | Microsoft 365 frequently introduces new roles. Verify if a more scoped role exists that covers current needs and reassign accordingly. |
| **MFA is enabled and registered** | Verify that multifactor authentication is active and that the administrator has registered and functional authentication methods. |

### Justification
Periodic reviews prevent the accumulation of unnecessary privileges (*privilege creep*), detect orphaned accounts, and ensure that security controls remain in effect over time.

This script can be used for validation: [**Get-M365RoleReport**](../Scripts/Get-M365RoleReport.ps1)

---

## Executive Summary

| Control | Objective | Benefit |
|------|--------|---------|
| ≤ 4 permanent Global Admins | Reduce attack surface | Lower risk of total control |
| 2 Break Glass Accounts | Operational resilience | Avoid tenant lockout |
| Account separation | Containment | Protection against phishing |
| Named accounts | Traceability | Audit and investigation |
| Cloud-only accounts | Isolation | Hybrid protection |
| Mandatory MFA (phishing-resistant) | ATO prevention | Protection of critical identities |
| Semi-annual validation | Privilege hygiene | Detect orphaned accounts and privilege creep |

---
