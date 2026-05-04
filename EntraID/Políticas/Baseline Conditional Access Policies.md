# Conditional Access Templates (Microsoft Entra) 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*
## Prerequisites
- Have at least one **break-glass** account excluded from Conditional Access.
- Always start policies in **Report-only**.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Require multifactor authentication for all users

### Objective
Requires that **all users** complete **multifactor authentication (MFA)** when accessing organizational resources, as a baseline measure to reduce the risk of credential compromise.

### Steps
1. Go to https://entra.microsoft.com
2. Entra ID → Protection → Conditional Access
3. **Create new policy from template**
4. Category: **Secure foundation**
5. Template: **Require multifactor authentication for all users**
6. Review + Create

### Configuration
- Users: Include **All users**
- Exclude: Break-glass and temporary admin account
- Target resources: **All resources**
- Grant: **Require multifactor authentication**
- Enable policy: **Report-only**

---

## Require phishing-resistant multifactor authentication for administrators

### Objective
Requires that **administrative accounts** use **phishing-resistant MFA methods** to protect roles with the highest impact on tenant security.

### Steps
1. Conditional Access → Create new policy from template
2. Category: **Protect administrators**
3. Template: **Require phishing-resistant multifactor authentication for administrators**
4. Review + Create

### Configuration
- Target: **Directory roles** (critical admin roles)
- Grant: **Require authentication strength → Phishing-resistant MFA**
- Exclude: Break-glass
- Enable policy: **Report-only**

**Register FIDO2 or Windows Hello for Business beforehand.**

---

## Require multifactor authentication for risky sign-ins

### Objective
Requires MFA when Microsoft Entra ID detects a **medium or high risk in the sign-in**, using risk signals to apply adaptive protection.

### Steps
1. Create new policy from template
2. Category: **Emerging threats**
3. Template: **Require multifactor authentication for risky sign-ins**
4. Review + Create

### Configuration
- Condition: Sign-in risk **Medium** and **High**
- Grant: **Require MFA**
- Exclude: Break-glass
- Enable policy: **Report-only**

---

## Block legacy authentication

### Objective
Blocks sign-in attempts that use **legacy authentication protocols**, which do not support MFA and are commonly used in brute force and password spray attacks.

### Steps
1. Create new policy from template
2. Category: **Secure foundation**
3. Template: **Block legacy authentication**
4. Review + Create

### Configuration
- Users: Include **All users**
- Exclude: Break-glass (and justified legacy accounts)
- Conditions → Client apps: **Exchange ActiveSync** and **Other clients**
- Grant: **Block access**
- Enable policy: **Report-only**

---

## Recommended Deployment Order
1. MFA for all users
2. Phishing-resistant MFA for admins
3. MFA for risky sign-ins
4. Block legacy authentication

---
