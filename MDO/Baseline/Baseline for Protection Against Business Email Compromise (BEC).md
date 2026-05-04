# Protection Against Business Email Compromise (BEC) 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

Business Email Compromise (BEC) is a highly targeted fraud attack based on social engineering, impersonation, and identity compromise. Its goal is to manipulate financial or operational decisions through emails that appear authentic, frequently sent from legitimate compromised accounts.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

### Modern BEC attacks combine:
- Identity compromise
- User and domain impersonation
- Advanced impersonation without technical spoofing
- Real knowledge of internal processes
- Email thread manipulation

No single layer stops BEC by itself.
Mitigation requires **discipline + technology + processes**.

---

# Multi-Layer Protection Model (Zero Trust + NIST + Microsoft Defender)

1. Email authentication (SPF, DKIM, DMARC)
2. Advanced anti‑phishing (MDO)
3. Safe Links / Safe Attachments / ZAP
4. Identity protection (Zero Trust / Entra ID Protection)
5. Business process controls
6. SOC detection and response (MDO + XDR)
7. Continuous awareness

---

# 1. Email Authentication  
### Together, these mechanisms protect the brand, reduce fraud risk, and ensure that critical business email reaches its destination securely

## SPF
SPF (Sender Policy Framework) defines which servers are authorized to send email on behalf of your domain.

Basic configuration, where -all is highlighted:
```
v=spf1 include:spf.protection.outlook.com -all
```

## DKIM
DKIM (DomainKeys Identified Mail) adds a digital signature to each outgoing email.

Mandatory enabled on all domains.
```
selector1._domainkey.tudominio.com  | selector1-tudominio-com._domainkey.tutenant.onmicrosoft.com
selector2._domainkey.tudominio.com  | selector2-tudominio-com._domainkey.tutenant.onmicrosoft.com
```

## DMARC
DMARC (Domain-based Message Authentication, Reporting & Conformance) defines what to do when SPF or DKIM fail and requires alignment with the visible email domain.

Minimum acceptable:
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```
Ideal:
```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```

> For more detail see [**SPF, DKIM, DMARC and MTA-STS Standards**](L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md#4-est%C3%A1ndares-spf-dkim-dmarc-y-mta-sts)

---

# 2. Anti‑Phishing – Microsoft Defender for Office 365
**This measure is essential for blocking highly specific and sophisticated impersonation attempts, where the attacker mimics executives, vendors, or key areas to induce fraudulent actions**

---

## Phishing threshold
This threshold controls the sensitivity for applying machine learning models to messages to determine a phishing verdict.
1 - Standard

2 - Aggressive

**3 – More aggressive** (Highly Recommended)

4 - Most aggressive

### Impersonation Protection
Impersonation protection received strong signals that the following messages are suspicious
- Executives
- Finance
- Legal
- Critical vendors
- Strategic partners

## Mailbox Intelligence
Mailbox intelligence uses artificial intelligence (AI) to determine user email patterns with their frequent contacts.

**Enabled + Impersonation Protection**

## Spoof Intelligence
Choose how you want to filter emails from senders who are spoofing domains.

**Enabled and respecting DMARC**

> 

How to create [**Anti-Phishing Policy**](../Pol%C3%ADticas/Pol%C3%ADtica%20Anti-Phishing%20MDO.md)

---

# 3. Safe Links, Safe Attachments and ZAP
**Safe Links, Safe Attachments, and ZAP provide real-time protection against malicious URLs, dangerous files, and emails that become suspicious after delivery**

## Safe Links
Protects your users from opening and sharing malicious links in email messages and Office applications

**Real-time protection:**
- Outlook, Teams, SharePoint, OneDrive
- Click‑time scanning
- Block original URL
- Log clicks

> Reference: [**Safe Links Policy**](../Pol%C3%ADticas/Politica%20Safe%20links.md)

## Safe Attachments
Protect your organization from malicious content in email attachments and files in SharePoint, OneDrive, and Teams

**Recommendation:**
- **Dynamic Delivery**
- **Block** mode
- Enable for SharePoint / OneDrive / Teams

> Reference: [**Safe Attachments Policy**](../Pol%C3%ADticas/Pol%C3%ADtica%20de%20Safe%20Attachments.md)

## Zero‑Hour Auto Purge (ZAP)
**Zero‑Hour Auto Purge (ZAP)** is a post‑delivery protection from Microsoft Defender for Office 365 that **automatically detects and removes** malicious emails that were already delivered to the **user's mailbox**
- Globally enabled
- Removes delivered emails that are later classified as malicious

> To validate ZAP run this script [**Validate-ZAPConfiguration**](../Scripts/Validate-ZAPConfiguration.ps1)

---
# 4. Identity Protection (Zero Trust)
## Mandatory MFA for all users

Requires that **all users** complete **multi-factor authentication (MFA)** when accessing organizational resources, as a baseline measure to reduce the risk of credential compromise

> Recommended template: [**Require multifactor authentication for all users**](../../EntraID/Pol%C3%ADticas/Linea%20base%20Conditional%20Access%20Policies.md#require-multifactor-authentication-for-all-users)

## Phishing-resistant MFA (administrators)

Requires that **administrative accounts** use **phishing-resistant MFA methods** to protect the roles with the greatest impact on tenant security.

> Recommended template: [**Require phishing-resistant multifactor authentication for administrators**](../../EntraID/Pol%C3%ADticas/Linea%20base%20Conditional%20Access%20Policies.md#require-phishing-resistant-multifactor-authentication-for-administrators)

## Detect risky sign-ins

Requires MFA when Microsoft Entra ID detects a **medium or high risk in the sign-in**, using risk signals to apply adaptive protection.

> Recommended template: [**Require multifactor authentication for risky sign-ins**](../../EntraID/Pol%C3%ADticas/Linea%20base%20Conditional%20Access%20Policies.md#require-multifactor-authentication-for-risky-sign-ins)

## Legacy Authentication Blocking

Blocks sign-in attempts that use **legacy authentication protocols**, which do not support MFA and are commonly used in brute force and password spray attacks

> Recommended template: [**Block legacy authentication**](../../EntraID/Pol%C3%ADticas/Linea%20base%20Conditional%20Access%20Policies.md#block-legacy-authentication)


---

# 5. Business Process Controls

## Out-of-band dual validation

### This is a control that requires verifying critical transactions using a channel other than email, even if the message:
- Appears legitimate
- Continues a real thread
- Uses correct signatures, tone, and language

**This is critical because in modern BEC attacks:**
- The attacker does control the account
- The email is real
- Technical tools may not block it 

**Must be mandatory for:**
- Vendor bank detail changes
- Urgent or out-of-pattern payments
- New vendors
- Executive instructions (CEO Fraud)

**Recommended best practices**
- Call a previously registered number
- Use an independent channel (corporate phone, financial system)
- Document the verification
- Require subsequent second approval
 ---

## Separation of Duties (SoD)
### Separation of duties (SoD) is a control principle that establishes that a single person should NOT be able to execute an entire critical business process by themselves.

> In simple terms:
>
> No one should be able to initiate, approve, and execute a sensitive transaction without another person intervening.
---

**Prevents:**
- A single person from executing the entire process.
- An attacker (or human error)
- From completing a fraud from start to finish
- Compromising a single account

> In BEC attacks, the attacker's goal is **a single decision point.**
> 
> If that point exists, the fraud occurs immediately

**Example WITHOUT separation of duties (Risky)**
- The person receives the email ("urgent payment")
- Changes the bank details
- Authorizes the payment
- Executes the transfer

> The attacker wins with a single compromised account.

**Example WITH separation of duties (SoD)**

| Step                    | Different Role |
|-------------------------|--------------|
| Receive the request     | User A    |
| Validate out of band    | User B    |
| Authorize the payment   | User C    |
| Execute the payment     | User D    |

 In this model, **the attacker would need to compromise several people at the same time**, which **drastically reduces the risk of fraud** and significantly raises the attack barrier.

> **Key idea**
>
> SoD is not bureaucracy.
>
> It is a structural barrier against fraud.
>
> That's why it appears in standards like ISO 27001, SOX, PCI-DSS, and NIST

## Priority accounts

### These are accounts whose compromise has a direct and serious impact on the business, not just IT.
**They typically include:**
- Executives (CEO, CFO, COO)
- Finance / Treasury / Procurement
- Legal / Compliance

**Why are they so critical?**
- They have authority for payments, contracts, and decisions
- Their emails are automatically trusted
- They are the primary target in BEC attacks

> An attacker **doesn't need malware** if they can convince Finance or an Executive

### Differentiated controls by user type

| Control                     | Normal users | Priority accounts |
|-----------------------------|------------------|----------------------|
| MFA                         | Yes               | Yes (phishing‑resistant) |
| Anti‑phishing               | Yes               | Yes (dedicated impersonation) |
| Safe Attachments / Links    | Yes               | Yes (strict mode) |
| Mandatory SoD               | No               | Yes |
| Out-of-band validation      | No               | Yes |
| SOC monitoring              | Basic           | Continuous |

> **Key idea**
>
> Not all users represent the same risk to the business.
> Priority accounts require priority controls.

---

# 6. SOC Detection and Response

##  Priority signals
- Impersonation detected
- Mailbox Intelligence anomalies
- Suspicious rules
- New ASNs or risky IPs

##  Common suspicious rules
- External auto‑forward
- Move to RSS/Archive
- Mark as read
- Delete sent items

##  Threat Explorer
- Blast radius
- Lookalike domains
- Who replied / forwarded

##  Advanced Hunting
- Thread hijacking
- Malicious rules
- Anomalous login

##  XDR
Automatic correlation of identity + email + endpoint.

---

[Reference Operational Security Guides MDO](../)

---

# 7. Awareness and Training

## Recommended simulations
- CEO Fraud
- Vendor Fraud
- Payment Diversion
- Invoice Scam

## Key metrics
- Vulnerable users
- Report rate
- Accumulated risk

---

# Executive Summary

**Effective BEC mitigation requires:**
- Strong identity
- Aggressive anti‑phishing
- Safe Links / Safe Attachments / ZAP
- Robust processes
- Trained users
- Fast and disciplined SOC
- XDR correlation

> **BEC fails when each layer assumes that the previous one can be compromised.**


---