# Comprehensive Email Security in Microsoft 365 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*
---

# Baseline Configurations for Exchange Online

**Audience:** Architecture, Messaging, SOC, SecOps, CISO  
**Level:** Technical / Operational (Enterprise)  
**Framework:** Zero Trust – Mail Flow Security

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Index
1. [Introduction](#1-introduction)
2. [Basic mail flow rules – Microsoft 365](#2-basic-mail-flow-rules--microsoft-365)
3. [RejectDirectSend in Exchange Online](#3-rejectdirectsend-in-exchange-online)
4. [SPF, DKIM, DMARC and MTA-STS Standards](#4-spf-dkim-dmarc-and-mta-sts-standards)
5. [Parked Domains](#5--parked-domains)
6. [Baseline Validation for improving security posture in Exchange Online](#baseline-validation-for-improving-security-posture-in-exchange-online)


---
# 1. Introduction

A correct setup of **mail flow rules in Microsoft 365**, **Direct Send blocking**, and the correct configurations of **SPF, DKIM, DMARC and MTA‑STS**, allow:

- Protecting the **brand** and the **domain**
- Reducing **phishing** and **spoofing**
- Ensuring the **deliverability** of legitimate email
- Preventing the **abuse of technical domains** (for example: `*.onmicrosoft.com`)
- Enforcing **SMTP encryption in transit** between servers
- Protecting **unused domains**
- Baseline for improving security posture in Exchange Online

---
> This basic setup establishes the minimum controls needed to protect domain identity and ensure secure and reliable email communication.
---

# 2. Basic Mail Flow Rules – Microsoft 365

Below you will find basic mail flow rules that are **highly recommended** to add to improve the security posture of Microsoft 365.

## Objectives

- Block emails sent to `mydominio.onmicrosoft.com` and `mydominio.mail.onmicrosoft.com`
- Block emails that cannot be analyzed (sent to quarantine)

---

## Mail flow rule to block emails sent to mydominio.onmicrosoft.com and mydominio.mail.onmicrosoft.com

### Option 1: Automated script – download the script that executes this task: [Block-onmicrosoftEmails](../Scripts/Block-OnMicrosoftEmails.ps1)

### Option 2: Manual creation

**Note:** Replace `mydomain` with the tenant's base domain.

#### Steps

1. Go to https://admin.exchange.microsoft.com/#/transportrules
2. Click **+ Add a rule**
3. Select **Create a new rule**
4. Name: **Block emails sent to mydomain.onmicrosoft.com**
5. Apply this rule if: **The message headers** → **matches these text patterns**
6. In **Enter text**, specify the **To** header and save
7. In **Enter words**, add:
   - `@mydomain\.onmicrosoft.com`
   - `@mydomain\.mail\.onmicrosoft.com`
8. Do the following: **Block the message** → **Delete the message without notifying anyone**
9. Next
10. Rule mode: **Enforce**
11. Severity: **High**
12. Check **Stop processing more rules**
13. Check **Defer the message if rule processing doesn't complete**
14. Next and **Finish**
15. Once the rule is created, edit it and change the Priority to 0
16. Click Save

#### References
> [Mail flow rules (transport rules) in Exchange Online](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules)
> 
> [New-TransportRule (Exchange PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchange/new-transportrule)
  

---

## Mail flow rule to block emails that cannot be inspected

### Option 1: Automated script – download the script that executes this task: [Attachments Can't be inspected](../Scripts/Attachmentscannotbeinspected.ps1)

### Option 2: Manual creation

#### Steps

1. Go to https://admin.exchange.microsoft.com/#/transportrules
2. Click **+ Add a rule**
3. Select **Create a new rule**
4. Name: **Quarantine Attachments Can't be inspected**
5. Apply this rule if: **Any attachment** → **content can't be inspected**
6. Do the following: **Redirect the message to** → **Hosted quarantine**
7. Next
8. Rule mode: **Enforce**
9. Severity: **High**
10. Check **Stop processing more rules**
11. Next and **Finish**
12. Once the rule is created, edit it and change the Priority to 1
13. Click Save


#### Reference
> [Inspect message attachments – Microsoft Learn](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/inspect-message-attachments)
  


---
# 3. RejectDirectSend in Exchange Online
---
## What is Direct Send?

**Direct Send** allows sending emails to internal tenant mailboxes using:

- SMTP port **25**  
- Destination: `tenant.mail.protection.outlook.com`  
- **Without authentication** (anonymous)  
- Sender domain (**P1 MAIL FROM**) belongs to an *accepted domain*

Designed for:

- Printers  
- Scanners  
- Legacy on‑prem applications

### Inherent Risk

- Does not require account compromise  
- Allows credible internal impersonation (CEO, Finance, HR)  
- Depends on SPF / DKIM / DMARC (subsequent controls, not preventive)

---

### What does RejectDirectSend do?

```powershell
Set-OrganizationConfig -RejectDirectSend $true
```

### Evaluation Logic

Exchange Online **rejects the message** when:

1. The email arrives **anonymously**  
2. It is not associated with an **authenticated Mail Flow Connector**  
3. The **P1 MAIL FROM** belongs to an accepted domain of the tenant  
4. The recipient is an internal mailbox

### Result

- ❌ Does not enter the antispam pipeline  
- ❌ SPF / DKIM / DMARC is not evaluated  
- ✅ Immediate SMTP rejection

**Typical error:**

```
550 5.7.68 TenantInboundAttribution; Direct Send not allowed for this organization
```

---

### What this control does NOT do

- Does not validate the **P2 From header**  
- Does not analyze reputation  
- Does not depend on DMARC  
- Does not apply heuristics

It is a **deterministic control**, not probabilistic.

---

### Security Impact (SOC view)

**Without RejectDirectSend**

- Internal phishing without identity compromise  
- Spoofed emails can reach Inbox / Junk  
- High risk of financial fraud

**With RejectDirectSend**

- Total blocking of internal SMTP spoofing  
- Immediate reduction of attack surface  
- Control aligned to Zero Trust

---

### Operational Impact on Applications

**Flows that break**

- Printers / scanners  
- ERPs / legacy HR  
- Old SMTP scripts  
- Misconfigured SaaS

**Supported alternatives**

- ✅ Mail Flow Connector authenticated by **certificate** (recommended)  
- ✅ Mail Flow Connector by **fixed IP**  
- ✅ SMTP AUTH with dedicated account (last resort)

---

### Control Status

| Property | Value |
|---------|------|
| Default | false |
| $false | Direct Send isn't blocked |
| $true | Direct Send is blocked |
| Propagation | ~30 minutes |

**Verification:**

```powershell
Get-OrganizationConfig | Select RejectDirectSend
```

#### Reference
> [Direct Send: Send mail directly from your device or application to Microsoft 365 or Office 365](https://learn.microsoft.com/es-mx/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365#direct-send-send-mail-directly-from-your-device-or-application-to-microsoft-365-or-office-365)
> 
> [RejectDirectSend](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig?view=exchange-ps#-rejectdirectsend)

---

# 4. SPF, DKIM, DMARC and MTA-STS Standards

SPF, DKIM, DMARC, and MTA-STS are fundamental email security controls that protect organizations against identity impersonation (spoofing), phishing, fraud, and in-transit attacks, in addition to ensuring the deliverability of legitimate email.

**Together, these mechanisms protect the brand, reduce fraud risk, and ensure that critical business email reaches its destination securely.**

---

## SPF (Sender Policy Framework)

### What is SPF?
SPF defines which servers are authorized to send emails on behalf of a domain.

### What problems does it prevent?
- Sending forged emails using your domain
- Basic IP-based spoofing

### How does SPF work?

#### 1. SPF Record in DNS (TXT)
The domain publishes a TXT record specifying the authorized hosts/IPs.

Example:
```
v=spf1 ip4:203.0.113.0/24 include:mail.example.com -all
```

Structure:
- `v=spf1` → version
- Mechanisms: `ip4`, `ip6`, `a`, `mx`, `include`, `exists`
- Final qualifier: `-all`, `~all`, `?all`, `+all`

#### 2. Evaluation at the receiving server
- The receiving MTA queries the **MAIL FROM** domain
- Compares the sending IP against the defined mechanisms

Possible results:
- `pass`
- `fail`
- `softfail`
- `neutral`
- `permerror`
- `temperror`

#### Action based on result
- **pass** → email accepted
- **fail (-all)** → possible rejection
- **softfail (~all)** → marked as suspicious

### Main SPF mechanisms

- **ip4 / ip6** → authorizes specific IPs
- **a / mx** → authorizes IPs resolved via DNS
- **include** → inherits rules from another domain
- **exists** → advanced conditional validation

### SPF Qualifiers

- `-all` → hard reject
- `~all` → soft reject
- `?all` → neutral
- `+all` → allow all (not recommended)

> Note: The `/all` qualifier **does not exist** in the SPF standard.

#### Reference
> [Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)

---

## DKIM (DomainKeys Identified Mail)

### What is DKIM?
DKIM is a domain-level cryptographic authentication mechanism that verifies that:
1. The message was authorized by the sending domain
2. The content was not altered in transit

DKIM validates **the domain**, not the user.

### Key Components

#### Cryptographic Key Pair
- **Private key**: resides on the sending server and signs the message
- **Public key**: published in DNS as a TXT record

> Current recommendation: **RSA 2048 bits**

#### DKIM Selector
Allows multiple active keys per domain.

Example:
```
selector1._domainkey.ejemplo.com
```

Advantages:
- Rotation without downtime
- Multiple providers
- Secure delegation

#### DKIM-Signature Header

Example:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=ejemplo.com; s=selector1;
 h=from:to:subject:date:message-id;
 bh=Base64HashBody;
 b=FirmaDigitalBase64
```

Important fields:
- `d` → signing domain
- `s` → selector
- `h` → signed headers
- `bh` → body hash
- `b` → digital signature


#### Reference
> [DomainKeys Identified Mail (DKIM)](https://dkim.org/)
---

## DMARC (Domain-based Message Authentication, Reporting & Conformance)

### What is DMARC?
DMARC is a protocol that operates on top of SPF and DKIM, adding:
- Alignment with the **From:** field
- Action policies
- Visibility reports

### How does it work?
1. The receiver evaluates SPF and DKIM
2. Verifies alignment with From:
3. Applies the defined policy (`none`, `quarantine`, `reject`)

### Components of a DMARC Record

Published at:
```
_dmarc.tudominio.com
```

Main tags:
- `p` → policy
- `rua` → aggregate reports
- `ruf` → forensic reports
- `adkim` / `aspf` → alignment
- `pct` → application percentage

### Recommended Implementation

1. Prepare SPF and DKIM
2. Start with `p=none`
3. Analyze reports
4. Migrate to `quarantine`
5. Harden to `reject`

Strict example:
```
v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100
```

Best practices:
- Continuous monitoring
- Strict alignment
- Subdomain protection

#### Reference
> [Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489.html)

---

## MTA-STS (Mail Transfer Agent – Strict Transport Security)

### What is MTA-STS?
MTA-STS is a standard (RFC 8461) that protects email **in transit between SMTP servers**, enforcing the use of validated TLS.

### Mitigated Threats
- Man-in-the-Middle (MITM)
- TLS downgrade
- SMTP traffic interception

### Historical SMTP Problem
- Opportunistic STARTTLS
- Fallback to plain text

MTA-STS makes TLS **mandatory**.

### Key Components

#### 1. DNS Record `_mta-sts`
```
_mta-sts.ejemplo.com IN TXT "v=STSv1; id=2024022501"
```

#### 2. HTTPS Policy

Location:
```
https://mta-sts.ejemplo.com/.well-known/mta-sts.txt
```

Example:
```
version: STSv1
mode: enforce
mx: mail.ejemplo.com
max_age: 604800
```

####  TLS Reporting (TLS-RPT)

```
_smtp._tls.ejemplo.com IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@ejemplo.com"
```

Provides operational visibility.

---

## Validation Script

You can validate SPF, DKIM, DMARC, and MTA-STS with the following script: [Domain-Health-Check.ps1](../Scripts/Domain-Health-Check.ps1)

#### Reference
> [SMTP MTA Strict Transport Security (MTA-STS)](https://www.rfc-editor.org/rfc/rfc8461)

---

# 5.  Parked Domains

##**What is a "parked domain"?**

A **parked domain** is a domain that:
- Has no active services (web, email, applications).
- Points to a generic page of the provider (hosting or registrar).
- Has no explicit **DNS**, **security**, or **email** configurations.

> In practice: the domain exists, but **is not really controlled at an operational level**.

---

## What to do instead of using a "parked domain"?

Even if **you are not going to actively use the domain**, it is recommended to configure it in a minimal and defensive manner.

### Minimum Recommended Configuration

#### SPF (domain not used for email)
```dns
v=spf1 -all
```

#### DMARC (most secure configuration)
```dns
v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@tudominio.com
```

### What does this configuration achieve?
- Rejects all email that fails **SPF** or **DKIM**.
- Completely protects against **spoofing**.
- Sends **aggregate authentication reports** (rua).

---

## Risk of Abuse for Phishing and Impersonation

A parked domain normally:
- Does not have **SPF**, **DKIM**, or **DMARC** configured.
- Does not reject email by design.
- Can be used by attackers to **impersonate your brand**.

### Real Impact
- Phishing using your domain.
- Fraud against clients and vendors.
- Immediate reputational damage.

> Many attacks use "forgotten" domains because **nobody monitors their use**.

---

## Domain Reputation and Future Email Problems

If a parked domain:
- Appears in spam campaigns.
- Has no restrictive DMARC policies.
- Does not maintain a clean sending history.

When you later want to use it:
- Emails will go to **SPAM**.
- There will be blocks from Microsoft, Google, Proofpoint, among others.
- It will be necessary to **rebuild the reputation from scratch**.

> It is much cheaper to prevent than to recover a domain's reputation.

---

## Total Lack of Security Control (DNS and ownership)

A parked domain usually:
- Uses the registrar's DNS.
- Has no explicit records (**CAA**, **DNSSEC**, **controlled MX**).
- Depends on shared generic configurations.

### Associated Risks
- Unaudited changes.
- Greater ease for **DNS hijacking**.
- Lack of traceability during incidents.

---

## Risk of "Domain Shadow IT"

In large organizations it is common to:
- Buy domains "just in case".
- Forget about them.
- Not assign a responsible **owner**.

### Result
- Nobody monitors the domain.
- Nobody receives alerts.
- Nobody reviews logs.

> This is **Shadow IT of identity and brand**, one of the most ignored risks in security.
 ---
---
#### Reference
> [Parked and Inactive Domain Setup for MX, SPF and DMARC](https://support.dmarcreport.com/support/solutions/articles/5000882467-parked-and-inactive-domain-setup-for-mx-spf-and-dmarc)

# Baseline Validation for Improving Security Posture in Exchange Online

**A quick validation can be performed by running the following script: [Validate-EXOSecurityBaseline](../Scripts/Validate-EXOSecurityBaseline.ps1)**

  > Internal Tools 2026
