# Monthly/Ad-Hoc Operational Security Guide: Microsoft Defender for Endpoint 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes Monthly/Ad-Hoc procedures to analyze threat trends, execute proactive hunting, manage vulnerabilities, and review endpoint security posture in Microsoft Defender for Endpoint (MDE).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

## Scope
This guide describes **monthly and ad-hoc operational** activities for Microsoft Defender for Endpoint (MDE), focused on:

---

## Table of Contents
1. [Monthly review of what's new](#1-review-whats-new-with-microsoft-defender-for-endpoint-monthly)
2. [Ad-hoc review of endpoint configurations, rules, and policies](#2-review-endpoint-configuration-rules-and-policy-settings-ad-hoc)

---

## 1. Review What's New with Microsoft Defender for Endpoint (Monthly)

### Objective
Ensure the security team:
- Is aware of functional changes in MDE
- Anticipates operational impact
- Updates runbooks, configurations, and processes when applicable

---

### Roles
- Security Architect  
- SOC Lead  
- Security Administrator

---

### Sources / Consoles
- Microsoft Defender Portal  
- Microsoft 365 Message Center  
- Official MDE "What's new" documentation

---

### Step-by-Step Procedure

#### 1. Review service announcements
1. Go to: https://admin.microsoft.com/#/MessageCenter
2. Filter by:
   - Microsoft Defender
   - Endpoint
3. Identify announcements related to:
   - EDR
   - ASR (Attack Surface Reduction)
   - Sensors
   - Licensing changes
   - Changes in default behavior

---

#### 2. Review MDE-specific updates
1. Check the **What's new** section of Microsoft Defender for Endpoint
2. Identify:
   - New detections
   - Changes to ASR rules
   - New response capabilities
   - Portal experience changes

---

#### 3. Assess impact
For each relevant change, answer:
- Does it require technical action?
- Does it impact end users, SOC, or IT?
- Should it be communicated or documented?

---

#### 4. Update documentation
- Record changes in:
  - Monthly security log
  - SOC Runbooks
  - Operational procedures

---

### Expected Outcome (DoD)
- Relevant changes documented
- Adjustments planned when applicable
- No unanticipated operational impacts

---

## 2. Review Endpoint Configuration, Rules, and Policy Settings (Ad-Hoc)

### Objective
Validate that the **endpoint security posture** remains:
- Consistent
- Aligned with best practices
- Free of configuration drift

---

### Roles
- SOC Operator  
- Security Administrator  
- Endpoint / Intune Administrator (when applicable)

---

### Primary Console
- Microsoft Defender Portal  
  https://security.microsoft.com

---

### Step-by-Step Procedure

---

### A. General Endpoint Status Review

1. Navigate to:  
   **Assets → Devices**
2. Validate:
   - Onboarding status
   - Sensor health (EDR)
   - Last communication
   - Operating system and version

**Action:**
- Investigate devices:
  - Inactive
  - Can be onboarded
  - Sensor issues

---

### B. Configuration and Policy Review

1. Navigate to:  
   **Endpoints → Configuration management → Dashboard**
2. Review:
   - Device compliance
   - Applied configurations
   - Conflicts between Intune and GPO

---

### C. Attack Surface Reduction (ASR) Review

1. Go to:  
   **Reports → Endpoints → Attack surface reduction rules**
2. Validate critical rules in **Block** mode, for example:
   - Block credential stealing from LSASS
   - Block Office apps from creating child processes
   - Block executable content from email
3. Analyze:
   - Event volume
   - Potential false positives

**Action:**
- Adjust exclusions only if they are:
  - Justified
  - Documented
  - With an assigned owner

---

### D. Device Discovery Review (if applicable)

1. Navigate to:  
   **Settings → Endpoints → Device discovery**
2. Validate:
   - **Standard discovery** mode
   - Corporate subnets properly monitored
3. Review:
   - Detected unmanaged devices

---

### Expected Outcome (DoD)
- No unknown critical configurations
- ASR aligned with the actual risk of the environment
- Changes documented and traceable

---

## Key Operational Principles

- What's new and not reviewed becomes a risk
- Every exclusion must have an owner, reason, and date
- ASR in Audit mode **does not protect**
- Configuration drift is a silent threat

---
