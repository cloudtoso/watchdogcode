# 🛡️ Monthly/Ad-Hoc Operational Security Guide: Microsoft Defender for Identity

## *Technology enables security, but discipline ensures its effectiveness.*

The monthly and ad-hoc MDI guide enables evaluating identity security posture, adjusting controls, and responding to extraordinary events that may impact business continuity.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Table of Contents
- [Review Microsoft Service Health before troubleshooting (Monthly)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#review-microsoft-service-health-before-troubleshooting-monthly)
- [Review server onboarding process to include MDI sensors (Ad-Hoc)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#review-server-onboarding-process-to-include-mdi-sensors-ad-hoc)
- [Validate domain configuration with Test-MDIConfiguration (PowerShell) (Ad-Hoc)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#validate-domain-configuration-with-test-mdiconfiguration-powershell-ad-hoc)

---
## Review Microsoft Service Health before troubleshooting (Monthly)

### Purpose
Avoid unnecessary troubleshooting when a service degradation exists at the Microsoft level.

### Step by step
1. When experiencing degradation, open **Service Health**:
   - https://admin.microsoft.com/#/servicehealth
2. If an incident exists:
   - Record **ID**, **scope**, and **ETA**.
   - Communicate the information to the team.
3. If no incident exists:
   - Continue with internal validation (health issues, connectivity, etc.).

### Output / DoD
- Documented confirmation of service status.
- Recorded decision (**wait** / **take action**).

---

## Review server onboarding process to include MDI sensors (Ad-Hoc)

### Purpose
Ensure that new **DC / AD CS / AD FS** are protected from the start.

> Reference: organization's internal documentation. The official article indicates reviewing the internal process.

### Step by step
1. Take the current server onboarding flow (DC / ADCS / ADFS).
2. Verify that it explicitly includes:
   - Installation of the **MDI sensor**.
   - **Post-installation** verification.
3. If any of the points are missing:
   - Update the checklist.
   - Define mandatory evidence for each onboarding.

### Output / DoD
- Process updated or validated.
- Required evidence clearly defined.

---

## Validate domain configuration with Test-MDIConfiguration (PowerShell) (Ad-Hoc)

### Purpose
Verify **Advanced Audit Policy**. A misconfiguration can cause event and coverage gaps.

### Where
- PowerShell on servers with **MDI sensor** (DC / corresponding servers).
- Official reference (quarterly / ad-hoc guide):
  - https://learn.microsoft.com/en-us/defender-for-identity/ops-guide/ops-guide-quarterly

### Step by step
1. On a DC (or server with sensor), open **PowerShell** with administrator permissions.
2. Run the command:
   ```powershell
   Test-MDIConfiguration
   ```
3. Review results:
   - If incomplete or misconfigured auditing exists:
     - Open ticket to **AD / Infrastructure** to fix **GPO / Audit Policy**.
4. Repeat validation after applying corrections.
5. Document the **final state**.

### Output / DoD
- Compliance evidence **or** documented remediation plan.
- Final state validated for auditing and coverage.