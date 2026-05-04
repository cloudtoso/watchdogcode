# Weekly Operational Security Guide: Microsoft Defender for Cloud Apps 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes weekly procedures to analyze trends, identify high-risk users, and manage threat campaigns in Microsoft Defender for Cloud Apps.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Table of Contents

- [Review policy assessments](#review-policy-assessments)
- [Review activity logs](#review-activity-logs)


---

## Review policy assessments
**Objective:** Policy effectiveness.

### Step by step

Go to https://security.microsoft.com/cloudapps/policies/management

- **Path:** `Cloud Apps > Policies`
- **Evaluate:**
  - **Alert volume** (trends vs. previous months)
  - **False positives** (operational impact and noise)

### Applied recommendations
- Define **monthly baselines** for alerts per policy.
- Document policies with **>20% false positives** for adjustment.
- Prioritize critical policies aligned with business risks.

### Action
- **Adjust thresholds** incrementally and record changes.

---

## Review activity logs
**Objective:** Investigation and compliance.

### Step by step

Go to https://security.microsoft.com/cloudapps/activity-log

- **Path:** `Cloud Apps > Activity log`
- **Apply filters by:**
  - **App** (focus on high-risk applications)
  - **User** (privileged users or those with anomalies)
  - **Activity type** (sensitive actions)

### Applied recommendations
- Use **standard time windows** (30 days) for consistency.
- Correlate activities with active alerts from the period.
- Validate log retention according to compliance requirements.

### Action
- **Export logs** when:
  - There is an active incident
  - Required by audit
  - Forensic analysis is needed

---

## Operational notes
- Record results in the SOC backlog.
- Escalate recurring findings for continuous policy improvement.
