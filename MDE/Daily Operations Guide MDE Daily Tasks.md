# Daily Operational Security Guide: Microsoft Defender for Endpoint 🛡️

## *Technology enables security, but discipline ensures its effectiveness.*

This guide establishes the daily procedures for monitoring alerts, managing at-risk devices, validating EDR sensor health, and responding to incidents in Microsoft Defender for Endpoint (MDE).

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano


## Scope
This guide describes **daily operational** activities for Microsoft Defender for Endpoint (MDE), focused on:

---

## Table of Contents

1. [Incident and Alert Monitoring](#incident-and-alert-monitoring)
2. [Alert Management and Classification](#alert-management-and-classification)  
3. [At-Risk Devices](#at-risk-devices) 
4. [Sensor Health and EDR Coverage](#sensor-health-and-edr-coverage)  
5. [Incident Response Actions](#incident-response-actions)  
6. [Threat Analytics Review](#threat-analytics-review)   

---

# Incident and Alert Monitoring

## Review the Incidents Queue

Go to the portal [Incidents - Microsoft Defender](https://security.microsoft.com/incidents)
In the Incidents panel, configure the following filters:
* **Period:** 1 Day
* **Status:** New and In progress
* **Alert severity:** Sort descending (Critical → High → Medium → Low)
* **Service sources:** Microsoft Defender for Endpoint

Save the custom view for future use

Review key columns:
* **Severity**
* **Status**
* **Assigned to**
* **Impacted assets** (Affected devices and users)
* **Alerts** (Number of correlated alerts)

## Prioritize Critical and High Incidents

1. Review incidents with **Critical** and **High** severity in the last 24 hours
2. Evaluate the number of correlated alerts, affected devices, and involved users
3. Assign the incident to the corresponding analyst if unassigned

## Validate Cross-Workload Correlation

Verify whether the incident has correlated alerts from other workloads:
* **MDO:** Malicious emails with attachments or URLs that triggered on the endpoint
* **MDI:** Lateral movement, privilege escalation from compromised identity
* **MDA:** Suspicious OAuth applications connected to the device

Document correlation findings in the incident comments

> If active impact is detected, escalate immediately to the response team.

---

# Alert Management and Classification

## Review New and Recurring Alerts

Go to the portal [Alerts - Microsoft Defender](https://security.microsoft.com/alerts)
Apply the following filters:
* **Status:** New
* **Service source:** Microsoft Defender for Endpoint
* **Time range:** Last 24 hours

## Classify Each Alert

Analysts must classify each alert as:
* **True Positive (TP):** Confirmed malicious activity → Investigate and remediate
* **Benign True Positive (BTP):** Legitimate activity that triggered the alert → Document justification
* **False Positive (FP):** Incorrect detection → Create controlled exclusion
* **Informational:** Low-relevance alert → Resolve with a note

Select **Manage alert** to apply the classification and add comments.

## Adjust Rules and Exclusions

When an alert is classified as FP:

1. Go to **Settings** → **Endpoints** → **Rules** → **Indicators** or **Custom detection rules**
2. Create the exclusion with the minimum necessary scope
3. Document each exclusion with justification, date, and responsible party
4. Verify that the exclusion does not affect ASR or Antivirus coverage

> **Never** create broad exclusions (e.g., excluding an entire directory like `C:\`). Keep the alert queue clear of items pending longer than 24 hours.

---

# At-Risk Devices

## Identify High-Risk Devices

Go to the portal [Device inventory - Microsoft Defender](https://security.microsoft.com/machines)
Apply the following filters:
* **Risk level:** High, Critical
* Sort by **Risk level** descending

For each high-risk device, review:
* Associated active alerts
* Users who signed in
* Detected software vulnerabilities
* Exposure level

## Detect Devices with Multiple Alerts in 24 Hours

1. Go to **Advanced Hunting**: https://security.microsoft.com/v2/advanced-hunting
2. Run the following query:

```kql
AlertInfo
| where Timestamp >= ago(24h)
| where ServiceSource has "Endpoint"
| join kind=inner (AlertEvidence | where Timestamp >= ago(24h) | where EntityType == "Machine") on AlertId
| summarize AlertCount = count(), Severities = make_set(Severity) by DeviceName
| where AlertCount >= 3
| order by AlertCount desc
```

3. Evaluate whether the alerts are part of a coordinated attack (kill chain)

## Review Pending Containment Actions

Verify whether there are recommended actions that have not been executed:
* Network isolation
* Antivirus scan execution
* Investigation package collection

> If containment requires approval, escalate to the team lead.

---

# Sensor Health and EDR Coverage

## Verify Onboarding Status

Go to the portal [Device inventory - Microsoft Defender](https://security.microsoft.com/machines)
Filter by **Onboarding status** and review:
* Devices with status `Can be onboarded` or `Insufficient info`
* Devices that stopped reporting telemetry

Report non-onboarded devices to the infrastructure team.

## Review Sensor Health Alerts

Go to **Settings** → **Endpoints** → **Device health** → **Sensor health & OS**
Check for devices with:
* **Impaired communications:** The sensor is not reporting telemetry
* **No sensor data:** No sensor data for more than 7 days
* **Misconfigured:** Incomplete or incorrect configuration

> Escalate devices with impaired communications for more than 48 hours.

## Validate Microsoft Defender Antivirus Status

Review in the device inventory:
* That signatures are up to date (no more than 3 days old)
* That the antivirus engine is active and in **real-time protection** mode
* Identify devices with third-party antivirus that may be causing conflicts

To validate via Advanced Hunting:

```kql
DeviceInfo
| where Timestamp >= ago(24h)
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus != "Onboarded" or SensorHealthState != "Active"
| project Timestamp, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, ExposureLevel
| order by Timestamp desc
```

---

# Incident Response Actions

## Evaluate the Appropriate Response Action

Before executing any action:
* Review the severity, threat type, and incident impact
* Confirm that the device has an active sensor and stable communication

## Execute Response Actions

From the device page, select **Response actions** and choose based on the scenario:

1. **Isolate device**
    * When: Confirmed active threat, risk of lateral propagation
    * Impact: The device loses network connectivity except with the MDE service
    * Schedule release review within <24 hours
2. **Run antivirus scan**
    * When: Malware detection, suspicious file on disk
    * Impact: Full or quick on-demand scan
3. **Collect investigation package**
    * When: Forensic evidence is needed (logs, processes, connections)
    * Impact: Generates a downloadable ZIP package with endpoint artifacts
4. **Initiate automated investigation**
    * When: Multiple alerts on the same device
    * Impact: Triggers automated investigation and remediation
5. **Live Response**
    * When: Advanced real-time forensic analysis
    * Impact: Remote session to the endpoint to execute commands, collect files

## Review and Approve AIR Actions

1. Go to [Action center - Microsoft Defender](https://security.microsoft.com/action-center/pending)
2. Review actions awaiting approval:
    * Quarantine file
    * Stop and quarantine process
    * Isolate device
    * Block URL / IP
3. For each pending action:
    * Click on the action to view details
    * Review **Investigation details** and **Evidence**
4. Make a decision:
    * **Approve:** If the evidence is conclusive
    * **Reject:** If it is a false positive
5. Check the **History** tab to confirm execution

## Live Response Considerations

* Requires **Security Operator** role or higher
* Enable at: **Settings** → **Endpoints** → **Advanced features** → **Live Response**
* Use only when automated actions are insufficient
* Document all commands executed during the session

> All actions must be documented in the incident: action taken, time, analyst, and justification.

---

# Threat Analytics Review

## Review Active and Emerging Threats

Go to the portal [Threat analytics - Microsoft Defender](https://security.microsoft.com/threatanalytics3)
Review threats marked as **Active** or **Trending**, prioritizing:
* Ransomware
* Prevalent malware
* Zero-day threats
* Targeted campaigns

## Evaluate Impact on the Environment

For each relevant threat, review:
* **Analyst report:** Technical description of the threat, TTPs, and IOCs
* **Impacted assets:** Devices and users exposed or affected in the tenant
* **Mitigations & detections:** Status of protections (ASR rules, AV signatures, EDR detections)

Prioritize threats that show exposed devices or incomplete mitigations.

## Execute Actions Based on Assessment

If there are exposed devices:
* Execute the mitigations recommended by Microsoft

If there are new IOCs:
1. Go to **Settings** → **Endpoints** → **Rules** → **Indicators**
2. Create custom indicators (hashes, URLs, IPs)
3. Select the action: **Block**, **Alert**, or **Alert and block**

If there are active ransomware or prevalent malware campaigns:
* Notify the security team
* Consider temporary hardening of ASR rules in block mode

## Document the Review

1. Record in the operational log: threats reviewed, impact assessed, actions taken
2. Include relevant findings in the daily report

> The daily Threat Analytics review should not exceed 15 minutes. Document critical users and devices for continuous monitoring.
