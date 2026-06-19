# Email Attack Hunting Playbook

## Version

* Version: 1.0
* Last Updated: 2026-04-21
* Data Sources: Microsoft Defender XDR, Microsoft Sentinel

---

## Purpose

This playbook provides practical KQL-based techniques to identify, investigate, and remediate email-based attacks.

It focuses on detecting **patterns**, not just individual emails, enabling analysts to:

* Identify phishing campaigns
* Detect malicious attachments and URLs
* Track user interaction (clicks, execution)
* Pivot across identity and endpoint data
* Execute effective remediation

---

## 📧 Email Investigation Workflow

## Scope

Covers:

* Phishing campaigns (credential harvesting)
* Malware delivery via attachments
* URL-based attacks
* Internal impersonation (BEC-style)
* Spray-and-pray email attacks

---

## Core Tables

| Table               | Description                        |
| ------------------- | ---------------------------------- |
| EmailEvents         | Email metadata and delivery status |
| EmailUrlInfo        | URLs within emails                 |
| EmailAttachmentInfo | Attachment metadata                |
| UrlClickEvents      | User click telemetry               |

Optional pivots:

* IdentityLogonEvents / AADSignInEvents
* DeviceProcessEvents
* SecurityAlert / AlertEvidence

---

## Attack Pattern Methodology

Every investigation should answer:

1. **Is this a campaign?**
2. **Was it delivered?**
3. **Did a user interact?**
4. **What is the blast radius?**

---

# Hunting Queries and Workflows

---

## 1. Sender Domain Volume Spikes

**Type:** Hunting
**Use Case:** Campaign Detection

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize MsgCount=count(), Recipients=dcount(RecipientEmailAddress)
    by bin(Timestamp, 1h), SenderFromDomain
| where MsgCount > 20
| sort by MsgCount desc
```

### Why it matters

Phishing campaigns often generate **bursty traffic patterns**.

### Pivot

* SenderFromDomain → all messages
* NetworkMessageId → URLs + attachments
* DeliveryAction → was it delivered?

### Remediation

* Block domain
* Purge delivered messages
* Investigate user clicks

---

## 2. One Sender Targeting Many Users

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize
    TotalMessages=count(),
    TargetedUsers=dcount(RecipientEmailAddress)
    by SenderFromAddress, SenderFromDomain
| where TargetedUsers >= 10
| sort by TargetedUsers desc
```

### Pivot

* Subjects used
* URL reuse
* Departments targeted

### Remediation

* Block sender/domain
* Notify impacted users
* Investigate clicks

---

## 3. Reused Subject Campaigns

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize Recipients=dcount(RecipientEmailAddress) by Subject
| where Recipients >= 10
| sort by Recipients desc
```

### Pivot

* All senders using subject
* URLs tied to subject
* Delivery status

### Remediation

* Purge messages
* Create temporary detection rule

---

## 4. Delivered Emails with Click Activity

**High Priority Detection**

```kusto
EmailEvents
| where Timestamp > ago(7d)
| project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress, DeliveryAction
| join kind=inner (
    UrlClickEvents
    | project NetworkMessageId, AccountUpn, Url, ActionType, ClickTime=Timestamp
) on NetworkMessageId
| project ClickTime, AccountUpn, RecipientEmailAddress, Subject, SenderFromAddress, DeliveryAction, Url, ActionType, NetworkMessageId
| sort by ClickTime desc
```

### Simulation Note

In phishing simulations, `UrlClickEvents` may show user interaction even when `EmailUrlInfo` does not return URL details. In that case, use `UrlClickEvents` as the primary source for confirming interaction and pivot from `AccountUpn`, `Url`, and `NetworkMessageId`.

### Why it matters

This confirms **user interaction with a potentially malicious email**.

### Pivot

* AccountUpn → sign-in logs
* URL → campaign infrastructure
* Device activity → payload execution

### Remediation

* Reset password
* Revoke sessions
* Investigate sign-ins
* Notify user

---

## 5. Malicious Attachment Campaigns

```kusto
EmailAttachmentInfo
| where Timestamp > ago(14d)
| summarize Recipients=dcount(RecipientEmailAddress) by SHA256
| where Recipients >= 5
| sort by Recipients desc
```

### Pivot

* SHA256 → DeviceProcessEvents
* FileName variations
* Message distribution

### Remediation

* Block hash
* Isolate impacted devices
* Hunt execution activity

---

## 6. URL-Based Campaign Detection

```kusto
EmailUrlInfo
| where Timestamp > ago(14d)
| summarize Messages=dcount(NetworkMessageId) by UrlDomain
| sort by Messages desc
```

### Pivot

* UrlDomain → all messages
* UrlClickEvents → user interaction

### Remediation

* Block domain
* Identify clickers
* Initiate identity review

---

## 7. Internal Domain Spoofing

```kusto
let MyDomain = "contoso.com";
EmailEvents
| where SenderFromDomain =~ MyDomain
| where SenderFromAddress !endswith MyDomain
```

### Remediation

* Tune SPF/DKIM/DMARC
* Block spoof patterns
* Alert users

---

## 8. Spray-and-Pray Detection

```kusto
EmailEvents
| summarize Domains=dcount(SenderFromDomain) by RecipientEmailAddress
| where Domains >= 10
```

### Remediation

* Focus on high-risk users
* Increase monitoring
* Provide awareness

---

# Pivot Workflow (Critical)

## Step 1: Start with Message

* NetworkMessageId
* Sender
* Subject

---

## Step 2: Expand Scope

* All recipients
* Delivery status

---

## Step 3: Investigate Payload

* URLs → EmailUrlInfo
* Attachments → EmailAttachmentInfo

---

## Step 4: Confirm Interaction

* UrlClickEvents
* Device activity

---

## Step 5: Identity Validation

* Sign-in logs
* Token anomalies

---

## Step 6: Determine Impact

Ask:

* Multiple users affected?
* Repeated infrastructure?
* Ongoing campaign?
* Additional containment required?

---

## Email Investigation Pivots

When URL metadata is missing or incomplete, pivot from the telemetry that is available.

Primary pivots:

* NetworkMessageId → message scope
* AccountUpn → identity activity
* Url → clicked infrastructure
* RecipientEmailAddress → targeted user
* SenderFromAddress / SenderFromDomain → campaign source

If `EmailUrlInfo` does not return results, check `UrlClickEvents` directly to confirm interaction.

---

# Remediation Playbooks

## Credential Phishing

Actions:

1. Identify recipients and clickers
2. Reset passwords
3. Revoke active sessions
4. Review sign-in activity
5. Block malicious domains and URLs
6. Purge malicious emails

---

## Malware Attachments

Actions:

1. Identify recipients
2. Block malicious file hashes
3. Investigate endpoint execution
4. Isolate impacted devices
5. Hunt for persistence mechanisms

---

## Business Email Compromise (BEC)

Actions:

1. Identify targeted users
2. Determine whether users responded or took action
3. Alert impacted business units (Finance, HR, Executives)
4. Review and strengthen impersonation protection controls
5. Review email authentication controls (SPF, DKIM, DMARC)

---

# Tuning Guidance

Email attack patterns vary significantly by environment. Adjust hunting thresholds and filters based on:

* Organization size
* Email volume
* Trusted senders and domains
* Business communication patterns

Example tuning:

```kusto
| where SenderFromDomain !endswith "contoso.com"
| where DeliveryAction =~ "Delivered"
```

The goal of tuning is to reduce noise while preserving meaningful attack signals.

---

# Escalation Criteria

Escalate investigations when:

* Multiple users clicked malicious URLs
* High-value users or privileged accounts were targeted
* Malware execution occurred
* Suspicious authentication activity follows email interaction
* Multiple related messages indicate an active campaign

---

# Related Documentation

* KQL Playbook Deep Dive (Core methodology)
* Microsoft Defender XDR Advanced Hunting Documentation
* Microsoft Sentinel KQL Documentation

---

# Future Enhancements

Potential future additions:

* QR phishing (Quishing) detection
* Callback phishing patterns
* OAuth consent phishing detection
* Email authentication anomaly hunting
* Sentinel analytics rule conversion
* Automated response workflows

---

# Email Validation Checks

Use validation checks to confirm that hunting results represent actionable activity before moving into remediation.

## Validate Email Delivery

Confirm whether the message was:

* Delivered
* Quarantined
* Blocked
* Soft deleted

Key fields:

* DeliveryAction
* DeliveryLocation

---

## Validate User Interaction

Confirm whether users interacted with the message:

* URL clicks
* Attachment interaction
* Endpoint activity

Primary sources:

* UrlClickEvents
* DeviceProcessEvents

---

## Validate Identity Impact

Determine whether email activity resulted in identity compromise indicators:

* New sign-in locations
* Impossible travel scenarios
* Suspicious token activity
* Abnormal authentication patterns

Primary sources:

* AADSignInEvents
* IdentityLogonEvents

---

## Final Analyst Checklist

Before closing an investigation:

☐ Identify the original sender and infrastructure
☐ Determine all impacted recipients
☐ Confirm delivery status
☐ Validate user interaction
☐ Investigate endpoint activity
☐ Review identity compromise indicators
☐ Determine campaign scope
☐ Complete remediation actions

---

## Closing Notes

Version 1.0 of the Email Attack Hunting Playbook focuses on practical email investigation workflows using Microsoft Defender XDR and Microsoft Sentinel.

The methodology emphasizes moving from an individual suspicious email to full campaign understanding through telemetry pivots, user interaction analysis, endpoint investigation, identity validation, and remediation.

This playbook serves as the baseline foundation for future versions that expand into advanced detection engineering, automation workflows, and additional email threat scenarios.

---

# Disclaimer

The KQL queries, hunting techniques, and detection methodologies provided in this playbook are intended for educational, research, threat hunting, and detection engineering purposes.

These examples are designed to demonstrate investigative workflows and potential detection strategies using Microsoft Defender XDR, Microsoft Sentinel, and related security telemetry. They are not intended to be universally deployed as production detections without appropriate testing, validation, and environment-specific tuning.

Every organization has unique infrastructure, communication patterns, business workflows, and acceptable risk thresholds. Before operationalizing any query as a custom detection, alert, automated response, or remediation action, organizations should:

* Validate the availability and quality of required telemetry
* Review and tune thresholds, identity lists, trusted senders, and exclusions
* Assess false positives and operational impact
* Test detections in a controlled manner before enabling automated actions such as message Soft Delete, quarantine, or other remediation workflows

These techniques are intended to complement—not replace—existing security controls, including Microsoft Defender for Office 365 anti-phishing protections, mailbox intelligence, impersonation protection, SPF, DKIM, DMARC validation, and established security operations processes.

Threat actors continuously evolve their tactics, techniques, and procedures (TTPs). Detection engineering should be treated as an iterative process involving continuous testing, tuning, validation, and improvement.

Use these examples responsibly and evaluate all detection and response actions within the context of your organization's security policies, operational requirements, and risk tolerance.



