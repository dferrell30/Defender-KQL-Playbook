# 📧 Email Threat Hunting & Detection Engineering Playbook

![Version](https://img.shields.io/badge/Version-2.0-blue)
![KQL](https://img.shields.io/badge/Language-KQL-purple)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_XDR-green)
![Data Source](https://img.shields.io/badge/Data-Microsoft_Defender_XDR_%26_Sentinel-success)
![Status](https://img.shields.io/badge/Status-Community_Detection_Engineering-orange)

---

## Version

- **Version:** 2.0
- **Last Updated:** 2026-06-19
- **Data Sources:**
  - Microsoft Defender XDR
  - Microsoft Sentinel

---

## Purpose

This playbook provides practical KQL-based hunting workflows and detection engineering examples to identify, investigate, and respond to modern email threats.

The methodology focuses on detecting attacker **patterns and behaviors**, not just static indicators of compromise.

Coverage includes:

- Phishing campaigns
- Credential harvesting
- Malware delivery
- URL-based attacks
- Business Email Compromise (BEC)
- Identity impersonation
- Display-name spoofing
- Corporate lookalike domains
- Cross-domain investigation pivots

---

# ⚠️ Detection Engineering Disclaimer

The BEC detection examples included in this playbook are provided for:

- Threat hunting
- Detection engineering
- Lab validation
- Environment-specific testing

They are not intended to be deployed directly as production detections without proper validation.

Before enabling custom detections or automated response actions such as Soft Delete:

- Validate data availability
- Tune protected identities
- Configure known-safe exclusions
- Review false positives
- Evaluate operational impact

These examples are intended to complement Microsoft Defender for Office 365 protections including:

- Anti-phishing policies
- User impersonation protection
- Mailbox intelligence
- Domain impersonation protection
- SPF/DKIM/DMARC validation

---

# Table of Contents

- [Purpose](#purpose)
- [Detection Engineering Disclaimer](#-detection-engineering-disclaimer)
- [Email Investigation Workflow](#email-investigation-workflow)
- [Core Tables](#core-tables)
- [Attack Pattern Methodology](#attack-pattern-methodology)
- [Hunting Queries and Workflows](#hunting-queries-and-workflows)
- [BEC Detection Engineering Framework](#bec-detection-engineering-framework)
- [Investigation Pivots](#investigation-pivots)
- [Remediation Playbooks](#remediation-playbooks)
- [Detection Tuning Guidance](#detection-tuning-guidance)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Future Enhancements](#future-enhancements)

---

# Email Investigation Workflow

## Scope

Covers:

- Phishing campaigns
- Malware delivery via attachments
- URL-based attacks
- Internal impersonation
- Business Email Compromise (BEC)
- Spray-and-pray email attacks

---

# Core Tables

| Table | Description |
|---|---|
| EmailEvents | Email metadata and delivery status |
| EmailUrlInfo | URLs embedded within messages |
| EmailAttachmentInfo | Attachment metadata |
| UrlClickEvents | User interaction telemetry |

Optional pivots:

- IdentityLogonEvents / AADSignInEvents
- DeviceProcessEvents
- SecurityAlert / AlertEvidence

---

# Attack Pattern Methodology

Every investigation should answer:

1. Is this a campaign?
2. Was it delivered?
3. Did a user interact?
4. Did execution occur?
5. What is the blast radius?

---

# Detection Lifecycle

```
Hunt
 ↓
Alert
 ↓
Tune
 ↓
Validate
 ↓
Automate
```

---

# Hunting Queries and Workflows

---

# 1. Sender Domain Volume Spikes

**Type:** Hunting  
**Use Case:** Campaign Detection

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize
    MsgCount=count(),
    Recipients=dcount(RecipientEmailAddress)
    by bin(Timestamp, 1h), SenderFromDomain
| where MsgCount > 20
| sort by MsgCount desc
```

### Why it matters

Phishing campaigns often generate burst activity from the same infrastructure.

### Pivot

- SenderFromDomain → All messages
- NetworkMessageId → URLs and attachments
- DeliveryAction → Delivered or blocked

### Remediation

- Block sender domain
- Purge delivered messages
- Investigate user interaction

---

# 2. One Sender Targeting Many Users

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

- Subjects used
- URLs reused
- Departments targeted

### Remediation

- Block sender/domain
- Notify affected users
- Investigate clicks

---

# 3. Reused Subject Campaigns

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize
    Recipients=dcount(RecipientEmailAddress)
    by Subject
| where Recipients >= 10
| sort by Recipients desc
```

### Pivot

- All senders using the same subject
- URLs tied to the lure
- Delivery status

### Remediation

- Purge malicious messages
- Create temporary detections

---

# 4. Delivered Emails with Click Activity

**Priority:** High

```kusto
EmailEvents
| where Timestamp > ago(7d)
| project
    NetworkMessageId,
    RecipientEmailAddress,
    Subject,
    SenderFromAddress,
    DeliveryAction
| join kind=inner (
    UrlClickEvents
    | project
        NetworkMessageId,
        AccountUpn,
        Url,
        ActionType,
        ClickTime=Timestamp
) on NetworkMessageId
| project
    ClickTime,
    AccountUpn,
    RecipientEmailAddress,
    Subject,
    SenderFromAddress,
    DeliveryAction,
    Url,
    ActionType,
    NetworkMessageId
| sort by ClickTime desc
```

### Why it matters

Confirms that a user interacted with a potentially malicious message.

### Investigation Pivot

- AccountUpn → Sign-in activity
- URL → Infrastructure investigation
- Device telemetry → Execution analysis

### Remediation

- Reset passwords
- Revoke sessions
- Investigate sign-ins
- Notify affected users

---
