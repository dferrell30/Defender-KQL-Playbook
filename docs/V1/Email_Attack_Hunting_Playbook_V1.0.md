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
| where DeliveryAction =~ "Delivered"
| project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress
| join kind=inner (
    UrlClickEvents
    | project NetworkMessageId, AccountUpn, Url, ClickTime=Timestamp
) on NetworkMessageId
```

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

## Step 2: Expand Scope

* All recipients
* Delivery status

## Step 3: Investigate Payload

* URLs → EmailUrlInfo
* Attachments → EmailAttachmentInfo

## Step 4: Confirm Interaction

* UrlClickEvents
* Device activity

## Step 5: Identity Validation

* Sign-in logs
* Token anomalies

## Step 6: Determine Impact

* Multiple users?
* Repeated infrastructure?
* Ongoing campaign?

---

# Remediation Playbooks

## Credential Phishing

Actions:

1. Identify recipients and clickers
2. Reset passwords
3. Revoke sessions
4. Review sign-in activity
5. Block domains/URLs
6. Purge emails

---

## Malware Attachments

Actions:

1. Identify recipients
2. Block file hash
3. Investigate execution
4. Isolate devices
5. Hunt persistence

---

## Business Email Compromise (BEC)

Actions:

1. Identify targeted users
2. Check for replies/actions
3. Alert finance/HR
4. Strengthen impersonation controls

---

## Tuning Guidance

Adjust thresholds based on:

* Organization size
* Email volume
* Trusted senders

Example:

```kusto
| where SenderFromDomain !endswith "contoso.com"
| where DeliveryAction =~ "Delivered"
```

---

## Escalation Criteria

Escalate when:

* Multiple users clicked
* High-value users targeted
* Malware executed
* Suspicious sign-ins detected

---

## Related Documentation

* KQL Playbook Deep Dive (Core methodology)

---

## Future Enhancements

* QR phishing detection
* Callback phishing patterns
* Sentinel analytics rule conversion
* Automated response workflows

