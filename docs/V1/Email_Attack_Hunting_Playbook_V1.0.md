# 📧 Email Threat Hunting & Detection Engineering Playbook

![Version](https://img.shields.io/badge/Version-2.0-blue)
![KQL](https://img.shields.io/badge/Language-KQL-purple)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_XDR-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Community_Research-orange)
![MITRE](https://img.shields.io/badge/MITRE-T1566_Phishing-red)

---

## Overview

This repository contains practical KQL-based hunting workflows and detection engineering examples designed for Microsoft Defender XDR and Microsoft Sentinel.

The playbook focuses on identifying **attacker behavior patterns**, not simply individual indicators of compromise (IOCs).

Coverage includes:

- Phishing campaigns
- Business Email Compromise (BEC)
- Identity impersonation
- Malicious attachments
- URL-based attacks
- User interaction telemetry
- Campaign correlation
- Cross-domain investigation pivots

---

# ⚠️ Important Disclaimer

These KQL queries are provided for:

- Security research
- Threat hunting
- Detection engineering
- Lab validation
- Environment-specific tuning

They are **not intended to be deployed as production detections without testing**.

Organizations should:

- Validate data availability
- Tune thresholds
- Add organization-specific exclusions
- Validate false positives
- Review operational impact

before enabling automated actions such as:

- Alert generation
- Automated investigation
- Message soft delete
- Automated remediation

These examples are intended to complement—not replace—Microsoft Defender for Office 365 protections, including:

- Anti-phishing policies
- Mailbox intelligence
- User impersonation protection
- Domain impersonation protection
- SPF/DKIM/DMARC validation

---

# 📚 Table of Contents

- [Overview](#overview)
- [Data Sources](#data-sources)
- [Email Investigation Methodology](#email-investigation-methodology)
- [Core Hunting Queries](#core-hunting-queries)
- [BEC Detection Engineering Framework](#bec-detection-engineering-framework)
- [Investigation Pivots](#investigation-pivots)
- [Remediation Workflows](#remediation-workflows)
- [Detection Tuning Guidance](#detection-tuning-guidance)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Future Enhancements](#future-enhancements)

---

# 📊 Data Sources

| Source | Purpose |
|---|---|
| EmailEvents | Email metadata, delivery, sender analysis |
| EmailUrlInfo | URL extraction and campaign tracking |
| EmailAttachmentInfo | Attachment investigation |
| UrlClickEvents | User interaction telemetry |
| IdentityLogonEvents | Identity investigation pivots |
| AADSignInEvents | Sign-in analysis |
| DeviceProcessEvents | Payload execution investigation |
| SecurityAlert | Existing detection correlation |

---

# 🧭 Email Investigation Methodology

Every investigation should answer:

1. Is this part of a larger campaign?
2. Was the message delivered?
3. Did a user interact with it?
4. Did execution or credential compromise occur?
5. What is the blast radius?
6. Is additional remediation required?

---

# 🔍 Core Hunting Queries

## Campaign Analysis

- Sender domain volume spikes
- One sender targeting many recipients
- Subject reuse analysis
- Spray-and-pray detection

## Payload Investigation

- URL-based campaigns
- Malicious attachment campaigns
- User click correlation

---

# 🛡️ BEC Detection Engineering Framework

Modern BEC attacks frequently rely on identity abuse rather than traditional malware.

This playbook includes three detection patterns:

---

## BEC-01: Consumer Account Identity Impersonation

### Purpose

Detects consumer email accounts attempting to impersonate:

- Employees
- Executives
- Finance teams
- HR
- IT administration
- Shared business functions

### Methodology

```
Consumer Email Domain
           +
Normalized Sender Identity
           +
Protected Identity Patterns
           -
Known Safe Exceptions
           =
Potential BEC
```

Recommended Lifecycle:

```
Hunting
   ↓
Alert
   ↓
Tuned Detection
   ↓
Optional Automated Response
```

---

## BEC-02: Display Name Impersonation

### Purpose

Detects emails where:

The display name claims to be a trusted identity, but the actual sender does not align with expected naming patterns.

Example:

```
Display Name:
John Smith

Actual Sender:
billing-update123@gmail.com
```

Methodology:

```
Display Name Matches Protected Identity
                     +
Actual Sender Does Not Match Expected Pattern
                     =
Potential BEC Display Name Impersonation
```

---

## BEC-03: Corporate Lookalike Domain Impersonation

### Purpose

Detects domains attempting to imitate an organization.

Examples:

```
john.smith@contoso-security.com
ceo@contoso-support.com
payroll@contoso.co
```

Methodology:

```
Domain Resembles Organization
               +
Domain Not Trusted
               +
Protected Identity Present
               =
Potential Brand Impersonation
```

---

# 🔄 Investigation Pivots

Useful pivots include:

- NetworkMessageId → Message scope
- SenderFromAddress → Campaign source
- SenderFromDomain → Infrastructure
- RecipientEmailAddress → Target analysis
- URL → Infrastructure and click activity
- SHA256 → Endpoint execution
- AccountUpn → Identity impact

---

# 🛠️ Remediation Workflows

## Credential Phishing

- Reset credentials
- Revoke active sessions
- Investigate sign-ins
- Block malicious infrastructure

## Malware Delivery

- Block file hashes
- Isolate impacted devices
- Hunt persistence mechanisms

## Business Email Compromise

- Identify targeted users
- Review replies and user actions
- Notify impacted business units
- Review impersonation controls

---

# 🎯 Detection Tuning Guidance

Every environment is unique.

Before promoting detections:

- Run in hunting mode
- Convert to alert-only detections
- Monitor false positives
- Add trusted senders and exclusions
- Validate identity patterns

High confidence detections may be candidates for:

- Soft delete
- Automated investigation
- Custom detection actions

---

# 🗺️ MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1566 | Phishing |
| T1585 | Establish Accounts |
| T1586 | Compromise Accounts |
| T1589 | Gather Victim Identity Information |
| T1036 | Masquerading |

---

# 🚀 Future Enhancements

Planned areas of research:

- QR phishing (Quishing)
- Callback phishing campaigns
- OAuth consent phishing
- First-seen sender analysis
- Mailbox intelligence correlation
- SPF/DKIM/DMARC anomaly detection
- Automated Defender XDR custom detection conversion
- Microsoft Sentinel analytics rules

---

# 🤝 Community Contribution

Security detection engineering improves through collaboration.

Feel free to:

- Adapt these queries
- Improve detection logic
- Submit enhancements
- Share additional hunting techniques

---

## Author Notes

This playbook was developed from practical threat hunting and detection engineering scenarios focused on improving visibility into modern email threats.

The goal is to provide reusable hunting methodologies that can be adapted to individual organizational requirements.
