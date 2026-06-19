# 📧 Email Threat Hunting & Detection Engineering Playbook

![Version](https://img.shields.io/badge/Version-2.0-blue)
![KQL](https://img.shields.io/badge/Language-KQL-purple)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_XDR-green)
![Data Source](https://img.shields.io/badge/Data-Microsoft_Defender_XDR_%26_Microsoft_Sentinel-success)
![Status](https://img.shields.io/badge/Status-Community_Detection_Engineering-orange)

---

# Version

* **Version:** 2.0
* **Last Updated:** 2026-06-19
* **Platforms:**

  * Microsoft Defender XDR
  * Microsoft Sentinel

---

# Purpose

This playbook provides practical KQL-based threat hunting workflows and detection engineering examples for modern email attacks.

The goal is to move beyond identifying individual malicious messages and provide analysts with repeatable methods to:

* Identify phishing campaigns
* Investigate malicious URLs and attachments
* Understand user interaction and impact
* Pivot into identity and endpoint telemetry
* Detect Business Email Compromise (BEC)
* Identify impersonation and brand abuse
* Convert validated hunting techniques into operational detections

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Detection Engineering Philosophy

A successful detection is not created by simply writing a KQL query.

Every detection should progress through a lifecycle:

```
Hunt
  ↓
Validate
  ↓
Tune
  ↓
Alert
  ↓
Automate (When Appropriate)
```

Organizations should validate detections against their own:

* Business communication patterns
* Trusted senders and partners
* Email routing configurations
* Journaling systems
* Accepted risk levels

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

<a id="table-of-contents"></a>

# Table of Contents

- [Version](#version)
- [Purpose](#purpose)
- [Detection Engineering Philosophy](#detection-engineering-philosophy)
- [Data Sources](#data-sources)
- [Investigation Methodology](#investigation-methodology)
- [Query Classification Matrix](#query-classification-matrix)
- [Core Email Hunting](#core-email-hunting)
  - [Query 1 — Sender Domain Volume Spikes](#query-1--sender-domain-volume-spikes)
  - [Query 2 — One Sender Targeting Many Users](#query-2--one-sender-targeting-many-users)
  - [Query 3 — Reused Subject Campaigns](#query-3--reused-subject-campaigns)
  - [Query 4 — Delivered Emails With Click Activity](#query-4--delivered-emails-with-click-activity)
  - [Query 5 — Malicious Attachment Campaigns](#query-5--malicious-attachment-campaigns)
  - [Query 6 — URL-Based Campaign Detection](#query-6--url-based-campaign-detection)
  - [Query 7 — Internal Domain Spoofing](#query-7--internal-domain-spoofing)
  - [Query 8 — Spray-and-Pray Detection](#query-8--spray-and-pray-detection)
- [Business Email Compromise (BEC) Detection Engineering Framework](#business-email-compromise-bec-detection-engineering-framework)
  - [Query 9 — Consumer Account Identity Impersonation](#query-9--consumer-account-identity-impersonation)
  - [Query 10 — Display Name Impersonation and Sender Mismatch](#query-10--display-name-impersonation-and-sender-mismatch)
  - [Query 11 — Corporate Lookalike Domain Impersonation](#query-11--corporate-lookalike-domain-impersonation)
- [Advanced Email Threat Hunting](#advanced-email-threat-hunting)
  - [Query 12 — QR Phishing (Quishing) Detection](#query-12--qr-phishing-quishing-detection)
  - [Query 13 — Callback Phishing / TOAD Detection](#query-13--callback-phishing--toad-detection)
  - [Query 14 — High-Risk Emails Delivered to Inbox](#query-14--high-risk-emails-delivered-to-inbox)
  - [Query 15 — First-Seen Sender Domain Detection](#query-15--first-seen-sender-domain-detection)
  - [Query 16 — URL Clicks After Delivery and User Exposure](#query-16--url-clicks-after-delivery-and-user-exposure)
  - [Query 17 — Shared URL Infrastructure Across Multiple Senders](#query-17--shared-url-infrastructure-across-multiple-senders)
  - [Query 18 — Attachment Filename Reuse and Campaign Correlation](#query-18--attachment-filename-reuse-and-campaign-correlation)
  - [Query 19 — Reply Chain / Conversation Hijacking Detection](#query-19--reply-chain--conversation-hijacking-detection)
  - [Query 20 — High-Value Business Function Targeting](#query-20--high-value-business-function-targeting)
- [Email Investigation & Validation Framework](#email-investigation--validation-framework)
- [Investigation Pivot Workflow](#investigation-pivot-workflow)
- [Email Validation Workflow](#email-validation-workflow)
- [Remediation Playbooks](#remediation-playbooks)
- [Detection Tuning Guidance](#detection-tuning-guidance)
- [Detection Engineering Lifecycle](#detection-engineering-lifecycle)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Future Research Areas](#future-research-areas)
- [Community Detection Engineering Disclaimer](#community-detection-engineering-disclaimer)
- [Closing Notes](#closing-notes)

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Data Sources

| Data Source                           | Purpose                                         |
| ------------------------------------- | ----------------------------------------------- |
| EmailEvents                           | Sender, recipient, delivery, and email metadata |
| EmailUrlInfo                          | URLs discovered within messages                 |
| EmailAttachmentInfo                   | Attachment metadata and file analysis           |
| UrlClickEvents                        | User interaction with URLs                      |
| IdentityLogonEvents / AADSignInEvents | Identity compromise investigation               |
| DeviceProcessEvents                   | Malware execution and endpoint validation       |
| SecurityAlert / AlertEvidence         | Existing security signal correlation            |

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Investigation Methodology

Every email investigation should answer:

1. Is this part of a larger campaign?
2. Was the email delivered?
3. Did the user interact?
4. Did a malicious payload execute?
5. Is there evidence of identity compromise?
6. What is the blast radius?
7. Does this represent a new detection opportunity?

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Query Classification Matrix

| Query | Category                        | Purpose                            |
| ----- | ------------------------------- | ---------------------------------- |
| 1     | Campaign Hunting                | Detect sender volume spikes        |
| 2     | Campaign Hunting                | Identify broad recipient targeting |
| 3     | Campaign Hunting                | Identify repeated phishing themes  |
| 4     | User Impact                     | Confirm user interaction           |
| 5     | Malware Analysis                | Attachment campaign identification |
| 6     | URL Analysis                    | URL infrastructure hunting         |
| 7     | Spoofing Detection              | Internal domain abuse              |
| 8     | Spray Detection                 | Wide targeting analysis            |
| 9     | BEC                             | Consumer identity impersonation    |
| 10    | BEC                             | Display name and sender mismatch   |
| 11    | BEC                             | Corporate lookalike domains        |
| 12    | Emerging Threats                | QR phishing detection              |
| 13    | Emerging Threats                | Callback phishing / TOAD           |
| 14    | Risk Validation                 | Delivered high-risk emails         |
| 15    | Infrastructure                  | First-seen sender domains          |
| 16    | User Impact                     | URL clicks after delivery          |
| 17    | Campaign Correlation            | Shared URL infrastructure          |
| 18    | Malware Correlation             | Attachment reuse                   |
| 19    | Conversation Abuse              | Reply-chain hijacking              |
| 20    | Executive / Financial Targeting | High-value user attacks            |

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Core Email Hunting

This section preserves the original hunting methodology from Version 1.0 while expanding each query with deeper detection engineering context.

The original objective remains unchanged:

* Identify the campaign
* Understand delivery impact
* Determine user interaction
* Identify compromise indicators
* Scope the blast radius
* Execute appropriate remediation

---

## Query 1 — Sender Domain Volume Spikes

**Category:** Campaign Hunting
**Use Case:** Identify high-volume email campaigns originating from a single sender domain.

### KQL Query

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

### How the KQL Works

This query analyzes email traffic over the previous seven days and groups messages into one-hour time windows.

Key logic:

* `bin(Timestamp, 1h)` identifies bursts of activity over time.
* `count()` measures total message volume.
* `dcount(RecipientEmailAddress)` measures the blast radius.
* Thresholds can be adjusted based on organizational size.

This is effective for identifying phishing campaigns that distribute many messages over a short period.

### Why It Matters

Large phishing operations frequently reuse the same infrastructure to target many users.

Even if individual emails appear benign, volume anomalies can reveal:

* Credential harvesting campaigns
* Malware distribution
* Spam waves
* Business email compromise attempts

### Investigation Pivots

Pivot into:

* SenderFromDomain → Identify all messages from the infrastructure.
* NetworkMessageId → Review URLs and attachments.
* RecipientEmailAddress → Identify targeted users.
* DeliveryAction → Determine whether messages reached inboxes.
* ThreatTypes and DetectionMethods → Review existing Defender verdicts.

### Remediation Considerations

Potential response actions:

* Block malicious domains.
* Remove delivered messages.
* Notify impacted users.
* Hunt for URL clicks and endpoint activity.

### Detection Engineering Notes

This is a strong candidate for:

* Scheduled hunting
* Alert creation after tuning
* Campaign monitoring dashboards

Thresholds should be adjusted based on normal organizational email volume.

---

## Query 2 — One Sender Targeting Many Users

**Category:** Campaign Hunting
**Use Case:** Identify a single sender or domain targeting a large number of users.

### KQL Query

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

### How the KQL Works

This query looks for a common phishing pattern where a single sender attempts to reach many recipients.

Key logic:

* `SenderFromAddress` identifies the exact sending identity.
* `SenderFromDomain` identifies the sending infrastructure.
* `count()` measures total email volume.
* `dcount(RecipientEmailAddress)` determines the number of unique users targeted.
* The threshold `>= 10` identifies broad targeting behavior and should be adjusted to match organizational size.

Unlike a volume-based detection, this query focuses on **recipient spread**, making it useful when attackers send a small number of messages to many users.

### Why It Matters

Many phishing campaigns attempt to maximize exposure by targeting:

* Entire departments
* Distribution groups
* Multiple business units
* High-value users

Common scenarios include:

* Credential harvesting campaigns
* Fake invoice campaigns
* Business email compromise attempts
* Malware delivery waves

### Investigation Pivots

Pivot into:

* **SenderFromAddress** → Review all messages from the sender.
* **SenderFromDomain** → Determine whether other identities from the domain are involved.
* **Subject** → Identify reused lures.
* **NetworkMessageId** → Investigate URLs and attachments.
* **RecipientEmailAddress** → Identify affected departments or privileged users.
* **DeliveryAction / DeliveryLocation** → Determine whether the messages reached users.

### Remediation Considerations

Potential response actions:

* Block malicious sender addresses.
* Block or monitor suspicious domains.
* Remove delivered messages.
* Notify impacted users.
* Review user interaction and potential compromise.

### Detection Engineering Notes

This query is well suited for:

* Scheduled hunting
* Campaign discovery dashboards
* Custom detections after tuning

Recommended tuning:

* Lower thresholds for smaller organizations.
* Increase thresholds for large enterprises.
* Create exclusions for trusted bulk senders or approved marketing platforms.

---

## Query 3 — Reused Subject Campaigns

**Category:** Campaign Hunting
**Use Case:** Identify phishing campaigns that reuse the same email lure or subject line.

### KQL Query

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize
    Recipients=dcount(RecipientEmailAddress)
    by Subject
| where Recipients >= 10
| sort by Recipients desc
```

### How the KQL Works

This query groups emails by their subject line and identifies subjects that appear across many recipients.

Key logic:

* `summarize` groups messages by the subject field.
* `dcount(RecipientEmailAddress)` determines how many unique users received the message.
* The threshold identifies widespread reuse of the same lure.

Attackers often reuse the same subject because changing infrastructure is easier than changing the social engineering theme.

### Why It Matters

Repeated subjects can reveal:

* Phishing campaigns
* Invoice scams
* Payroll or HR impersonation
* Fake document sharing notifications
* Security alert impersonation

Examples include:

* "Urgent Payment Request"
* "Invoice Attached"
* "Your Password Expires Today"
* "New Secure Document Shared"

### Investigation Pivots

Pivot into:

* **Subject** → Identify all related messages.
* **SenderFromAddress** → Determine whether multiple senders are using the same lure.
* **SenderFromDomain** → Identify campaign infrastructure.
* **EmailUrlInfo** → Investigate malicious links.
* **EmailAttachmentInfo** → Review attachment reuse.
* **UrlClickEvents** → Determine whether users interacted.

### Remediation Considerations

Potential response actions:

* Purge messages using the malicious subject.
* Create temporary transport or detection rules.
* Block associated domains and URLs.
* Notify impacted users.
* Investigate identity compromise if users interacted.

### Detection Engineering Notes

This query can generate false positives for legitimate mass communications.

Common exclusions may include:

* Internal announcements.
* Approved vendors.
* Automated business notifications.

Consider combining this detection with:

* New sender domains.
* URL reputation.
* Attachment prevalence.
* Delivery status.

---

## Query 4 — Delivered Emails With Click Activity

**Category:** User Impact Validation
**Priority:** High
**Use Case:** Identify emails where users interacted with potentially malicious content.

### KQL Query

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

### How the KQL Works

This query correlates email telemetry with user click activity.

Key logic:

* `NetworkMessageId` acts as the unique correlation point between email delivery and URL interaction.
* `join kind=inner` returns only emails that have associated click activity.
* The result provides the full chain:

```
Email → User → URL → Interaction
```

This transforms a suspicious email into a confirmed user-impact event.

### Why It Matters

A delivered phishing email becomes significantly more important once a user clicks.

This query helps identify:

* Credential theft attempts.
* Malware download attempts.
* Users who require immediate response.
* Potential identity compromise.

### Investigation Pivots

Pivot into:

* **AccountUpn** → Review sign-in activity.
* **Url** → Investigate phishing infrastructure.
* **DeviceProcessEvents** → Identify payload execution.
* **AADSignInEvents / IdentityLogonEvents** → Look for suspicious authentication.
* **NetworkMessageId** → Identify all related recipients.

### Remediation Considerations

Immediate actions may include:

1. Reset affected user passwords.
2. Revoke active sessions.
3. Review MFA registration changes.
4. Investigate risky sign-ins.
5. Inspect endpoint activity.
6. Notify affected users.

### Detection Engineering Notes

This is one of the highest confidence email detections because it confirms user interaction.

Recommended operational path:

```
Hunt
 ↓
Alert
 ↓
Automated investigation
 ↓
Incident response workflow
```

False positives are generally low, making this a strong candidate for automated alerting.

---

## Query 5 — Malicious Attachment Campaigns

**Category:** Malware Analysis
**Use Case:** Identify malicious attachments that are distributed across multiple recipients.

### KQL Query

```kusto
EmailAttachmentInfo
| where Timestamp > ago(14d)
| summarize
    Recipients=dcount(RecipientEmailAddress)
    by SHA256
| where Recipients >= 5
| sort by Recipients desc
```

### How the KQL Works

This query identifies attachment hashes that appear across multiple email recipients.

Key logic:

* `SHA256` represents the unique file fingerprint.
* `dcount(RecipientEmailAddress)` determines how many unique users received the same file.
* A threshold of `>= 5` identifies files distributed broadly enough to indicate potential campaign activity.
* The 14-day lookback allows analysts to identify slower-moving malware campaigns.

Unlike filename-based hunting, SHA256 remains consistent even when attackers rename files.

### Why It Matters

Attackers frequently reuse the same malicious attachment across many messages.

Common examples include:

* Malware droppers
* Trojan installers
* Malicious Office documents
* Password-protected archives
* Fake invoices
* Fake resumes
* Weaponized PDF documents

A single malicious attachment sent to multiple users may indicate an active malware campaign.

### Investigation Pivots

Pivot into:

* **SHA256** → Search `DeviceProcessEvents` for execution activity.
* **EmailEvents** → Identify sender, delivery status, and recipients.
* **FileName** → Identify variations or social engineering themes.
* **SenderFromDomain** → Determine campaign infrastructure.
* **RecipientEmailAddress** → Determine impacted users.

### Remediation Considerations

Potential response actions:

* Block the file hash.
* Remove delivered emails containing the attachment.
* Isolate impacted devices.
* Review process execution and persistence.
* Investigate additional files dropped by the attachment.

### Detection Engineering Notes

This is a strong hunting query for malware campaigns and can be converted into a custom detection after validating expected attachment behavior.

Consider tuning:

* Recipient thresholds.
* Known internal file distributions.
* Approved vendor attachments.

---

## Query 6 — URL-Based Campaign Detection

**Category:** URL and Infrastructure Analysis
**Use Case:** Identify malicious or suspicious URL infrastructure used across multiple messages.

### KQL Query

```kusto
EmailUrlInfo
| where Timestamp > ago(14d)
| summarize
    Messages=dcount(NetworkMessageId)
    by UrlDomain
| sort by Messages desc
```

### How the KQL Works

This query identifies URL domains that appear repeatedly across email messages.

Key logic:

* `UrlDomain` identifies the infrastructure being referenced.
* `dcount(NetworkMessageId)` identifies how many unique messages contain the URL.
* Higher counts may indicate phishing campaigns or widespread malicious infrastructure.

This helps analysts identify the campaign infrastructure rather than focusing on individual emails.

### Why It Matters

Attackers often rotate sender addresses while continuing to reuse:

* Landing pages.
* Credential harvesting portals.
* Malware download sites.
* Redirect services.
* Fake cloud sharing pages.

Finding common URL infrastructure helps expose the broader campaign.

### Investigation Pivots

Pivot into:

* **UrlDomain** → Review all associated messages.
* **UrlClickEvents** → Determine whether users clicked.
* **SenderFromAddress** → Identify related senders.
* **NetworkMessageId** → Expand investigation scope.
* **RecipientEmailAddress** → Identify impacted users.

### Remediation Considerations

Potential response actions:

* Block malicious URLs or domains.
* Purge messages containing malicious links.
* Notify users who clicked.
* Investigate identity compromise.
* Monitor for future attempts using related infrastructure.

### Detection Engineering Notes

This query works well when combined with:

* First-seen domain detections.
* URL click telemetry.
* Sender reputation analysis.
* Subject reuse analysis.

---

## Query 7 — Internal Domain Spoofing

**Category:** Email Identity Abuse
**Use Case:** Identify messages attempting to appear as if they originate from the organization.

### KQL Query

```kusto
let MyDomain = "contoso.com";

EmailEvents
| where SenderFromDomain =~ MyDomain
| where SenderFromAddress !endswith MyDomain
```

### How the KQL Works

This query searches for messages where the sender domain claims to be your organization's domain, but the complete sender address does not match expected formatting.

Key logic:

* `SenderFromDomain` identifies the domain presented by the message.
* `SenderFromAddress` validates the complete sender identity.
* The exclusion identifies sender addresses that do not align with the expected organizational domain.

This can reveal spoofing attempts where attackers try to leverage organizational trust.

### Why It Matters

Internal impersonation attempts are common in:

* Executive impersonation.
* Finance fraud.
* Payroll redirection.
* Business email compromise.
* Credential theft campaigns.

Users are significantly more likely to trust messages that appear to originate from their own organization.

### Investigation Pivots

Pivot into:

* **SenderFromAddress** → Identify the spoofed identity.
* **RecipientEmailAddress** → Determine who was targeted.
* **Subject** → Identify the social engineering theme.
* **Authentication results** → Review SPF, DKIM, and DMARC outcomes when available.
* **ThreatTypes / DetectionMethods** → Review Defender classification.

### Remediation Considerations

Potential response actions:

* Block spoofing patterns.
* Strengthen SPF, DKIM, and DMARC policies.
* Enable or review anti-impersonation protections.
* Notify targeted users.
* Review whether similar messages reached other recipients.

### Detection Engineering Notes

This query should be customized with your organization's:

* Primary domains.
* Accepted aliases.
* Partner mail flows.
* Third-party sending services.

False positives may occur if legitimate external services are allowed to send on behalf of your domain.

---

## Query 8 — Spray-and-Pray Detection

**Category:** Broad Targeting Analysis
**Use Case:** Identify users receiving messages from a large number of unrelated sender domains.

### KQL Query

```kusto
EmailEvents
| summarize
    Domains=dcount(SenderFromDomain)
    by RecipientEmailAddress
| where Domains >= 10
```

### How the KQL Works

This query shifts the investigation focus from the attacker to the target.

Key logic:

* `RecipientEmailAddress` becomes the primary investigation point.
* `dcount(SenderFromDomain)` calculates how many unique domains have sent messages to that user.
* A high number of unrelated senders may indicate mass phishing targeting.

This is especially valuable for identifying users who are repeatedly targeted.

### Why It Matters

Threat actors often conduct broad campaigns against:

* Executives.
* Finance teams.
* Human Resources.
* IT administrators.
* Users with access to sensitive data.

Repeated targeting can indicate that an email address has been harvested, leaked, or identified as a high-value target.

### Investigation Pivots

Pivot into:

* **RecipientEmailAddress** → Review all messages targeting the user.
* **SenderFromDomain** → Identify recurring attacker infrastructure.
* **Subjects** → Identify common phishing themes.
* **UrlClickEvents** → Determine user interaction.
* **Identity telemetry** → Review risky sign-ins or compromise indicators.

### Remediation Considerations

Potential response actions:

* Increase monitoring of targeted users.
* Provide targeted security awareness.
* Review mailbox protections.
* Monitor for additional attacks.
* Investigate whether any prior messages resulted in compromise.

### Detection Engineering Notes

This is an excellent hunting query for identifying high-risk users.

Consider tuning:

* The domain threshold based on organization size.
* Executive and privileged user monitoring.
* Known marketing or external communication sources.

This query can also be combined with identity risk telemetry to prioritize users who have both high email exposure and suspicious authentication activity.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Business Email Compromise (BEC) Detection Engineering Framework

Modern Business Email Compromise (BEC) attacks frequently avoid traditional malware and malicious URLs. Instead, attackers abuse **identity, trust, and brand familiarity** to convince users to take action.

Examples include:

* Fake executives requesting urgent payments.
* Impersonated employees sending invoices.
* Consumer email accounts designed to look like legitimate users.
* Display names that mimic trusted identities.
* Lookalike domains that appear associated with the organization.

The following detections are designed as **detection engineering examples**. They should be tested, tuned, and validated before being promoted to production alerts or automated remediation actions.

Recommended lifecycle:

```
Hunt
 ↓
Alert
 ↓
Tune
 ↓
Validate
 ↓
Automate (Optional)
```

---

# Query 9 — Consumer Account Identity Impersonation

**Category:** Business Email Compromise (BEC)
**Use Case:** Detect consumer email accounts that attempt to impersonate employees, executives, or business functions.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection =~ "Inbound"

| extend SenderAddress = tolower(SenderFromAddress)
| extend SenderDomain = tolower(SenderFromDomain)
| extend SenderLocalPart = tostring(split(SenderAddress, "@")[0])

// Normalize identity by removing non-letter characters
| extend NormalizedSender = replace_regex(SenderLocalPart, @"[^a-z]", "")

// Consumer email providers
| where SenderDomain in~ (
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "rocketmail.com",
    "aol.com",
    "icloud.com",
    "me.com"
)

// Approved sender exceptions
| where SenderAddress !in~ (
    "approved.sender@gmail.com"
)

// Protected identities and business roles
| where NormalizedSender has_any (
    "firstnamelastname",
    "finance",
    "payroll",
    "accounting",
    "hr",
    "helpdesk",
    "ceo",
    "cfo",
    "administrator"
)

| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    ThreatTypes,
    DetectionMethods
| order by Timestamp desc
```

### How the KQL Works

This query identifies **consumer email addresses attempting to resemble trusted identities**.

The detection performs several steps:

1. Filters only inbound mail.
2. Restricts analysis to common consumer providers.
3. Extracts the sender identity before the `@` symbol.
4. Normalizes the identity by removing:

   * Periods
   * Dashes
   * Underscores
   * Numbers
   * Special characters

This allows a single identity pattern:

```
johnsmith
```

to detect variations such as:

```
john.smith@gmail.com
john-smith2026@yahoo.com
john_smith123@outlook.com
```

### Why It Matters

BEC actors commonly register free consumer accounts that appear legitimate at a glance.

A user may only see:

```
John Smith <john.smith2026@gmail.com>
```

and assume it is a legitimate communication.

This detection identifies attempts to abuse employee names, executives, or business functions.

### Investigation Pivots

Pivot into:

* **SenderFromAddress** → Identify all activity from the account.
* **SenderFromDomain** → Identify additional consumer accounts used.
* **RecipientEmailAddress** → Determine targeted users.
* **Subject** → Identify the social engineering theme.
* **DeliveryAction / DeliveryLocation** → Confirm whether the email reached the inbox.
* **ThreatTypes / DetectionMethods** → Review Defender's classification.

### Remediation Considerations

Potential response actions:

* Block the sender.
* Remove delivered messages.
* Notify targeted users.
* Review whether other impersonation attempts exist.

### Detection Engineering Notes

Recommended operational maturity:

```
Hunting
 ↓
Alert
 ↓
Tune identity lists
 ↓
Validate false positives
 ↓
Soft Delete (Optional)
```

Important tuning areas:

* Protected identities.
* Executive names.
* Finance and payroll aliases.
* Approved consumer senders.
* Journal or service accounts.

---

# Query 10 — Display Name Impersonation and Sender Mismatch

**Category:** Business Email Compromise (BEC)
**Use Case:** Detect emails where the display name claims to be a trusted identity, but the underlying sender address does not match expected identity patterns.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection =~ "Inbound"

| extend SenderAddress = tolower(SenderFromAddress)
| extend SenderDomain = tolower(SenderFromDomain)
| extend DisplayName = tolower(SenderDisplayName)

| extend NormalizedDisplayName =
    replace_regex(DisplayName, @"[^a-z]", "")

| extend NormalizedSender =
    replace_regex(
        tostring(split(SenderAddress, "@")[0]),
        @"[^a-z]",
        ""
    )

// Consumer providers
| where SenderDomain in~ (
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "aol.com",
    "icloud.com"
)

// Display name matches protected identities
| where NormalizedDisplayName has_any (
    "firstnamelastname",
    "ceo",
    "cfo",
    "finance",
    "payroll",
    "helpdesk"
)

// Sender does NOT match expected identity pattern
| where not(
    NormalizedSender has_any (
        "firstnamelastname",
        "finance",
        "payroll",
        "helpdesk"
    )
)

| project
    Timestamp,
    SenderDisplayName,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation
| order by Timestamp desc
```

### How the KQL Works

This detection compares two identities:

**Visible identity**

```
Display Name:
John Smith
```

versus

**Actual sender identity**

```
security-alerts123@gmail.com
```

The query normalizes both values and determines whether:

* The display name matches a protected identity.
* The actual sender does not align with expected naming conventions.

### Why It Matters

Many users trust the display name rather than the sender address.

This technique is extremely common in:

* Executive impersonation.
* Payment fraud.
* Payroll scams.
* Fake internal requests.

### Investigation Pivots

* Review other messages using the same display name.
* Identify all targeted users.
* Review similar consumer domains.
* Investigate user responses.
* Review mailbox actions and replies.

### Remediation Considerations

* Remove malicious messages.
* Warn targeted users.
* Strengthen impersonation policies.
* Add detections for recurring patterns.

### Detection Engineering Notes

This detection should typically begin as:

```
Hunting → Alert → Tune → Automate
```

Pay close attention to:

* Legitimate external contacts.
* Vendors using personal email accounts.
* Shared business aliases.

---

# Query 11 — Corporate Lookalike Domain Impersonation

**Category:** Business Email Compromise (BEC)
**Use Case:** Detect external domains attempting to impersonate the organization, brand, executives, or business functions.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection =~ "Inbound"

| extend SenderAddress = tolower(SenderFromAddress)
| extend SenderDomain = tolower(SenderFromDomain)
| extend SenderLocalPart = tostring(split(SenderAddress, "@")[0])

// Normalize sender identity
| extend NormalizedSender =
    replace_regex(SenderLocalPart, @"[^a-z]", "")

// Exclude approved corporate domains
| where SenderDomain !in~ (
    "contoso.com",
    "trustedpartner.com"
)

// Domains attempting to resemble your organization
| where SenderDomain has_any (
    "contoso",
    "companyname",
    "brandname"
)

// Protected identities and business roles
| where NormalizedSender has_any (
    "ceo",
    "cfo",
    "finance",
    "payroll",
    "helpdesk",
    "firstnamelastname"
)

| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    ThreatTypes,
    DetectionMethods
| order by Timestamp desc
```

### How the KQL Works

This query identifies external domains that attempt to abuse organizational trust.

The detection performs several checks:

1. Excludes known trusted domains.
2. Searches for domains containing company or brand references.
3. Normalizes the sender identity.
4. Compares the sender identity against protected users and business functions.

Example:

**Legitimate domain:**

```
ceo@contoso.com
```

**Potential impersonation:**

```
ceo@contoso-security.com
finance@contoso-support.com
john.smith@contoso-helpdesk.net
```

### Why It Matters

Domain impersonation is commonly used in:

* Executive fraud.
* Wire transfer scams.
* Vendor payment fraud.
* Payroll manipulation.
* Sensitive data requests.

Unlike simple spoofing, attackers register legitimate domains designed to appear trustworthy.

### Investigation Pivots

Pivot into:

* **SenderFromDomain** → Identify additional emails from the infrastructure.
* **SenderFromAddress** → Review identities being impersonated.
* **RecipientEmailAddress** → Determine targeted users or departments.
* **Subject** → Identify social engineering themes.
* **ThreatTypes / DetectionMethods** → Review Defender verdicts.

### Remediation Considerations

* Block the impersonating domain.
* Purge delivered messages.
* Notify impacted users.
* Review whether additional lookalike domains exist.
* Strengthen anti-impersonation policies.

### Detection Engineering Notes

Recommended maturity path:

```
Hunt
 ↓
Alert
 ↓
Tune approved domains
 ↓
Validate false positives
 ↓
Optional automated response
```

Important tuning areas:

* Corporate domains.
* Subsidiary domains.
* Trusted partners.
* Vendor domains.
* Executive identities.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Advanced Email Threat Hunting

The following detections expand coverage beyond traditional phishing by focusing on modern social engineering techniques, emerging attack trends, and advanced campaign behavior.

---

# Query 12 — QR Phishing (Quishing) Detection

**Category:** Emerging Threats
**Use Case:** Identify suspicious messages containing QR-code themed attachments.

### KQL Query

```kusto
EmailAttachmentInfo
| where Timestamp >= ago(14d)
| where FileName has_any (
    "qr",
    "scan",
    "invoice",
    "payment",
    "authentication",
    "verify"
)
or FileType in~ (
    "png",
    "jpg",
    "jpeg",
    "gif",
    "pdf"
)
| summarize
    Messages=dcount(NetworkMessageId),
    Recipients=dcount(RecipientEmailAddress)
    by FileName, FileType, SHA256
| where Recipients >= 3
| sort by Recipients desc
```

### How the KQL Works

QR phishing often avoids traditional URL scanning by placing malicious links inside:

* Images.
* PDF documents.
* Invoice attachments.
* Authentication-themed documents.

This query identifies attachments commonly associated with QR phishing campaigns.

It measures:

* How many messages contained the attachment.
* How many users received it.
* Whether the same file hash was reused.

### Why It Matters

Modern phishing campaigns increasingly use QR codes to:

* Bypass URL inspection.
* Move the attack to a mobile device.
* Circumvent browser protections.
* Harvest credentials.

Common themes include:

* Microsoft 365 authentication.
* Secure document viewing.
* Invoice approval.
* Account verification.

### Investigation Pivots

Pivot into:

* **SHA256** → Search for additional occurrences.
* **FileName** → Identify similar lures.
* **RecipientEmailAddress** → Identify impacted users.
* **SenderFromDomain** → Identify campaign infrastructure.

### Remediation Considerations

* Remove malicious emails.
* Block known attachment hashes.
* Educate targeted users.
* Review whether users authenticated after scanning.

### Detection Engineering Notes

This detection is intentionally broad.

Recommended tuning:

* Exclude trusted document workflows.
* Add known business applications.
* Tune attachment names and recipient thresholds.

---

# Query 13 — Callback Phishing / TOAD Detection

**Category:** Social Engineering
**Use Case:** Identify telephone-oriented phishing attacks that convince users to call an attacker-controlled phone number.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(14d)
| where Subject has_any (
    "invoice",
    "subscription",
    "renewal",
    "payment",
    "charge",
    "refund",
    "support",
    "receipt"
)
| where Subject has_any (
    "call",
    "phone",
    "contact",
    "support",
    "helpdesk"
)
| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    NetworkMessageId
| sort by Timestamp desc
```

### How the KQL Works

Callback phishing (also known as TOAD — Telephone-Oriented Attack Delivery) relies on convincing the victim to initiate contact with the attacker.

Unlike traditional phishing:

* There may be no malicious URL.
* There may be no attachment.
* The phone conversation becomes the attack vector.

This query searches for common social engineering language involving:

* Billing.
* Payments.
* Renewals.
* Refunds.
* Technical support.

### Why It Matters

TOAD campaigns frequently target:

* Finance departments.
* Executives.
* Procurement teams.
* Users with purchasing authority.

Attackers use urgency and fear to bypass technical controls.

### Investigation Pivots

* Review similar subject lines.
* Identify other recipients.
* Investigate the sender infrastructure.
* Review whether users contacted the provided number.

### Remediation Considerations

* Remove confirmed malicious messages.
* Notify affected users.
* Alert finance or procurement teams.
* Add awareness training scenarios.

### Detection Engineering Notes

This query may produce false positives due to legitimate billing emails.

Recommended tuning:

* Exclude known vendors.
* Tune keywords based on business processes.
* Combine with first-seen sender analysis.

---

# Query 14 — High-Risk Emails Delivered to Inbox

**Category:** Risk Validation
**Use Case:** Identify emails that Defender classified as suspicious but still reached a user's inbox.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryLocation =~ "Inbox"
    or DeliveryAction =~ "Delivered"
| where ThreatTypes has_any (
    "Phish",
    "Malware",
    "Spam"
)
or DetectionMethods has_any (
    "Phish",
    "Malware",
    "Spoof"
)
| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    DeliveryAction,
    DeliveryLocation,
    NetworkMessageId
| order by Timestamp desc
```

### How the KQL Works

This query focuses on the highest-priority scenario: a message that contains suspicious characteristics but still reached the end user.

The detection evaluates:

* Delivery outcome using `DeliveryAction` and `DeliveryLocation`.
* Microsoft Defender classification using `ThreatTypes`.
* Detection confidence and techniques using `DetectionMethods`.

This allows analysts to identify situations where:

* The message was allowed.
* The message was delivered due to policy configuration.
* The message was not classified strongly enough for automatic remediation.

### Why It Matters

A suspicious message that reaches the inbox represents a potential failure point in the email protection chain.

Common scenarios include:

* Newly emerging phishing campaigns.
* Sophisticated BEC attempts.
* Low-confidence phishing detections.
* Messages allowed due to policy exceptions.

### Investigation Pivots

Pivot into:

* **NetworkMessageId** → Review the complete email history.
* **SenderFromAddress** → Identify additional messages.
* **SenderFromDomain** → Investigate attacker infrastructure.
* **RecipientEmailAddress** → Determine impacted users.
* **UrlClickEvents** → Determine user interaction.
* **DeviceProcessEvents** → Investigate payload execution.

### Remediation Considerations

* Remove delivered messages.
* Review Safe Links and Safe Attachments configuration.
* Investigate user interaction.
* Notify impacted users.
* Review why the message bypassed expected controls.

### Detection Engineering Notes

This is a high-confidence detection candidate because it combines:

* Delivery confirmation.
* Existing Defender suspicion.
* Potential user exposure.

Recommended lifecycle:

```
Hunting
    ↓
Alert
    ↓
Automated Investigation
    ↓
Optional Automated Remediation
```

---

# Query 15 — First-Seen Sender Domain Detection

**Category:** Infrastructure Analysis
**Use Case:** Identify newly observed sender domains targeting users.

### KQL Query

```kusto
let RecentDomains =
EmailEvents
| where Timestamp >= ago(1d)
| summarize
    RecentRecipients=dcount(RecipientEmailAddress)
    by SenderFromDomain;

let HistoricalDomains =
EmailEvents
| where Timestamp between (ago(30d) .. ago(2d))
| summarize
    by SenderFromDomain;

RecentDomains
| join kind=leftanti HistoricalDomains on SenderFromDomain
| where RecentRecipients >= 5
| order by RecentRecipients desc
```

### How the KQL Works

This detection compares recent email activity against historical communication patterns.

The logic:

* Builds a list of domains seen in the last 24 hours.
* Builds a historical baseline from the previous month.
* Uses `leftanti` join to identify domains that did not previously exist.
* Prioritizes domains targeting multiple recipients.

This creates a "first-seen sender" capability without requiring external reputation services.

### Why It Matters

Attackers frequently rotate infrastructure to avoid reputation-based blocking.

A first-seen domain may indicate:

* A new phishing campaign.
* A compromised vendor.
* A fake business relationship.
* A newly registered malicious domain.

### Investigation Pivots

Pivot into:

* **SenderFromDomain** → Review all associated messages.
* **SenderFromAddress** → Identify impersonated identities.
* **Subject** → Determine social engineering themes.
* **URLs and attachments** → Identify malicious content.
* **Recipients** → Identify targeted departments.

### Remediation Considerations

* Investigate before blocking.
* Verify unexpected business communications.
* Review domain reputation.
* Increase monitoring for additional messages.

### Detection Engineering Notes

Because legitimate vendors may contact the organization for the first time, this detection requires tuning.

Recommended exclusions:

* Approved vendors.
* Known partner domains.
* Business onboarding processes.

---

# Query 16 — URL Clicks After Delivery and User Exposure

**Category:** User Impact Validation
**Priority:** Critical

**Use Case:** Identify users who clicked URLs contained within delivered emails.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryLocation =~ "Inbox"
    or DeliveryAction =~ "Delivered"
| project
    NetworkMessageId,
    RecipientEmailAddress,
    Subject,
    SenderFromAddress,
    DeliveryAction,
    DeliveryLocation
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(7d)
    | project
        ClickTime=Timestamp,
        AccountUpn,
        Url,
        ActionType,
        NetworkMessageId
) on NetworkMessageId
| project
    ClickTime,
    AccountUpn,
    RecipientEmailAddress,
    Subject,
    SenderFromAddress,
    Url,
    ActionType,
    DeliveryAction,
    DeliveryLocation
| order by ClickTime desc
```

### How the KQL Works

This expands upon traditional email investigation by confirming a complete attack chain:

```
Email Delivered
       ↓
User Clicked URL
       ↓
Potential Credential or Malware Exposure
```

The `inner join` ensures only messages with confirmed click activity are returned.

### Why It Matters

This represents one of the highest-priority scenarios in email security because user interaction has occurred.

Potential outcomes include:

* Credential theft.
* Session theft.
* Malware downloads.
* OAuth consent abuse.
* Redirection to attacker-controlled infrastructure.

### Investigation Pivots

Pivot into:

* **AccountUpn** → Review authentication activity.
* **AADSignInEvents** → Investigate suspicious sign-ins.
* **IdentityLogonEvents** → Review identity risk indicators.
* **DeviceProcessEvents** → Identify execution activity.
* **URL reputation** → Determine campaign infrastructure.

### Remediation Considerations

Immediate actions may include:

1. Reset credentials.
2. Revoke active sessions.
3. Review MFA registrations.
4. Investigate endpoint activity.
5. Validate account compromise.

### Detection Engineering Notes

This is an excellent candidate for:

* High-severity alerts.
* Automated investigations.
* Incident creation.

---

# Query 17 — Shared URL Infrastructure Across Multiple Senders

**Category:** Campaign Correlation
**Use Case:** Identify phishing infrastructure reused by multiple sender identities.

### KQL Query

```kusto
EmailUrlInfo
| where Timestamp >= ago(14d)
| summarize
    MessageCount=dcount(NetworkMessageId),
    SenderCount=dcount(SenderFromAddress),
    RecipientCount=dcount(RecipientEmailAddress)
    by Url, UrlDomain
| where SenderCount >= 3
    or RecipientCount >= 10
| order by RecipientCount desc
```

### How the KQL Works

Attackers often rotate sender accounts while continuing to use the same phishing infrastructure.

This query identifies:

* URLs reused across multiple campaigns.
* Shared phishing portals.
* Common malicious infrastructure.

The query measures:

* Unique messages.
* Unique senders.
* Number of users targeted.

### Why It Matters

A single phishing URL appearing from multiple senders may indicate:

* Coordinated phishing campaigns.
* Automated phishing kits.
* Multiple compromised accounts being used for delivery.

### Investigation Pivots

Pivot into:

* **UrlDomain** → Identify related infrastructure.
* **SenderFromAddress** → Identify associated senders.
* **NetworkMessageId** → Expand investigation scope.
* **UrlClickEvents** → Determine user impact.

### Remediation Considerations

* Block malicious URLs.
* Remove associated emails.
* Notify impacted users.
* Investigate successful interactions.

### Detection Engineering Notes

This detection works especially well when combined with:

* First-seen sender domains.
* Subject reuse.
* Attachment reuse.
* User click telemetry.

It is a strong candidate for scheduled hunting and campaign monitoring.

---

# Query 18 — Attachment Filename Reuse and Campaign Correlation

**Category:** Malware Campaign Correlation
**Use Case:** Identify attachment names that are repeatedly used across multiple sender identities or recipients.

### KQL Query

```kusto
EmailAttachmentInfo
| where Timestamp >= ago(14d)
| summarize
    MessageCount=dcount(NetworkMessageId),
    SenderCount=dcount(SenderFromAddress),
    RecipientCount=dcount(RecipientEmailAddress),
    HashCount=dcount(SHA256)
    by FileName
| where SenderCount >= 3
    or RecipientCount >= 10
| order by RecipientCount desc
```

### How the KQL Works

Attackers frequently reuse convincing attachment names while changing infrastructure.

Examples include:

* `Invoice_2026.pdf`
* `Payroll_Adjustment.xlsx`
* `Updated_Benefits_Document.docx`
* `Secure_Document.zip`

The query:

* Groups messages by `FileName`.
* Calculates how many unique messages contained the file name.
* Determines how many different senders used the same attachment name.
* Identifies how many recipients were targeted.
* Measures whether multiple hashes are associated with the same lure.

This helps identify situations where attackers change the file contents but maintain the same social engineering theme.

### Why It Matters

Threat actors commonly rotate:

* Sender addresses.
* Sending domains.
* Attachment hashes.

However, they often continue to reuse successful lure names.

This detection can uncover:

* Malware campaigns.
* Invoice fraud.
* Fake HR documents.
* Credential harvesting attachments.
* Business email compromise lures.

### Investigation Pivots

Pivot into:

* **FileName** → Identify similar campaigns.
* **SHA256** → Determine whether files executed on endpoints.
* **SenderFromAddress** → Identify related attackers.
* **SenderFromDomain** → Investigate infrastructure.
* **RecipientEmailAddress** → Determine affected users.
* **DeviceProcessEvents** → Validate execution.

### Remediation Considerations

* Block malicious file hashes.
* Remove related messages.
* Isolate impacted devices.
* Review execution chains.
* Notify affected users.

### Detection Engineering Notes

This query is most effective when combined with:

* SHA256 analysis.
* Sender reputation.
* URL investigation.
* User interaction telemetry.

It is useful for campaign correlation and threat hunting but may require tuning for common business document names.

---

# Query 19 — Reply Chain / Conversation Hijacking Detection

**Category:** Business Email Compromise (BEC)
**Use Case:** Identify suspicious attempts to abuse existing email conversations by using reply or forwarded message themes.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(14d)
| where Subject startswith "RE:"
    or Subject startswith "FW:"
| where SenderFromDomain !endswith "yourdomain.com"
| summarize
    Messages=count(),
    TargetedUsers=dcount(RecipientEmailAddress)
    by SenderFromAddress,
       SenderFromDomain,
       Subject
| where TargetedUsers >= 3
| order by TargetedUsers desc
```

### How the KQL Works

Conversation hijacking relies on trust and familiarity.

Attackers frequently use:

* `RE: Previous Conversation`
* `FW: Updated Invoice`
* `RE: Payment Confirmation`

The query identifies:

* External senders using reply or forward subjects.
* Repeated targeting across multiple users.
* Potential conversation-based social engineering.

### Why It Matters

Thread hijacking is often more convincing than standard phishing because users assume:

* The conversation already exists.
* The sender is known.
* The request is part of normal business activity.

These attacks are frequently associated with:

* Business email compromise.
* Invoice fraud.
* Credential theft.
* Malware delivery.

### Investigation Pivots

Pivot into:

* **Subject** → Review similar conversation lures.
* **SenderFromAddress** → Determine campaign scope.
* **SenderFromDomain** → Review reputation and history.
* **RecipientEmailAddress** → Identify targeted departments.
* **URLs and Attachments** → Investigate payloads.
* **User responses** → Determine whether the conversation continued.

### Remediation Considerations

* Remove confirmed malicious emails.
* Block malicious domains.
* Warn affected users.
* Review mailbox rules.
* Investigate possible account compromise if legitimate threads were abused.

### Detection Engineering Notes

This detection requires tuning.

Consider exclusions for:

* Known external partners.
* Vendor communications.
* Ongoing legitimate email threads.

Combining this query with:

* First-seen domains.
* URL analysis.
* Attachment analysis.
* BEC identity detections.

will significantly improve confidence.

---

# Query 20 — High-Value Business Function Targeting

**Category:** Targeted Attack Detection
**Use Case:** Identify external emails targeting sensitive business functions that are frequently targeted in fraud campaigns.

### KQL Query

```kusto
EmailEvents
| where Timestamp >= ago(7d)
| where EmailDirection =~ "Inbound"
| where RecipientEmailAddress has_any (
    "finance",
    "payroll",
    "accounting",
    "hr",
    "executive",
    "ceo",
    "cfo",
    "administrator",
    "it"
)
| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    ThreatTypes,
    DetectionMethods,
    NetworkMessageId
| order by Timestamp desc
```

### How the KQL Works

Certain users and departments are disproportionately targeted by attackers.

The query identifies inbound messages sent to addresses associated with:

* Finance.
* Payroll.
* Human Resources.
* Executives.
* IT administrators.
* Privileged business functions.

This provides focused visibility into users who are more likely to receive:

* Payment fraud requests.
* Credential phishing.
* Executive impersonation.
* Vendor compromise attempts.

### Why It Matters

Not all users carry the same level of business risk.

A single suspicious message sent to:

* `ceo@company.com`
* `finance@company.com`
* `payroll@company.com`

may require a higher priority response than a broad phishing message sent to many general users.

### Investigation Pivots

Pivot into:

* **RecipientEmailAddress** → Review historical targeting.
* **SenderFromAddress** → Investigate previous interactions.
* **SenderFromDomain** → Determine whether it is new or suspicious.
* **ThreatTypes / DetectionMethods** → Review existing Defender classifications.
* **URLs and Attachments** → Evaluate malicious content.

### Remediation Considerations

* Increase monitoring for targeted users.
* Apply additional email protections.
* Review impersonation policies.
* Notify sensitive business units.
* Validate unusual requests through alternate communication channels.

### Detection Engineering Notes

This query works especially well when combined with:

* BEC impersonation detections.
* First-seen sender domain detection.
* Delivered high-risk email detection.
* User click telemetry.

Consider maintaining a custom list of:

* Executive accounts.
* Finance personnel.
* Privileged administrators.
* Shared business mailboxes.

This allows the detection to align with organizational risk.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 🔎 Email Investigation & Validation Framework

Effective email investigations should move beyond identifying a single suspicious message. Analysts should determine:

1. **Was the email part of a larger campaign?**
2. **Did the email reach the intended user?**
3. **Did the user interact with the message?**
4. **Did any malicious activity occur after interaction?**
5. **Was identity, endpoint, or business risk introduced?**
6. **Does the activity justify a new detection or control improvement?**

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Investigation Pivot Workflow

## Phase 1 — Email Identification

Start with the original message and establish scope.

Primary pivots:

* NetworkMessageId
* SenderFromAddress
* SenderFromDomain
* SenderDisplayName
* Subject
* DeliveryAction
* DeliveryLocation

Key questions:

* Was the message delivered?
* How many users received it?
* Is the sender associated with previous activity?
* Is this part of a broader campaign?

---

## Phase 2 — URL Investigation

Review malicious infrastructure and user interaction.

Primary pivots:

* Url
* UrlDomain
* UrlClickEvents
* Click timestamp
* User identity

Key questions:

* Did users click the URL?
* Did the URL redirect to another destination?
* Was the infrastructure reused across multiple campaigns?
* Is the domain newly observed?

---

## Phase 3 — Attachment Investigation

Determine whether malicious files were delivered or executed.

Primary pivots:

* SHA256
* FileName
* FileType
* DeviceProcessEvents

Key questions:

* Was the attachment reused?
* Did the file execute on a device?
* Did it create additional files or processes?
* Is persistence present?

---

## Phase 4 — Identity Investigation

Determine whether the email resulted in account compromise.

Primary pivots:

* AccountUPN
* AADSignInEvents
* IdentityLogonEvents
* Identity protection alerts
* Risk detections

Key questions:

* Did the user authenticate from unusual locations?
* Were new devices registered?
* Was MFA changed or manipulated?
* Are there signs of session theft?

---

## Phase 5 — Endpoint Investigation

Determine whether the attack progressed beyond email.

Primary pivots:

* DeviceProcessEvents
* DeviceNetworkEvents
* DeviceFileEvents
* SecurityAlert
* AlertEvidence

Key questions:

* Was malware executed?
* Did command and control activity occur?
* Was persistence established?
* Did the threat move laterally?

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 📧 Email Validation Workflow

Before remediation, validate the actual impact.

## Email Delivery Validation

Determine whether the email was:

* Delivered to Inbox
* Moved to Junk
* Quarantined
* Blocked
* Soft Deleted

Important fields:

* DeliveryAction
* DeliveryLocation

---

## User Interaction Validation

Determine whether a user:

* Clicked a URL
* Opened an attachment
* Executed malicious content
* Responded to a BEC request

Important sources:

* UrlClickEvents
* DeviceProcessEvents
* Mailbox investigation artifacts

---

## Identity Impact Validation

Determine whether the email led to:

* Credential theft
* Account takeover
* Suspicious sign-ins
* MFA abuse
* Token theft

Important sources:

* AADSignInEvents
* IdentityLogonEvents
* Risk detections
* Security alerts

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 🛡️ Remediation Playbooks

## Credential Phishing Response

Immediate actions:

1. Reset the affected user's password.
2. Revoke active sessions.
3. Review MFA registration and changes.
4. Investigate suspicious sign-ins.
5. Hunt for additional compromised accounts.
6. Remove related emails.

---

## Malware Attachment Response

Immediate actions:

1. Identify all recipients.
2. Block malicious hashes.
3. Isolate impacted devices.
4. Investigate execution chains.
5. Remove malicious messages.
6. Validate that persistence does not remain.

---

## Business Email Compromise (BEC) Response

Immediate actions:

1. Identify all targeted users.
2. Determine whether users responded.
3. Validate financial or sensitive requests.
4. Review mailbox forwarding rules.
5. Review OAuth consent grants.
6. Investigate unusual sign-ins.
7. Remove malicious messages.
8. Strengthen impersonation protection.

---

## Domain and Brand Impersonation Response

Immediate actions:

1. Block malicious domains.
2. Review lookalike infrastructure.
3. Update impersonation policies.
4. Notify targeted users.
5. Review external communication controls.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# ⚙️ Detection Tuning Guidance

A successful detection is not one that generates the most alerts — it is one that generates the most actionable alerts.

Tune detections using:

## Known Safe Senders

Maintain allow lists for:

* Approved vendors
* Business partners
* Third-party services
* Legitimate consumer accounts

---

## Expected Identity Patterns

Examples:

Corporate format:

```
firstname.lastname@company.com
```

Business aliases:

```
finance@company.com
payroll@company.com
support@company.com
```

Use expected patterns to exclude legitimate identities while continuing to detect:

* Consumer impersonation
* Lookalike domains
* Unexpected sender formats

---

## Environment-Specific Adjustments

Review:

* Message volume thresholds
* Recipient thresholds
* Trusted domains
* Executive identities
* Business functions
* Regional communication patterns

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 🔁 Detection Engineering Lifecycle

Every detection should progress through a controlled maturity model:

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

Examples of automation include:

* Creating Defender custom detections.
* Generating incidents.
* Triggering automated investigations.
* Soft deleting confirmed malicious messages.

Automation should only occur after repeated validation and tuning.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 🧬 MITRE ATT&CK Mapping

This playbook aligns with the following MITRE ATT&CK techniques:

| Technique | Description              |
| --------- | ------------------------ |
| T1566     | Phishing                 |
| T1566.001 | Spearphishing Attachment |
| T1566.002 | Spearphishing Link       |
| T1036     | Masquerading             |
| T1585     | Establish Accounts       |
| T1586     | Compromise Accounts      |
| T1078     | Valid Accounts           |
| T1098     | Account Manipulation     |
| T1204     | User Execution           |

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# 🔬 Future Research Areas

Email threats continuously evolve. Future detection engineering opportunities include:

* AI-generated phishing campaigns.
* Advanced QR phishing (Quishing).
* Callback phishing (TOAD) improvements.
* OAuth consent phishing.
* Vendor and supply-chain compromise.
* Thread hijacking enhancements.
* LLM-assisted phishing analysis.
* Automated campaign clustering.
* Machine learning–based anomaly detection.

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# ⚠️ Community Detection Engineering Disclaimer

The KQL queries and detection methodologies provided in this playbook are intended for:

* Security research.
* Threat hunting.
* Detection engineering.
* Lab validation.
* Environment-specific testing.

They are examples and should not be considered production-ready detections without proper validation.

Before converting any hunting query into an alert or automated response:

* Validate available telemetry.
* Tune thresholds.
* Review trusted senders and expected identity patterns.
* Assess false positives.
* Test operational impact.

Automated actions such as Soft Delete, quarantine, or blocking should only be enabled after sufficient testing and approval through your organization's security processes.

These examples are intended to complement existing security controls, including:

* Microsoft Defender for Office 365 anti-phishing protections.
* Mailbox Intelligence.
* User and domain impersonation protection.
* SPF, DKIM, and DMARC validation.
* Security Operations Center (SOC) procedures.

Threat actors continuously evolve their techniques. Detection engineering should be treated as a continuous lifecycle of:

Hunt → Validate → Tune → Improve → Automate

---

⬆️ [Return to Table of Contents](#table-of-contents)

---

# Closing Notes

Version 2.0 expands the original Email Attack Hunting Playbook into a complete Email Threat Hunting & Detection Engineering reference.

The goal is not simply to identify malicious emails, but to provide analysts with a repeatable methodology to:

* Detect campaigns.
* Validate impact.
* Pivot across Microsoft Defender XDR telemetry.
* Investigate identity and endpoint compromise.
* Improve organizational detections over time.

The strongest detections are not created once—they are continuously tested, tuned, validated, and improved.
---

⬆️ [Return to Table of Contents](#table-of-contents)

