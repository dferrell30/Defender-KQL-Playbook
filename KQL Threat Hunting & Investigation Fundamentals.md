# 🔎 KQL Threat Hunting & Investigation Fundamentals

![Version](https://img.shields.io/badge/Version-2.0-blue)
![Language](https://img.shields.io/badge/Language-KQL-purple)
![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_XDR-green)
![Focus](https://img.shields.io/badge/Focus-Threat_Hunting-orange)
![Status](https://img.shields.io/badge/Status-Community_Playbook-success)

---

# Version

* **Version:** 2.0
* **Last Updated:** 2026-06-19
* **Platforms:**

  * Microsoft Defender XDR
  * Microsoft Sentinel

---

# Purpose

This playbook is designed to teach security analysts, threat hunters, and detection engineers how to think through investigations using Kusto Query Language (KQL).

The objective is not to memorize queries. The objective is to understand how to follow attacker behavior through telemetry, correlate evidence, validate findings, and make informed security decisions.

KQL is not simply a search language.

It is an investigation language.

A successful investigation answers:

* What happened?
* Who was involved?
* What systems were affected?
* What was the impact?
* What evidence supports the conclusion?
* What action should be taken?

---

# The Threat Hunting Mindset

Many analysts begin with the question:

> "What KQL query should I run?"

A more effective approach is to ask:

> "What behavior am I trying to understand?"

Every investigation should follow a repeatable process:

```
Signal
   ↓
Entity
   ↓
Pivot
   ↓
Context
   ↓
Validation
   ↓
Decision
```

This prevents analysts from becoming dependent on individual queries and encourages evidence-driven investigations.

---

# Investigation Model

This playbook uses a simple investigation model:

```
Hunt
  ↓
Pivot
  ↓
Investigate
  ↓
Validate
  ↓
Decide
```

## Hunt

Identify suspicious activity, anomalies, alerts, or behaviors that require additional context.

Examples:

* A suspicious email
* A risky sign-in
* A malicious process
* A suspicious network connection
* An unusual file

---

## Pivot

Use entities to move between telemetry sources.

An investigation should not remain isolated in a single table.

For example:

```
Email
  ↓
User
  ↓
Identity
  ↓
Device
  ↓
Process
  ↓
Network
```

This allows analysts to understand the complete attack chain.

---

## Investigate

Collect additional evidence by expanding:

* Time ranges
* Related entities
* Historical behavior
* Associated users
* Related devices

The goal is to answer:

"Is this normal or abnormal?"

---

## Validate

Security tools provide signals. Analysts validate impact.

Validation includes:

* Was the activity actually successful?
* Did the user interact?
* Did malware execute?
* Did credentials get compromised?
* Did the attacker move laterally?

---

## Decide

Every investigation should end with an operational decision:

* No action required
* Continue monitoring
* Create a hunting query
* Develop a detection
* Initiate incident response

---

# Entity-Based Investigation Strategy

Modern Microsoft Defender XDR investigations are not table-based.

They are entity-based.

A table provides evidence.

An entity provides the path forward.

---

## Common Investigation Entities

| Entity      | Examples                 | Common Pivot Targets                          |
| ----------- | ------------------------ | --------------------------------------------- |
| User        | AccountUPN, AccountName  | Sign-ins, devices, emails, alerts             |
| Device      | DeviceName, DeviceId     | Processes, files, network, alerts             |
| IP Address  | IPAddress                | Sign-ins, network events, threat intelligence |
| Email       | NetworkMessageId         | URLs, attachments, recipients                 |
| URL/Domain  | Url, UrlDomain           | Email, clicks, network activity               |
| File        | SHA256, FileName         | Email attachments, execution, alerts          |
| Application | AppId, Service Principal | OAuth activity, consent, identity events      |

---

# Cross-Layer Investigation

Modern attacks rarely stay in one security layer.

A single investigation may move across:

* Defender for Office 365 (Email)
* Microsoft Entra ID (Identity)
* Defender for Endpoint (Device)
* Defender for Cloud Apps (Cloud)
* Microsoft Defender XDR (Correlated Signals)

Typical attack progression:

```
Email
 ↓
Credential Theft
 ↓
Suspicious Sign-In
 ↓
Device Access
 ↓
Process Execution
 ↓
Network Communication
```

Understanding this relationship is what transforms hunting into detection engineering.

---

# KQL Fundamentals for Security Investigations

KQL is more than a language for retrieving data. Effective defenders use KQL to reduce noise, identify abnormal behavior, correlate evidence, and build detections.

The following concepts represent the foundation of almost every Microsoft Defender XDR investigation.

---

# Time Scoping with `ago()`

## Purpose

Every investigation should begin with an appropriate time range.

Searching all available telemetry increases noise and decreases performance.

---

## KQL Example

```kusto
EmailEvents
| where Timestamp > ago(7d)
```

---

## How It Works

The `where` operator filters records that occurred within the previous seven days.

Common investigation windows:

| Time     | Use Case                                     |
| -------- | -------------------------------------------- |
| 1 hour   | Active incidents and live response           |
| 24 hours | New alerts and recent activity               |
| 7 days   | Initial threat hunting                       |
| 30 days  | Campaign and historical analysis             |
| 90+ days | Long-term trends and advanced investigations |

---

## Why It Matters

A properly scoped investigation:

* Reduces unnecessary data.
* Improves query performance.
* Focuses the analyst on relevant activity.

---

# Filtering with `where`

## Purpose

Filtering removes irrelevant activity and focuses the investigation on suspicious behavior.

---

## KQL Example

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
```

---

## How It Works

The `where` operator evaluates conditions and returns only matching records.

Examples include:

* Specific users.
* Devices.
* Commands.
* Domains.
* File names.
* IP addresses.

---

## Why It Matters

Most investigations begin with a simple question:

"What activity matches the behavior I am looking for?"

The `where` statement provides the first answer.

---

# Selecting Relevant Fields with `project`

## Purpose

Large Defender XDR tables contain hundreds of columns.

Analysts should reduce output to only the information needed.

---

## KQL Example

```kusto
DeviceNetworkEvents
| project Timestamp, DeviceName, RemoteIP, RemoteUrl
```

---

## How It Works

The `project` operator controls:

* Which fields appear.
* The order they appear.
* The overall readability of the results.

---

## Why It Matters

Clean results make investigations faster and easier to understand.

---

# Creating New Data with `extend`

## Purpose

Threat hunters often need to transform existing data into something easier to analyze.

---

## KQL Example

```kusto
EmailEvents
| extend SenderDomain =
    tostring(split(SenderFromAddress, "@")[1])
```

---

## How It Works

The `extend` operator creates new calculated fields.

Common uses:

* Extracting domains.
* Creating risk scores.
* Normalizing identities.
* Converting formats.
* Combining fields.

---

## Why It Matters

Many advanced detections rely on transforming raw telemetry into meaningful investigation data.

Example:

```
john.smith123@gmail.com
          ↓
johnsmith
```

This technique was used in the BEC detection engineering examples to identify identity variations.

---

# Sorting Results with `sort` and `order by`

## Purpose

Security analysts need to prioritize the most important findings.

---

## KQL Example

```kusto
DeviceProcessEvents
| sort by Timestamp desc
```

---

## How It Works

Sorting allows analysts to:

* View the newest events first.
* Identify highest counts.
* Prioritize suspicious activity.

---

## Why It Matters

The most recent event is often the most relevant during an active investigation.

---

# Limiting Results with `take`

## Purpose

Large datasets can return thousands or millions of records.

---

## KQL Example

```kusto
DeviceProcessEvents
| take 100
```

---

## How It Works

The `take` operator limits the number of records returned.

This is useful for:

* Testing queries.
* Exploring new tables.
* Reviewing samples.

---

## Why It Matters

Analysts should first understand the data before creating complex detections.

---

# Searching with `has`, `contains`, and `startswith`

## Purpose

Different search operators provide different levels of precision.

---

## KQL Examples

### Word-based matching

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
```

---

### Partial string matching

```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "powershell.exe -enc"
```

---

### Prefix matching

```kusto
EmailEvents
| where Subject startswith "RE:"
```

---

## Why It Matters

Choosing the wrong operator can cause:

* Missed detections.
* Excessive false positives.
* Slow queries.

Understanding operator behavior is critical for detection engineering.

---

# Investigation Tip

Do not begin by writing complex KQL.

Start simple:

```
What data exists?
        ↓
What behavior am I hunting?
        ↓
What fields identify that behavior?
        ↓
Can I filter or normalize the data?
        ↓
Can this become a reliable detection?
```

The best detection engineers start with simple observations and gradually build confidence through data.

---

# Advanced KQL for Detection Engineering

Simple queries identify events.

Advanced KQL identifies:

* Patterns
* Relationships
* Anomalies
* Campaigns
* Repeated attacker behavior

Detection engineering requires moving beyond individual events and understanding how activity connects over time.

---

# Aggregation with `summarize`

## Purpose

Security investigations often require understanding trends rather than individual records.

The `summarize` operator groups data and calculates statistics.

---

## KQL Example

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize MessageCount=count()
    by SenderFromDomain
| sort by MessageCount desc
```

---

## How It Works

This query:

* Groups all emails by sender domain.
* Counts the total messages from each domain.
* Identifies the most active senders.

---

## Why It Matters

Aggregation reveals:

* Phishing campaigns.
* Malware distribution.
* High-volume senders.
* Abnormal communication patterns.

This is the foundation of many hunting and detection scenarios.

---

# Counting vs Distinct Counting

## Purpose

Understanding the difference between total activity and unique entities is critical.

---

## `count()`

Counts every event.

Example:

```kusto
EmailEvents
| summarize TotalEmails=count()
    by SenderFromAddress
```

This answers:

> "How many emails did this sender send?"

---

## `dcount()`

Counts unique values.

Example:

```kusto
EmailEvents
| summarize UniqueRecipients=dcount(RecipientEmailAddress)
    by SenderFromAddress
```

This answers:

> "How many different users were targeted?"

---

## Why It Matters

Detection engineering often depends on **blast radius**.

Examples:

* One sender targeting 100 users.
* One URL appearing in 50 messages.
* One file executing on multiple devices.
* One user authenticating from many locations.

---

# Creating Context with `make_set()`

## Purpose

Investigators often need to see all related entities together.

---

## KQL Example

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize
    Targets=make_set(RecipientEmailAddress)
    by SenderFromAddress
```

---

## How It Works

Instead of only counting recipients, `make_set()` creates a list of the actual recipients.

Example output:

```
SenderFromAddress:
attacker@example.com

Targets:
[
 user1@contoso.com,
 user2@contoso.com,
 user3@contoso.com
]
```

---

## Why It Matters

Counts tell you the size of the incident.

Lists tell you who was impacted.

---

# Correlating Data with `join`

## Purpose

Real investigations rarely stay within a single table.

The `join` operator connects related telemetry.

---

## Common Join Types

| Join Type | Purpose                                                                         |
| --------- | ------------------------------------------------------------------------------- |
| inner     | Return records that exist in both datasets                                      |
| leftouter | Return all records from the first dataset plus matching records from the second |
| leftanti  | Return records that do not exist in another dataset                             |

---

# `inner` Join Example

## Scenario

Find delivered emails where users clicked a URL.

```kusto
EmailEvents
| project NetworkMessageId, RecipientEmailAddress, Subject
| join kind=inner (
    UrlClickEvents
    | project NetworkMessageId, AccountUpn, Url
) on NetworkMessageId
```

---

## Why It Matters

This creates a full attack chain:

```
Email
 ↓
User
 ↓
URL Interaction
```

This moves an investigation from:

"Was a phishing email delivered?"

to:

"Did a user interact with it?"

---

# `leftouter` Join Example

## Scenario

Show all suspicious emails and include click data if it exists.

```kusto
EmailEvents
| where ThreatTypes has "Phish"
| join kind=leftouter (
    UrlClickEvents
) on NetworkMessageId
```

---

## Why It Matters

The email remains visible even if nobody clicked.

This is useful for understanding:

* Exposure.
* Potential impact.
* User interaction.

---

# `leftanti` Join Example

## Purpose

Find new or unusual behavior by removing known historical activity.

---

## KQL Example

```kusto
let RecentDomains =
EmailEvents
| where Timestamp > ago(1d)
| summarize by SenderFromDomain;

let HistoricalDomains =
EmailEvents
| where Timestamp between (ago(30d)..ago(1d))
| summarize by SenderFromDomain;

RecentDomains
| join kind=leftanti HistoricalDomains
    on SenderFromDomain
```

---

## Why It Matters

`leftanti` is one of the most powerful hunting techniques.

It identifies:

* First-seen domains.
* New processes.
* New IP addresses.
* New applications.
* Unexpected users.

---

# Creating Reusable Logic with `let`

## Purpose

Complex detections often require reusable variables.

---

## KQL Example

```kusto
let HighValueUsers = dynamic([
    "ceo@contoso.com",
    "finance@contoso.com",
    "payroll@contoso.com"
]);

IdentityLogonEvents
| where AccountUpn in (HighValueUsers)
```

---

## Why It Matters

`let` statements make queries:

* Easier to read.
* Easier to maintain.
* Easier to tune.

They are heavily used in mature detection engineering.

---

# Dynamic Arrays

## Purpose

Dynamic arrays allow detections to compare activity against lists.

Common uses include:

* Protected users.
* Approved senders.
* Trusted domains.
* Known applications.
* Administrative accounts.

---

## Example

```kusto
let TrustedDomains = dynamic([
    "contoso.com",
    "trustedpartner.com"
]);

EmailEvents
| where SenderFromDomain !in (TrustedDomains)
```

---

## Why It Matters

Dynamic lists separate detection logic from organizational configuration.

Instead of changing the query logic, analysts only update the list.

This makes detections scalable.

---

# Regular Expressions and Normalization

## Purpose

Attackers frequently manipulate identities to avoid simple matching.

Examples:

```
john.smith@gmail.com
john-smith2026@gmail.com
john_smith_123@gmail.com
```

A simple comparison sees three different identities.

Normalization reveals:

```
johnsmith
```

---

## KQL Example

```kusto
EmailEvents
| extend NormalizedIdentity =
    replace_regex(
        tostring(split(SenderFromAddress, "@")[0]),
        @"[^a-z]",
        ""
    )
```

---

## Why It Matters

This technique is essential for:

* Business Email Compromise detection.
* Identity impersonation.
* Lookalike account analysis.
* Pattern matching.

---

# Performance Optimization

Good KQL should be accurate and efficient.

Follow these principles:

---

## Filter Early

Good:

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
```

Avoid:

```kusto
DeviceProcessEvents
| summarize count() by FileName
| where FileName =~ "powershell.exe"
```

---

## Reduce Columns

Use `project` to return only required fields.

---

## Use Appropriate Time Ranges

Do not search 180 days of telemetry when the investigation requires 24 hours.

---

## Test Before Automating

A query that works in hunting may not be suitable as a detection.

Before creating alerts:

* Review false positives.
* Validate telemetry.
* Understand normal business behavior.
* Tune exclusions and thresholds.

---

# Detection Engineering Mindset

The strongest detections are not built by searching for a single indicator.

They are created by combining:

```
Behavior
    +
Context
    +
Correlation
    +
Validation
```

The process is:

```
Hunt
 ↓
Identify Pattern
 ↓
Create Logic
 ↓
Tune Noise
 ↓
Validate Accuracy
 ↓
Deploy Detection
 ↓
Continuously Improve
```

This philosophy transforms KQL from a search language into a detection engineering platform.

---

The methodologies, KQL examples, and detection concepts included in this playbook are provided for:

- Security research
- Threat hunting
- Detection engineering education
- Lab validation
- Environment-specific testing

These examples are intended to demonstrate investigation and detection engineering concepts and should not be considered production-ready detections without proper validation and tuning.

Every organization has different:

- Telemetry availability
- Licensing and data retention
- Business workflows
- Trusted applications and services
- Normal user behavior
- Operational response requirements

Before converting hunting queries into production detections, organizations should:

- Validate data availability
- Tune thresholds and exclusions
- Review false-positive impact
- Test alerting workflows
- Validate response procedures

Effective detection engineering is a continuous process:

Hunt → Validate → Tune → Detect → Measure → Improve

---

⚠️ Platform, Telemetry, and Licensing Considerations

The KQL examples and investigation methodologies in this playbook are designed around Microsoft Defender XDR telemetry; however, data availability may vary based on licensing, product configuration, enabled capabilities, operating systems, and telemetry retention.

A successful query depends on the required telemetry being collected and available within the environment.

Microsoft Defender for Endpoint Licensing Considerations

Microsoft Defender for Endpoint capabilities differ between licensing tiers.

Defender for Endpoint Plan 1 (P1)

Typically provides foundational endpoint protection capabilities including:

Next-generation protection
Attack Surface Reduction (ASR) rules
Device control (platform dependent)
Basic security recommendations
Core endpoint telemetry availability

Limitations may include reduced access to advanced investigation and detection capabilities compared with higher licensing tiers.

Defender for Endpoint Plan 2 (P2)

Provides advanced detection and response capabilities including:

Endpoint Detection and Response (EDR)
Advanced Hunting
Automated Investigation and Response (AIR)
Threat and Vulnerability Management (TVM)
Advanced threat analytics and investigation workflows

Many advanced KQL hunting scenarios are designed around telemetry commonly associated with Defender for Endpoint Plan 2 capabilities.

Microsoft Defender for Business

Microsoft Defender for Business provides enterprise-grade endpoint protection designed for small and medium-sized organizations.

Capabilities may include:

Endpoint protection
Endpoint Detection and Response
Threat and Vulnerability Management
Automated Investigation and Response
Advanced Hunting capabilities (feature availability may vary by service evolution and licensing terms)

Organizations should validate available tables and telemetry within their tenant before implementing advanced hunting or custom detections.

Microsoft Defender XDR Service Availability

The presence of a table does not necessarily indicate complete coverage.

Examples:

DeviceProcessEvents requires endpoint telemetry.
DeviceNetworkEvents requires network telemetry collection.
EmailEvents requires Microsoft Defender for Office 365 email telemetry.
UrlClickEvents depends on Safe Links and applicable email protections.
Identity-related tables depend on Microsoft Entra ID and associated telemetry.
Cloud application telemetry requires applicable Microsoft Defender for Cloud Apps capabilities.
Data Retention and Historical Hunting

The ability to perform historical investigations depends on retention settings and licensing.

Examples:

A 90-day hunting query will not produce useful results if the environment only retains 30 days of relevant telemetry.
Long-term campaign analysis may require additional retention capabilities.

Always confirm the available retention period before designing scheduled hunts or detections.

Validation Before Operational Use

Before implementing a hunting query as a production detection:

Validate that required tables exist.
Confirm expected telemetry is being collected.
Understand product licensing limitations.
Test queries against known-good and known-bad scenarios.
Review false positives and environmental noise.
Confirm alerting and response workflows.

A successful detection is not determined only by KQL logic; it depends on the quality and availability of the underlying telemetry.



