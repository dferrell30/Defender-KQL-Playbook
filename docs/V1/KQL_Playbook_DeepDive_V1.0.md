KQL Playbook Deep Dive V1.0

⸻

🧭 Investigation Model

This playbook is built around a simple investigation model:

Hunt → Pivot → Investigate → Validate → Decide

Instead of asking:
“What queries should I run?”

The focus becomes:
“What is this behavior actually telling me?”

Each query should lead to a question.
Each question should lead to a pivot.
Each pivot should lead to clarity.

⸻

🔁 Entity Pivoting Strategy

Investigation in Defender XDR is not table-based. It is entity-based.

Primary pivot points:

* User (AccountUpn / AccountName)
* Device (DeviceName / DeviceId)
* IP Address
* URL / Domain
* Email Message ID

These allow movement across:

* Email (Defender for Office 365)
* Identity (Entra ID / Conditional Access)
* Endpoint (Defender for Endpoint)

The goal is to follow activity—not stay in one dataset.

⸻

🔗 Cross-Layer Correlation

Modern attacks do not stay in one layer.

Typical flow:

Email → Identity → Endpoint

KQL enables correlation across layers using shared entities.

Example: Email → Identity

EmailEvents
| where ThreatTypes has “Phish”
| join IdentityLogonEvents on AccountUpn
| project Timestamp, AccountUpn, IPAddress

Example: Identity → Endpoint

IdentityLogonEvents
| join DeviceProcessEvents on AccountName
| project Timestamp, AccountName, DeviceName, FileName

⸻

🔍 Hunting & Investigation Queries

⸻

📧 Suspicious Email Activity

What this is doing
Identifies phishing or malicious email delivery.

Query
EmailEvents
| where ThreatTypes has “Phish”
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes

Pivot

* UrlClickEvents
* IdentityLogonEvents

What to look for

* repeated targeting
* suspicious senders
* multiple impacted users

⸻

🔗 URL Click Activity

What this is doing
Determines whether a user interacted with a malicious link.

Query
UrlClickEvents
| project Timestamp, AccountUpn, Url, ActionType

Pivot

* IdentityLogonEvents
* DeviceEvents

What to look for

* successful clicks
* unknown domains
* timing correlation

⸻

🔐 Identity Sign-In Activity

What this is doing
Analyzes authentication patterns.

Query
IdentityLogonEvents
| project Timestamp, AccountUpn, IPAddress, Location, ResultType

Pivot

* DeviceProcessEvents
* additional sign-in events

What to look for

* impossible travel
* suspicious IPs
* failed → successful login chains

⸻

💻 Endpoint Process Activity

What this is doing
Identifies suspicious process execution.

Query
DeviceProcessEvents
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

Pivot

* DeviceNetworkEvents
* AlertInfo

What to look for

* abnormal processes
* suspicious command lines
* unexpected execution paths

⸻

🌐 Endpoint Network Activity

What this is doing
Analyzes outbound connections.

Query
DeviceNetworkEvents
| project Timestamp, DeviceName, RemoteIP, RemoteUrl

Pivot

* DeviceProcessEvents
* IdentityLogonEvents

What to look for

* unknown domains
* repeated connections
* correlation with processes

⸻

🚨 Alerts & Evidence

What this is doing
Surfaces Defender alerts and context.

Query
AlertInfo
| project Timestamp, Title, Severity, Category

Pivot

* AlertEvidence
* related user/device activity

What to look for

* high severity alerts
* repeated patterns
* alignment with observed behavior

⸻

🧪 Validation Layer

Deployment does not guarantee visibility.

Validation confirms what actually happened.

Key questions:

* Was the activity captured?
* Did expected signals appear?
* Were alerts triggered?
* Is anything missing?

Security tools often fail quietly.
Validation is how you detect that.

⸻

🎯 From Hunting to Detection

Hunting is not the end state.

When behavior becomes:

* repeatable
* reliable
* low noise

It should be turned into detection.

This allows:

* continuous monitoring
* faster response
* reduced manual investigation

Hunting finds behavior.
Detection operationalizes it.