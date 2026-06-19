# Changelog

All notable changes to the Email Threat Hunting and Detection Engineering Playbook will be documented in this file.

---

# Version 2.0 — 2026-06-19

## Major Release — Email Threat Hunting & Detection Engineering Expansion

Version 2.0 significantly expands the original Email Attack Hunting Playbook into a comprehensive email threat hunting and detection engineering reference for Microsoft Defender XDR and Microsoft Sentinel.

The original Version 1.0 methodology has been preserved and expanded with additional detection engineering guidance, modern email threat scenarios, and operational workflows.

---

## Added

### Business Email Compromise (BEC) Detection Engineering Framework

Added new identity-focused detections:

* **BEC-01 — Consumer Account Identity Impersonation**

  * Detects consumer email accounts attempting to impersonate employees, executives, and business functions.
  * Includes identity normalization techniques to identify variations using periods, dashes, underscores, numbers, and other character substitutions.

* **BEC-02 — Display Name Impersonation and Sender Mismatch**

  * Detects trusted display names where the underlying sender identity does not match expected patterns.

* **BEC-03 — Corporate Lookalike Domain Impersonation**

  * Detects external domains attempting to impersonate organizational brands and trusted identities.

---

### Advanced Email Threat Hunting

Added modern detection scenarios:

* QR Phishing (Quishing) detection
* Callback phishing / Telephone-Oriented Attack Delivery (TOAD)
* High-risk emails delivered to inboxes
* First-seen sender domain analysis
* URL click correlation after delivery
* Shared phishing infrastructure detection
* Attachment filename reuse analysis
* Conversation and reply-chain hijacking detection
* High-value business function targeting

---

### Detection Engineering Enhancements

Added:

* Detection lifecycle methodology:

  * Hunt
  * Alert
  * Tune
  * Validate
  * Automate

* Detection engineering notes for every query:

  * How the KQL works
  * Why the detection matters
  * Investigation pivots
  * Remediation considerations
  * Tuning recommendations

---

### Expanded Investigation Workflows

Added expanded guidance for:

* Email investigation
* URL analysis
* Attachment analysis
* Identity compromise validation
* Endpoint investigation
* Campaign scoping
* Blast radius analysis

---

### New Operational Guidance

Added:

* Detection tuning strategies
* Safe sender considerations
* Expected identity patterns
* Threshold tuning guidance
* Soft Delete readiness guidance
* Alert validation recommendations

---

### MITRE ATT&CK Alignment

Expanded mapping to include:

* T1566 — Phishing
* T1566.001 — Spearphishing Attachment
* T1566.002 — Spearphishing Link
* T1036 — Masquerading
* T1585 — Establish Accounts
* T1586 — Compromise Accounts
* T1078 — Valid Accounts
* T1098 — Account Manipulation
* T1204 — User Execution

---

## Preserved from Version 1.0

The following original content remains intact and has been enhanced:

* Sender volume campaign detection
* Multi-recipient targeting analysis
* Subject reuse analysis
* URL click investigation
* Attachment campaign analysis
* URL infrastructure analysis
* Internal domain spoofing analysis
* Spray-and-pray detection

---

## Version 1.0 — 2026-04-21

Initial release focused on practical email threat hunting workflows including:

* Email campaign identification
* URL investigation
* Attachment analysis
* User interaction validation
* Cross-domain investigation pivots
* Remediation workflows
* Security operations guidance

---

