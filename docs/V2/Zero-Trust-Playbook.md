# 🛡️ Zero Trust KQL Playbook (v2.0)

## 📘 Overview

This playbook provides a Zero Trust–aligned approach to threat detection and investigation using Kusto Query Language (KQL) across Microsoft Defender and Microsoft Entra.

It is designed to help defenders:

- detect identity-based threats  
- investigate endpoint activity  
- analyze network behavior  
- correlate signals across security layers

# 🔐 Identity (Entra)

## 🔐 Identity Overview

Identity telemetry provides visibility into authentication behavior, session activity, and access patterns.

This includes:

- sign-in activity  
- MFA challenges  
- token usage  
- risk signals  

---

## 📊 Identity Core Tables

### SigninLogs
Tracks authentication activity including:

- IP address  
- location  
- client app  
- risk level  

---

## 🔍 Identity Queries

---

## 🛡️ Zero Trust Alignment

This playbook is structured around core Zero Trust pillars:

- 🔐 Identity — authentication, access, and session security  
- 💻 Device — endpoint behavior and telemetry  
- 🌐 Network — communication and external connections  

---

## 🖼️ Zero Trust Model

![Zero Trust Model](../images/zero-trust-diagram.png)

> Zero Trust detection requires correlating signals across identity, device, and network.

# 🔐 Identity (Entra)

## 🔐 Identity Overview

Identity telemetry provides visibility into authentication behavior, session activity, and access patterns.

This includes:

- sign-in activity  
- MFA challenges  
- token usage  
- risk signals  

---

## 📊 Identity Core Tables

### SigninLogs
Tracks authentication activity including:

- IP address  
- location  
- client app  
- risk level  

---

## 🔍 Identity Queries

## 📌 Table of Contents

- [📘 Overview](#-overview)
- [🛡️ Zero Trust Alignment](#-zero-trust-alignment)
- [🖼️ Zero Trust Model](#-zero-trust-model)
- [🎯 Detection Strategy](#-detection-strategy)

---

## 🔐 Identity (Entra)

- [Overview](#-identity-overview)
- [Core Tables](#-identity-core-tables)

### 🔍 Identity Queries
- [Impossible Travel](#-impossible-travel)
- [Risky Sign-ins](#-risky-sign-ins)
- [MFA Fatigue](#-mfa-fatigue)
- [Legacy Authentication](#-legacy-authentication)
- [Token Reuse / Session Anomalies](#-token-reuse--session-anomalies)

### 🔎 Identity Investigation Workflows
- [Suspicious Sign-in](#-workflow-suspicious-sign-in--account-compromise)
- [Token Theft / Session Hijacking](#-workflow-token-theft--session-hijacking)
- [MFA Fatigue Attack](#-workflow-mfa-fatigue-attack)
- [Legacy Authentication Abuse](#-workflow-legacy-authentication-abuse)

---

## 💻 Device (Endpoint)

- [Overview](#-device-overview)
- [Core Tables](#-device-core-tables)

### 🔍 Device Queries

#### 🧱 Onboarding & Health
- [Devices Reporting](#-devices-reporting)
- [Stale Devices](#-stale-devices)

#### ⚠️ Threat Hunting
- [Suspicious PowerShell](#-suspicious-powershell)
- [Office → Script Execution](#-office--script-execution)

#### 🔐 Persistence
- [Registry Autoruns](#-registry-autorun-persistence)
- [Scheduled Tasks](#-scheduled-task-creation)
- [Service Creation](#-service-creation)

#### 🔑 Credential Abuse
- [Failed Logons](#-failed-logons)
- [Account Across Devices](#-account-across-multiple-devices)

#### 📂 File Activity
- [Suspicious File Creation](#-suspicious-file-creation)
- [Archive / Compression Activity](#-archive--compression-activity)
- [Certutil Abuse](#-certutil-abuse)

#### 🧪 Anomaly Hunting
- [Rare Processes](#-rare-processes)
- [Low Activity Devices](#-unusual-low-activity-devices)

---

## 🌐 Network

- [Overview](#-network-overview)
- [Core Tables](#-network-core-tables)

### 🔍 Network Queries
- [External Connections (Scripting Tools)](#-external-connections-from-scripting-tools)
- [Rare External IPs](#-rare-external-ips)
- [Unusual Port Usage](#-unusual-public-port-usage)

---

## 🔗 Cross-Pillar Correlation

- [Overview](#-cross-pillar-overview)

### 🔎 Correlation Workflows
- [Identity + Device](#-identity--device-correlation)
- [Device + Network](#-device--network-correlation)
- [Identity + Network](#-identity--network-correlation)

---

## 🔎 Investigation Workflows

- [Overview](#-investigation-workflows-overview)
- [Suspicious PowerShell Execution](#-investigation-workflow-suspicious-powershell-execution)
- [Defender Tampering](#-investigation-workflow-defender-tampering--defense-evasion)
- [Credential Access (LSASS)](#-investigation-workflow-credential-access-lsass--dumping)
- [Suspicious Process Chain](#-investigation-workflow-suspicious-process-chain)
- [Suspicious Network Activity](#-investigation-workflow-suspicious-network-activity)
- [Device Triage](#-investigation-workflow-device-triage-post-alert)

---

## ⚙️ Detection Engineering

- [Detection Strategy](#-detection-strategy)
- [Noise Reduction & Filtering](#-noise-reduction--advanced-filtering)
- [Query Tuning](#-detection-tuning--workflow)
- [Creating Detection Rules](#-creating-a-detection-rule)

---

## 📊 Expected Results

- [Overview](#-expected-results)

---

## 🧾 Closing Summary

- [Overview](#-closing-summary)
