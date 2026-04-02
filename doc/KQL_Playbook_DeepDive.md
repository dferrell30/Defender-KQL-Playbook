# 🔍 KQL Playbook Deep Dive

### Sections 1–3: Onboarding • Visibility • Threat Hunting

---

# 🧠 Core Principle

> Dashboards show the story. KQL shows the evidence.

---

# 📑 Table of Contents

* [1. Onboarding Validation](#-1-onboarding-validation)
* [2. Discovery & Visibility](#-2-discovery--visibility)
* [3. Threat Hunting](#-3-threat-hunting)

---

# 🔍 1. ONBOARDING VALIDATION

## Devices Reporting

```kusto
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform
| order by LastSeen desc
```

### Table Used

DeviceInfo → Device heartbeat and metadata

### What It Does

Finds the most recent reporting timestamp for each device.

### When to Use

* onboarding validation
* confirming device activity

### Normal vs Suspicious

* Normal: recent timestamps
* Suspicious: missing or delayed reporting

### Pivot

* process activity
* alerts

---

## Stale Devices

```kusto
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName
| where LastSeen < ago(7d)
```

### What It Does

Finds devices not reporting recently.

### When to Use

* onboarding gaps
* telemetry validation

### Suspicious

Active devices going silent.

---

# 📊 2. DISCOVERY & VISIBILITY

## Process Telemetry

```kusto
DeviceProcessEvents
| summarize count() by DeviceName
```

### What It Does

Confirms endpoint activity is being captured.

### Suspicious

Devices with very low activity.

---

## Alert Visibility

```kusto
DeviceAlertEvents
| summarize count() by DeviceName
```

### What It Does

Shows alert distribution across devices.

### Suspicious

Devices with no alerts despite activity.

---

# ⚠️ 3. THREAT HUNTING

## Suspicious PowerShell

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
```

### What It Does

Detects common attacker scripting patterns.

### Suspicious

Encoded commands, downloads.

---

## Office → Script Execution

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe")
```

### What It Does

Detects macro/phishing execution chains.

### Detection

🔥 Very High

---

# 🔥 Section Summary

* onboarding = validation
* visibility = confirmation
* hunting = detection

These three layers form the foundation of your KQL workflow.

