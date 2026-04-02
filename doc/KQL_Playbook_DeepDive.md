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
---

# 🔐 4. PERSISTENCE HUNTING

## Registry Autorun Persistence

```kusto
DeviceRegistryEvents
| where RegistryKey has_any (
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

### Table Used

DeviceRegistryEvents → Registry modification activity

### What It Does

Identifies changes to registry locations commonly used for persistence.

### When to Use

* post-compromise investigation
* persistence hunting

### Normal vs Suspicious

* Normal: known applications
* Suspicious: unknown binaries, scripts in temp paths

### Pivot

* process execution
* file creation
* user context

### Detection Potential

🔥 High (after filtering known apps)

---

## Scheduled Task Creation

```kusto
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create","-create")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

### Table Used

DeviceProcessEvents

### What It Does

Detects creation of scheduled tasks used for persistence or delayed execution.

### When to Use

* persistence detection
* attacker automation

### Normal vs Suspicious

* Normal: IT automation
* Suspicious: hidden or unusual task names

### Pivot

* parent process
* execution path
* logon activity

### Detection Potential

🔥 High

---

## Service Creation (Persistence / Privilege Abuse)

```kusto
DeviceProcessEvents
| where FileName in~ ("sc.exe","powershell.exe")
| where ProcessCommandLine has_any (" create ", "New-Service")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Table Used

DeviceProcessEvents

### What It Does

Detects creation of Windows services, often used for persistence or privilege escalation.

### When to Use

* post-exploitation
* persistence hunting

### Suspicious

* services pointing to temp paths
* unknown service names

### Pivot

* service binary
* process execution

### Detection Potential

🔥 High

---

# 🔑 5. CREDENTIAL & ACCOUNT ABUSE

## Failed Logons

```kusto
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedCount = count() by DeviceName, AccountName
| where FailedCount > 10
| order by FailedCount desc
```

### Table Used

DeviceLogonEvents → Authentication events

### What It Does

Identifies repeated failed logon attempts.

### When to Use

* brute force detection
* password spray

### Normal vs Suspicious

* Normal: occasional failures
* Suspicious: repeated attempts

### Pivot

* successful logons
* account activity

### Detection Potential

✅ Medium–High

---

## Account Across Multiple Devices

```kusto
DeviceLogonEvents
| summarize DeviceCount = dcount(DeviceName) by AccountName
| where DeviceCount > 5
| order by DeviceCount desc
```

### Table Used

DeviceLogonEvents

### What It Does

Finds accounts used across many devices.

### When to Use

* lateral movement detection
* shared credentials

### Normal vs Suspicious

* Normal: admin accounts
* Suspicious: standard users on many devices

### Pivot

* timeline analysis
* process activity

### Detection Potential

⚠️ Context dependent

---

# 🌐 6. NETWORK HUNTING

## External Connections from Scripting Tools

```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

### Table Used

DeviceNetworkEvents → Network connections

### What It Does

Identifies outbound connections from scripting or command-line tools.

### When to Use

* command and control detection
* suspicious downloads

### Normal vs Suspicious

* Normal: known infrastructure
* Suspicious: rare IPs, unusual behavior

### Pivot

* process command line
* rare IP analysis

### Detection Potential

🔥 High

---

## Rare External IPs

```kusto
DeviceNetworkEvents
| summarize DeviceCount = dcount(DeviceName) by RemoteIP
| where DeviceCount < 3
| order by DeviceCount asc
```

### Table Used

DeviceNetworkEvents

### What It Does

Finds IPs rarely seen across the environment.

### When to Use

* anomaly hunting
* threat intel pivot

### Suspicious

* uncommon external infrastructure

### Detection Potential

⚠️ Hunting query

---

## Unusual Public Port Usage

```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemotePort, InitiatingProcessFileName
| order by ConnectionCount asc
```

### Table Used

DeviceNetworkEvents

### What It Does

Identifies uncommon port usage patterns.

### When to Use

* anomaly detection
* C2 investigation

### Suspicious

* rare ports
* scripting tools using unusual ports

### Detection Potential

⚠️ Needs tuning

---

# 🔥 Section Summary

* Persistence → how attackers stay
* Identity → how attackers move
* Network → how attackers communicate

These layers start connecting behavior across the environment.



These three layers form the foundation of your KQL workflow.

