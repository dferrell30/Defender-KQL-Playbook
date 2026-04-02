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

### 📸 Example Output

![Devices Reporting](../images/onboarding-validation.png)

```kusto
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform
| order by LastSeen desc
```
## Query Output Example


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

### 🛠️ Recommended Remediation

**High Confidence (malicious behavior confirmed)**
- isolate the device
- initiate full antivirus scan
- collect investigation package
- review all recent PowerShell activity on the device
- reset credentials for affected account

**Medium Confidence (needs validation)**
- review command line for legitimacy
- validate user activity
- monitor for repeated behavior
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

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device immediately
- investigate email source and attachments
- block sender/domain if malicious
- reset user credentials
- review lateral movement activity

**Medium Confidence**
- validate document source
- check for known macros or business use
- monitor device behavior
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

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device
- block remote IP/domain
- run antivirus scan
- review command-line execution chain
- investigate potential command-and-control activity

**Medium Confidence**
- validate destination IP/domain
- compare against known infrastructure
- monitor for repeated connections

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

### 🛠️ Recommended Remediation

**High Confidence**
- block IP/domain via Defender or firewall
- isolate affected device
- review all connections to the IP across environment
- investigate associated processes

**Medium Confidence**
- validate IP against threat intelligence
- monitor for repeated communication
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
---
### 🛠️ Recommended Remediation

**High Confidence**
- block suspicious port or destination
- isolate device if malicious activity confirmed
- investigate process using the port

**Medium Confidence**
- validate port usage against expected application behavior
- monitor for recurrence
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
---

### 🛠️ Recommended Remediation

**High Confidence**
- block suspicious port or destination
- isolate device if malicious activity confirmed
- investigate process using the port

**Medium Confidence**
- validate port usage against expected application behavior
- monitor for recurrence
---

# 📂 7. FILE ACTIVITY HUNTING

## Suspicious File Creation (Temp / Public Paths)

```kusto id="p9k3lz"
DeviceFileEvents
| where FolderPath has_any ("\\AppData\\Local\\Temp\\","\\Users\\Public\\","\\Windows\\Temp\\")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

### Table Used

DeviceFileEvents → File activity on endpoints

### What It Does

Finds files created in common attacker staging locations.

### When to Use

* malware staging detection
* post-execution investigation

### Normal vs Suspicious

* Normal: installers, temp files
* Suspicious: executables/scripts in temp directories

### Pivot

* process execution
* network activity
* file hash lookup

### Detection Potential

✅ Medium–High (needs filtering)
---
### 🛠️ Recommended Remediation

**High Confidence**
- isolate device
- delete malicious file
- run full antivirus scan
- review file origin and execution chain

**Medium Confidence**
- validate file legitimacy
- check file hash reputation
- monitor execution behavior
---

## Archive / Compression Activity

```kusto id="1d4y7p"
DeviceProcessEvents
| where FileName in~ ("7z.exe","winrar.exe","rar.exe","powershell.exe")
| where ProcessCommandLine has_any (".zip",".rar",".7z","Compress-Archive")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### What It Does

Detects file compression, often used before data exfiltration.

### When to Use

* insider risk
* data staging

### Suspicious

* large archive operations
* unusual directories

### Detection Potential

⚠️ Context dependent
---

### 🛠️ Recommended Remediation

**High Confidence**
- investigate files being archived
- check for sensitive data exposure
- review user intent and behavior
- restrict data access if needed

**Medium Confidence**
- validate business use case
- monitor for large or repeated archive activity
---

## Certutil Abuse (Download / Decode)

```kusto id="yq0xtp"
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","http")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

### What It Does

Detects abuse of certutil to download or decode payloads.

### Detection Potential

🔥 High
---

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device immediately
- block associated URL/IP
- investigate downloaded or decoded content
- review for additional payload execution

**Medium Confidence**
- validate usage against known admin activity
- monitor command usage patterns
---

# 🧪 8. ANOMALY HUNTING

## Rare Processes

```kusto id="d8ahvc"
DeviceProcessEvents
| summarize SeenCount = count() by FileName
| where SeenCount < 5
| order by SeenCount asc
```

### What It Does

Finds processes rarely seen across the environment.

### When to Use

* anomaly detection
* unknown binaries

### Suspicious

* uncommon executables

### Detection Potential

⚠️ Hunting only
---

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device
- analyze process binary
- check hash against threat intelligence
- review execution context

**Medium Confidence**
- validate process against known software inventory
- monitor for additional executions
---

## Unusual Low Activity Devices

```kusto id="l2vntp"
DeviceProcessEvents
| summarize ProcessCount = count() by DeviceName
| where ProcessCount < 10
```

### What It Does

Identifies devices with unusually low activity.

### Suspicious

* devices not reporting properly
* stealth activity

### Detection Potential

❌ No

### 🛠️ Recommended Remediation

- verify endpoint is active
- confirm Defender sensor health
- check connectivity and telemetry ingestion
- re-onboard device if needed
---

# 🔧 9. NOISE REDUCTION & ADVANCED FILTERING

## Exclude Known Accounts

```kusto id="3q5v8n"
| where AccountName !in~ ("admin","svc_account","automation_user")
```

### What It Does

Removes known expected activity.

### Impact

* reduces noise
* improves detection quality
---

### 🛠️ Purpose
These filters are used to reduce false positives and improve detection accuracy before creating alerts.
---

## Exclude Management Tools

```kusto id="6a2cnb"
| where InitiatingProcessCommandLine !has_any ("SCCM","Intune","CompanyPortal")
```

### What It Does

Filters enterprise management activity.

### Impact

🔥 Critical before production detections

---

# ⚙️ 10. DETECTION TUNING & WORKFLOW

## Before (Noisy Query)

```kusto id="k0x91v"
DeviceProcessEvents
| where FileName =~ "powershell.exe"
```

---

## After (Detection-Ready)

```kusto id="9yzp0e"
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
| where AccountName !in~ ("admin","svc_account")
| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, ProcessCommandLine
```

---

### What Changed

* added behavioral filters
* removed known noise
* preserved key fields

---

## When a Query Becomes a Detection

A query is ready when:

* results are consistent
* noise is minimized
* behavior is clearly suspicious

---

## Investigation Workflow

1. Validate device
2. Review processes
3. Check network
4. Analyze logons
5. Review alerts
6. Add identity context
7. Confirm threat

---

## Pivot Model

**Process → Network → Logon → Alerts → Identity → Email**

---

## Creating a Detection Rule

Steps:

1. Go to **security.microsoft.com**
2. Open **Advanced Hunting**
3. Run query
4. Validate results
5. Click **Create detection rule**
6. Configure:

   * severity
   * frequency
   * entities

---

## Recommended Automated Actions

### High Confidence

* isolate device
* run antivirus scan
* collect investigation package

### Medium Confidence

* monitor
* initiate investigation

---

# 🔥 Final Section Summary

* File → staging & payloads
* Anomaly → outliers
* Filtering → signal clarity
* Detection → operationalization

---

# 🧭 Final Insight

> This is no longer just a set of queries.
> This is a full operational detection framework.

# 🛡️ Custom Detection Creation (Defender XDR)

🎯 Goal

Turn validated KQL queries into automated detections and alerts.

🧭 Step-by-Step
1. Open Advanced Hunting

Go to:

👉 https://security.microsoft.com

Navigate:

Hunting → Advanced Hunting
2. Run Your Query
paste your KQL query
validate results
confirm:
low noise
consistent behavior
3. Create Detection Rule

Click:

👉 “Create detection rule”

⚙️ Recommended Settings
🔴 Severity
Scenario	Severity
Confirmed malicious (PowerShell, Office chain)	High
Suspicious but needs context	Medium
Validation / anomaly queries	Low or none
⏱️ Frequency
Use Case	Frequency
Active threats	Every 5–15 minutes
General monitoring	Hourly
Baseline/anomaly	Daily
📊 Lookback Period

Recommended:

24 hours for most detections
shorter for high-risk queries
👤 Entities (CRITICAL)

Always map:

Device
Account

Optional:

IP address
File hash

👉 This enables:

investigation graph
automated response
🤖 Automated Actions
🔥 High Confidence Detections
isolate device
run antivirus scan
collect investigation package
⚠️ Medium Confidence
trigger investigation
alert SOC team
monitor behavior
🚨 Example: PowerShell Detection

Use query:

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
| where AccountName !in~ ("admin","svc_account")

Recommended:

Severity: High
Frequency: 15 minutes
Action: isolate device

