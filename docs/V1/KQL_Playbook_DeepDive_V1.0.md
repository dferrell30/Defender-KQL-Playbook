<h1 align="center">🛡️ Defender KQL Playbook</h1>

### 🔍 KQL Playbook Deep Dive Version 1.0

## 📌 Table of Contents

- [🧠 KQL Foundations](#-kql-foundations)
  - [🧱 Defender Data Model](#-defender-data-model)
  - [📊 Core Tables](#-core-tables)
  - [⚡ KQL Quick Cheat Sheet](#-kql-quick-cheat-sheet)
- [🔍 KQL Queries](#-KQL-Queries)

- [🚀 How to Use This Playbook](#-how-to-use-this-playbook)

- [🔎 Investigation Workflows](#-investigation-workflows)
  - [Suspicious PowerShell Execution](#-investigation-workflow-suspicious-powershell-execution)
  - [Defender Tampering / Defense Evasion](#-investigation-workflow-defender-tampering--defense-evasion)
  - [Credential Access (LSASS / Dumping)](#-investigation-workflow-credential-access-lsass--dumping)
  - [Suspicious Process Chain](#-investigation-workflow-suspicious-process-chain)
  - [Suspicious Network Activity](#-investigation-workflow-suspicious-network-activity)
  - [Device Triage (Post Alert)](#-investigation-workflow-device-triage-post-alert)

- [📊 Expected Results](#-expected-results)
- [🧾 Closing Summary](#-closing-summary)

---

## ⚠️ Disclaimer

For full disclaimer and usage terms, please refer to the main repository README:

➡️ [View Disclaimer](../README.md#️-disclaimer)

---

## 📄 License

This project is licensed under the MIT License.

For full license details, please refer to:

➡️ [View License](../LICENSE)

---

## 📘 Playbook Summary

This deep dive playbook provides a structured approach to using Kusto Query Language (KQL) within Microsoft Defender for Endpoint and Defender XDR for threat hunting and investigation.

Rather than presenting isolated queries, this playbook focuses on building a **repeatable investigation methodology** that enables defenders to:

- understand Defender telemetry and data relationships  
- use KQL to identify suspicious activity  
- pivot across process, network, file, and registry events  
- validate findings through structured investigation workflows  
- transition from reactive alert analysis to proactive hunting  

---

### 🎯 Key Objectives

This playbook is designed to help:

- standardize Defender hunting and investigation practices  
- reduce time to triage and validate suspicious activity  
- improve consistency in how KQL is used across investigations  
- bridge the gap between raw queries and real-world incident response  

---

### 🧠 What Makes This Different

Most KQL resources provide individual queries without context.

This playbook instead focuses on:

- **how to think during an investigation**  
- **how to pivot across Defender data sources**  
- **how to interpret results, not just generate them**  
- **how to apply queries in real-world scenarios**  

---

### 🔄 Investigation Approach

The methodology used throughout this playbook follows a consistent model:

---

## 🧠 How to Use This Playbook

This playbook is designed for:

- validating Defender telemetry  
- identifying visibility gaps  
- threat hunting  
- detection engineering  

Each query includes:
- what it does  
- when to use it  
- what to look for  
- recommended remediation  

Start with onboarding validation, then move into hunting and detection.

🔝 [Back to Table of Contents](#-table-of-contents)

## 🔄 Investigation Flow

Process → Network → Logon → Alerts → Identity → Email

---

# 🧠 Core Principle

> Dashboards show the story. KQL shows the evidence.

---

## 🧠 KQL Foundations

This section provides the foundational knowledge required to effectively use Kusto Query Language (KQL) within Microsoft Defender.

It is designed to help you understand:
- how Defender data is structured  
- which tables to use  
- how to write and interpret queries  
- key terminology used throughout this playbook

🔝 [Back to Table of Contents](#-table-of-contents)
  
---

### 🧱 Defender Data Model

Microsoft Defender stores telemetry across multiple tables that represent different types of activity on endpoints.

These tables are connected through common identifiers such as:

- DeviceId  
- Timestamp  
- AccountName  
- InitiatingProcess  

Understanding how these tables relate allows you to:

- correlate activity across multiple data sources  
- reconstruct attack chains  
- pivot between processes, network, and file activity

🔝 [Back to Table of Contents](#-table-of-contents)

---

# ⚡ KQL Quick Cheat Sheet

Common operators and patterns used throughout this playbook:

---

## 📊 Core Tables

The following tables are most commonly used in this playbook:

---

#### DeviceProcessEvents

Tracks process execution on endpoints.

Includes:
- process creation  
- parent-child relationships  
- command line arguments  
- execution context  

---

### DeviceNetworkEvents

Captures network activity initiated by processes.

Includes:
- remote IP address  
- domain name  
- protocol  
- initiating process  

---

### DeviceFileEvents

Tracks file system activity.

Includes:
- file creation  
- modification  
- deletion  

---

### DeviceRegistryEvents

Tracks registry changes.

Used for:
- persistence mechanisms  
- Defender configuration changes  
- tampering activity  

---

### DeviceLogonEvents

Captures authentication events.

Useful for:
- user activity tracking  
- lateral movement detection  
- credential misuse

🔝 [Back to Table of Contents](#-table-of-contents)

---

### 🔍 Filtering

```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
```

🔝 [Back to Table of Contents](#-table-of-contents)

 # 🔍 KQL-Queries

This section of the playbook contains KQL queries used for onboarding, threat hunting, and validation.

---

# 🔍 1. ONBOARDING VALIDATION AND HEALTH

## Devices Reporting

### 📸 Example Output

![Device Reporting](https://raw.githubusercontent.com/dferrell30/Defender-KQL-Playbook/main/images/DevicesReportingOutput.png)

### 📸 Example Output

```kusto
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform
| order by LastSeen desc
```

// Best practice endpoint configurations for Microsoft Defender for Endpoint deployment.

This query will be used to check device health, please note if Network Protection is disbled, check the endpoint state to see if it is in passive mode in the gui to confirm. If in passive recommend running the Microsoft Defender for Endpoint Client Analyzer either live session or local machine (elevated access) The Analyzer can be found here https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows

```Kusto
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003", "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId
| extend Test = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed) by DeviceId
| evaluate bag_unpack(Tests)
```

### 📸 Device Health Output

Below you can see if any onboarded systems are in distress or potentially have a third-party anti-virus installed.

![DeviceHealthOutput](images/DeviceHealthOutput.png)

---


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

### 🔍 What to Look For

- devices missing recent check-in timestamps
- inconsistent reporting across similar systems
- newly onboarded devices not appearing

### 🛠️ Recommended Remediation

- verify device is active and powered on
- confirm Defender agent is installed and healthy
- check network connectivity
- re-onboard device if necessary
- remove decommissioned devices from inventory
  

🔝 [Back to Table of Contents](#-table-of-contents)

---

## Stale Devices

```kusto
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName
| where LastSeen < ago(7d)
```
![Devices Reporting](../images/StaleDevices.png)

### What It Does

Finds devices not reporting recently.

### When to Use

* onboarding gaps
* telemetry validation

### Suspicious

Active devices going silent.

### 🔍 What to Look For

- devices not reporting within expected timeframe
- critical systems appearing inactive
- sudden drop-off in reporting devices

### 🛠️ Recommended Remediation

- verify device is still in use
- check Defender sensor health
- confirm network access to Microsoft services
- re-onboard device if necessary

 🔝 [Back to Table of Contents](#-table-of-contents)
 
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

# ⚠️ 3. THREAT HUNTING

## Suspicious PowerShell

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
```

![Devices Reporting](../images/Suspicioiuspowershell.png)

Below is the Powershell needed to investigate Poweshell run as System (helpful for NTLM Credential theft alerts)

```Kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
```

### What It Does

Detects common attacker scripting patterns.

### Suspicious

Encoded commands, downloads.

---

### 🔍 What to Look For

- encoded or obfuscated commands (`-enc`, base64)
- download activity (`DownloadString`, `Invoke-WebRequest`)
- unusual users running PowerShell
- execution from temp or user directories

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

🔝 [Back to Table of Contents](#-table-of-contents)

---

## Office → Script Execution

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe")
```

### What It Does

Detects macro/phishing execution chains.

---

### Detection

🔥 Very High

---

### 🔍 What to Look For

- Word, Excel, or Outlook spawning PowerShell or cmd
- script execution immediately after document open
- unusual command-line arguments
- activity tied to recent email delivery

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

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- entries in Run or RunOnce keys
- executables in temp or user directories
- unknown or unsigned binaries
- persistence linked to recent activity

### 🛠️ Recommended Remediation

**High Confidence**
- remove malicious registry entry
- isolate device
- investigate associated file
- review persistence across system

**Medium Confidence**
- validate application legitimacy
- compare against known baseline

🔝 [Back to Table of Contents](#-table-of-contents)

---

## Scheduled Task Creation

```kusto
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create","-create")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

![Devices Reporting](../images/ScheduleTaskCreation.png)

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

Check the following:

- DeviceProcessEvents → what executed
- DeviceFileEvents → what file was dropped
- DeviceNetworkEvents → did it call out
- DeviceLogonEvents → who created it

## 🧠 Note

Scheduled tasks are often used in combination with:
- PowerShell execution
- file staging in temp directories
- outbound network connections

Always correlate task creation with process and network activity.

### Detection Potential

🔥 High

### 🛠️ Recommended Remediation

**High Confidence (malicious persistence identified)**
- isolate the device immediately
- disable or delete the scheduled task
- identify and remove the associated file or script
- run full antivirus scan
- review all scheduled tasks on the device for additional persistence
- reset credentials for the affected account
- investigate lateral movement or additional compromise

**Medium Confidence (suspicious but unconfirmed)**
- validate task name and purpose with system owner
- review execution path and associated file
- monitor task execution behavior
- check for repeated or similar task creation across environment

**Low Confidence (likely benign)**
- document known task
- add to allowlist for future filtering

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- new or unusual service names
- services pointing to temp or user directories
- services created by non-admin users
- PowerShell-based service creation

### 🛠️ Recommended Remediation

**High Confidence**
- disable or remove service
- isolate device
- investigate service binary
- review privilege escalation activity

**Medium Confidence**
- validate service purpose
- monitor for repeated creation

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- repeated failed attempts for one account
- multiple accounts failing from one device
- rapid login attempts (spray behavior)
- failures followed by successful login

### 🛠️ Recommended Remediation

**High Confidence**
- block source device or IP
- reset credentials
- enforce MFA
- investigate brute force activity

**Medium Confidence**
- monitor login attempts
- review authentication patterns

🔝 [Back to Table of Contents](#-table-of-contents)
  
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

🔝 [Back to Table of Contents](#-table-of-contents)

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

![Devices Reporting](../images/ExternalConnectionsfromScriptingTools.png)

### Table Used

DeviceNetworkEvents → Network connections

### What It Does

Identifies outbound connections from scripting or command-line tools.

### When to Use

* command and control detection
* suspicious downloads

---

### Normal vs Suspicious

* Normal: known infrastructure
* Suspicious: rare IPs, unusual behavior

### Pivot

* process command line
* rare IP analysis

### Detection Potential

🔥 High

---

### 🔍 What to Look For

- scripting tools connecting to public IPs
- rare or unknown external destinations
- unusual ports or repeated connections
- command-line activity tied to network calls

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

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- IPs seen on very few devices
- uncommon external infrastructure
- connections tied to scripting tools
- lack of known business purpose

### 🛠️ Recommended Remediation

**High Confidence**
- block IP/domain via Defender or firewall
- isolate affected device
- review all connections to the IP across environment
- investigate associated processes

**Medium Confidence**
- validate IP against threat intelligence
- monitor for repeated communication

**Low Confidence**
- document known external services
- allowlist if legitimate

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For
- uncommon or non-standard ports
- scripting tools using unusual ports
- repeated connections on rare ports
- outbound traffic not aligned with normal application behavior

### 🛠️ Recommended Remediation

**High Confidence**
- block suspicious port or destination
- isolate device if malicious activity confirmed
- investigate process using the port

**Medium Confidence**
- validate port usage against expected application behavior
- monitor for recurrence

🔝 [Back to Table of Contents](#-table-of-contents)

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

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- accounts used across many devices
- unusual spread of standard user accounts
- access inconsistent with normal behavior

### 🛠️ Recommended Remediation

**High Confidence**
- reset credentials
- investigate lateral movement
- restrict account access

**Medium Confidence**
- validate usage patterns
- monitor for abnormal activity

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- scripting tools connecting to public IPs
- PowerShell, cmd, or mshta initiating outbound traffic
- rare or unknown external destinations
- unusual command-line activity tied to connections

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- IPs seen on very few devices
- uncommon external infrastructure
- connections tied to scripting tools
- lack of known business purpose

### 🛠️ Recommended Remediation

**High Confidence**
- block IP/domain
- isolate affected device
- investigate associated processes

**Medium Confidence**
- validate IP with threat intelligence
- monitor for repeated connections

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- uncommon or rarely used ports (non-80/443/53)
- scripting tools using unusual ports (PowerShell, cmd, mshta)
- outbound connections on high or non-standard ports
- repeated connections to the same port across devices

### 🧠 Note

Unusual port usage often becomes more meaningful when correlated with:
- scripting tool execution
- rare external IP connections
- recent file downloads or payload execution

---

### 🛠️ Recommended Remediation

**High Confidence (suspicious network activity confirmed)**
- isolate the device
- block the remote IP and/or port
- investigate the initiating process and command line
- review related network activity across the environment
- run antivirus scan and check for persistence mechanisms

**Medium Confidence (unusual but not confirmed malicious)**
- validate port usage against expected application behavior
- check if port is used by known software or services
- monitor for repeated or expanding activity

**Low Confidence (likely benign)**
- document known application behavior
- add to allowlist for future filtering

🔝 [Back to Table of Contents](#-table-of-contents)

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

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- executables or scripts in temp/public folders
- files created by scripting tools
- unusual or random file names
- activity tied to recent downloads
  
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

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- large or repeated archive creation
- compression in unusual directories
- activity by non-admin users
- behavior preceding external connections

### 🛠️ Recommended Remediation

**High Confidence**
- investigate files being archived
- check for sensitive data exposure
- review user intent and behavior
- restrict data access if needed

**Medium Confidence**
- validate business use case
- monitor for large or repeated archive activity

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- use of `-urlcache` or `-decode`
- external downloads via certutil
- encoded or decoded payloads
- execution followed by file creation

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device immediately
- block associated URL/IP
- investigate downloaded or decoded content
- review for additional payload execution

**Medium Confidence**
- validate usage against known admin activity
- monitor command usage patterns

🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- processes seen on very few devices
- unknown or unsigned executables
- unexpected binaries on user systems
- activity tied to suspicious execution chains

### 🛠️ Recommended Remediation

**High Confidence**
- isolate device
- analyze process binary
- check hash against threat intelligence
- review execution context

**Medium Confidence**
- validate process against known software inventory
- monitor for additional executions

 🔝 [Back to Table of Contents](#-table-of-contents)

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

### 🔍 What to Look For

- devices with little or no telemetry
- inconsistent reporting patterns
- active systems appearing inactive

### 🛠️ Recommended Remediation

- verify endpoint is active
- confirm Defender sensor health
- check connectivity and telemetry ingestion
- re-onboard device if needed

🔝 [Back to Table of Contents](#-table-of-contents)

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

🔝 [Back to Table of Contents](#-table-of-contents)

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

🔝 [Back to Table of Contents](#-table-of-contents)

---

# 🔥 Final Section Summary

* File → staging & payloads
* Anomaly → outliers
* Filtering → signal clarity
* Detection → operationalization

---

# 🛡️ Custom Detection Creation (Defender XDR)

🎯 Goal

Turn validated KQL queries into automated detections and alerts.

---

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

- ⚙️ Recommended Settings
- 🔴 Severity
- Scenario	Severity
- Confirmed malicious (PowerShell, Office chain)	High
- Suspicious but needs context	Medium
- Validation / anomaly queries	Low or none
- ⏱️ Frequency
- Use Case	Frequency
- Active threats	Every 5–15 minutes
- General monitoring	Hourly
- Baseline/anomaly	Daily
- 📊 Lookback Period

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

- investigation graph
- automated response
- 🤖 Automated Actions
- 🔥 High Confidence Detections
- isolate device
- run antivirus scan
- collect investigation package
- ⚠️ Medium Confidence
- trigger investigation
- alert SOC team
- monitor behavior
- 🚨 Example: PowerShell Detection

Use query:

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand","DownloadString","Invoke-WebRequest")
| where AccountName !in~ ("admin","svc_account")

Recommended:

Severity: High
Frequency: 15 minutes
Action: isolate device

🔝 [Back to Table of Contents](#-table-of-contents)

---

# 🧠 Analyst Guidance

This playbook is designed to support:

- telemetry validation  
- threat hunting  
- detection engineering  
- incident response  

Each query should be:
- validated in your environment  
- tuned to reduce noise  
- operationalized as needed  

> KQL is not just for hunting — it is for validating, Stay Safe Defenders!

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflows

The following workflows provide step-by-step guidance for investigating common Defender scenarios using KQL.

These are designed to help transition from:
- raw query execution  
- to structured investigation and decision-making

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Suspicious PowerShell Execution

### Step 1 — Identify suspicious PowerShell activity

Run a query targeting:

- Encoded commands  
- Download cradles  
- Suspicious flags (`-enc`, `-nop`, `-w hidden`)  

---

### Step 2 — Pivot to process context

Table:
- DeviceProcessEvents  

Validate:

- InitiatingProcessFileName  
- InitiatingProcessCommandLine  
- AccountName  

---

### Step 3 — Validate parent process

Look for:

- winword.exe → powershell.exe  
- excel.exe → powershell.exe  
- browser → powershell  

👉 These are high-risk parent-child relationships  

---

### Step 4 — Check network activity

Pivot to:
- DeviceNetworkEvents  

Look for:

- External connections  
- Suspicious domains  
- Download activity  

---

### Step 5 — Confirm or dismiss

Confirm suspicious if:

- Encoded or obfuscated commands  
- Unusual parent process  
- External download behavior  

Otherwise:

- Validate as admin or expected scripted activity

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Defender Tampering / Defense Evasion

### Step 1 — Identify Defender configuration changes

Run queries looking for:

- Set-MpPreference  
- Add-MpPreference  
- Registry changes affecting Defender  

---

### Step 2 — Pivot to registry activity

Table:
- DeviceRegistryEvents  

Look for:

- Disabled protections  
- Exclusions added  
- Real-time monitoring changes  

---

### Step 3 — Validate initiating process

Table:
- DeviceProcessEvents  

Check:

- CommandLine arguments  
- Script or binary used  
- Execution context  

---

### Step 4 — Check user context

Validate:

- AccountName  
- Privilege level  
- Expected administrative activity  

---

### Step 5 — Confirm or dismiss

Suspicious if:

- Unexpected user  
- Hidden or scripted execution  
- Multiple exclusions added  

Otherwise:

- Validate against known admin actions

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Credential Access (LSASS / Dumping)

### Step 1 — Identify LSASS access

Run queries for:

- lsass.exe access  
- Known dumping patterns  
- Suspicious tools  

---

### Step 2 — Pivot to process details

Table:
- DeviceProcessEvents  

Check:

- ProcessName  
- CommandLine  
- InitiatingProcess  

---

### Step 3 — Validate binary behavior

Look for:

- Unsigned executables  
- Unusual file paths  
- Living-off-the-land binaries  

---

### Step 4 — Check related activity

Pivot to:

- DeviceFileEvents  
- DeviceNetworkEvents  

Look for:

- Dump file creation  
- External connections  

---

### Step 5 — Confirm or dismiss

Suspicious if:

- LSASS accessed by non-system process  
- Dumping tools observed  
- Correlated suspicious activity  

Otherwise:

- Validate expected system or security tooling behavior 

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Suspicious Process Chain

### Step 1 — Identify abnormal execution

Look for:

- Unexpected parent-child relationships  
- Script interpreters launched by documents  

---

### Step 2 — Build process tree

Table:
- DeviceProcessEvents  

Trace:

- Parent process  
- Child processes  
- Execution sequence  

---

### Step 3 — Validate command lines

Check for:

- Encoded commands  
- Obfuscation  
- Suspicious arguments  

---

### Step 4 — Correlate additional activity

Pivot to:

- DeviceNetworkEvents  
- DeviceFileEvents  

---

### Step 5 — Confirm or dismiss

Suspicious if:

- Document → script → network chain  
- Multi-stage execution  
- Obfuscation present  

Otherwise:

- Expected application behavior

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Suspicious Network Activity

### Step 1 — Identify suspicious connections

Look for:

- External IP addresses  
- Rare or newly observed domains  
- High-volume outbound traffic  

---

### Step 2 — Pivot to process source

Table:
- DeviceProcessEvents  

Identify:

- Responsible process  
- CommandLine  
- User context  

---

### Step 3 — Validate destination

Check:

- Domain/IP reputation  
- Known indicators  
- Geographic anomalies  

---

### Step 4 — Correlate system activity

Pivot to:

- DeviceFileEvents  
- DeviceProcessEvents  

---

### Step 5 — Confirm or dismiss

Suspicious if:

- Unknown process initiating connections  
- Repeated outbound traffic  
- Known malicious indicators  

Otherwise:

- Expected application/network behavior

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🔎 Investigation Workflow: Device Triage (Post Alert)

### Step 1 — Start from alert context

Gather:

- DeviceName  
- AccountName  
- Timestamp  
- Alert details  

---

### Step 2 — Review process activity

Table:
- DeviceProcessEvents  

Look for:

- Recent executions  
- Suspicious binaries  
- Script usage  

---

### Step 3 — Review network activity

Table:
- DeviceNetworkEvents  

Check:

- External connections  
- Suspicious domains  

---

### Step 4 — Review file activity

Table:
- DeviceFileEvents  

Look for:

- Dropped files  
- Unknown executables  

---

### Step 5 — Determine scope

Identify:

- Single event vs broader compromise  
- Lateral movement indicators  
- Persistence mechanisms  

---

### Step 6 — Confirm or escalate

Escalate if:

- Multiple correlated suspicious signals  
- Known attack patterns  
- Cross-device activity  

Otherwise:

- Close as benign or expected behavior
  

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🧾 Closing Summary

This playbook demonstrates how Kusto Query Language (KQL) can be used as more than a querying tool — it serves as a structured methodology for threat hunting and investigation within Microsoft Defender.

Throughout this deep dive, we established a consistent approach to:

- understanding Defender telemetry and data relationships  
- identifying suspicious behavior using KQL  
- pivoting across process, network, file, and registry data  
- validating findings through repeatable investigation workflows

🔝 [Back to Table of Contents](#-table-of-contents)

---

### 🔄 From Queries to Investigations

A key takeaway from this playbook is that effective use of KQL is not about individual queries, but about **how those queries are applied within an investigation process**.

The methodology used throughout this playbook:

Hunt → Pivot → Investigate → Validate → Decide
---

This ensures that:

- queries are used in context  
- findings are verified before conclusions are made  
- investigations are structured and repeatable

🔝 [Back to Table of Contents](#-table-of-contents)

---

### 🚨 Operational Impact

When applied correctly, this approach enables security teams to:

- detect suspicious activity earlier through proactive hunting  
- improve consistency across investigations  
- reduce time to triage and validate alerts  
- build confidence in Defender telemetry and coverage  

Additionally, mature use of KQL allows teams to:

- convert high-value hunting queries into detections  
- improve visibility gaps over time  
- strengthen overall security posture  

Threat hunting is not a one-time activity — it is a continuous process of refinement and improvement. :contentReference[oaicite:0]{index=0}  

🔝 [Back to Table of Contents](#-table-of-contents)

---

### 🎯 Final Outcome

By using this playbook, defenders should be able to:

- move beyond running isolated queries  
- perform structured, end-to-end investigations  
- understand how different Defender data sources connect  
- develop repeatable workflows for real-world scenarios  

---

### 🚀 Next Evolution

The next step in maturity is to:

- translate validated hunting queries into detection rules  
- tune queries for accuracy and performance  
- integrate findings into broader incident response processes  

This transforms KQL from a hunting tool into a **core component of detection engineering and security operations**. :contentReference[oaicite:1]{index=1} 

🔝 [Back to Table of Contents](#-table-of-contents)

---

## 🛡️ Final Thought

Security tools do not fail loudly — they fail silently.

KQL provides the visibility needed to uncover those gaps,  
but only when used with structure, context, and intent.

The goal is not just to query data —  
it is to **understand what the data is telling you**.

