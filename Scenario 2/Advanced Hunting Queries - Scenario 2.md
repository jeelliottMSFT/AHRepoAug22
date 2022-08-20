# Scenario 2 Queries

## Web Shell Hunting
```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ('w3wp.exe')
| where FileName in~ ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe', 'net.exe', 'net1.exe', 'ping.exe', 'whoami.exe')
| project Timestamp, ProcessCommandLine, DeviceName
| sort by Timestamp asc 
```
```
DeviceProcessEvents
| where DeviceName startswith "web3"
| where InitiatingProcessFileName in~ ('w3wp.exe')
| where FileName in~ ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe', 'net.exe', 'net1.exe', 'ping.exe', 'whoami.exe')
| project Timestamp, ProcessCommandLine, DeviceName
| sort by Timestamp asc 
```
## Hunting SweetPotato
```
DeviceProcessEvents
| where InitiatingProcessFolderPath has @"C:\ProgramData\s.exe"
| project Timestamp, ActionType, FolderPath, AccountDomain, AccountName, DeviceName
```
## Named Pipe Manipulation
```
DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend ADF=parse_json(AdditionalFields)
| where ADF.PipeName endswith @"pipe\spoolss"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessAccountName, ADF.PipeName, ADF.NamedPipeEnd, ADF.FileOperation, DeviceName
```
## IIS Transport
```
DeviceEvents
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| summarize count() by ActionType
| where ActionType in~ ("NamedPipeEvent", "OpenProcessApiCall", "CreateRemoteThreatApiCall")
```
## Named Pipe Usage
```
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| extend ADF=parse_json(AdditionalFields)
| distinct tostring(ADF.PipeName)
```
## Create Remote Thread API Call
```
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| project Timestamp, ActionType, FileName, ProcessId
```
```
DeviceEvents
| where InitiatingProcessFileName == "mqsvc.exe"
| where InitiatingProcessId == 1292
| extend ADF=parse_json(AdditionalFields)
| distinct tostring(ADF.PipeName)
```
## Wider Named Pipe Usage
```
DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend ADF=parse_json(AdditionalFields)
| where tostring(ADF.PipeName) contains "IIS.Transport"
| distinct 
    InitiatingProcessFileName, InitiatingProcessId, 
    InitiatingProcessAccountName, InitiatingProcessAccountDomain, 
    tostring(ADF.PipeName), tostring(ADF.NamedPipeEnd)
```
## Broad Searching IIS Transport
```
search "IIS.transport.exe"
| summarize count() by $table
```
```
DeviceEvents
| search "IIS.Transport"
| summarize count() by ActionType
```
## Open Process API Call - lsass.exe
```
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where InitiatingProcessParentFileName =~ "IIS.Transport.exe"
```
## Children of Cobalt
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "iis.transport.exe"
| summarize count() by ProcessCommandLine, AccountName, AccountDomain
```
```
DeviceEvents
| where InitiatingProcessFileName == "dllhost.exe"
| where InitiatingProcessId == 592
| summarize count() by ActionType
```
## Children of Cobalt's Children
```
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "iis.transport.exe"
| where InitiatingProcessFileName =~ "dllhost.exe"
| summarize count() by ProcessCommandLine, AccountName, AccountDomain, ProcessId
```
## Administrator Dllhosts
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "dllhost.exe"
| where AccountDomain =~ "spacesound" and AccountName =~ "administrator"
| summarize count() by ProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName
```
## Tamper Protection
```
DeviceProcessEvents
| where FolderPath startswith @"C:\Windows\Temp"
| summarize count() by FileName
```
```
DeviceProcessEvents
| where FileName =~ "PowerShell.exe"
| where ProcessCommandLine has_any ("Get-MpPreference", "Add-MpPreference", "Set-MpPreference")
| project Timestamp, ProcessCommandLine, DeviceName, AccountName
```
## WMI
```
DeviceProcessEvents
| where Timestamp between (datetime("2022-08-18") .. datetime("2022-08-19"))
| where DeviceName startswith "DC1"
| where InitiatingProcessFileName =~ "WmiPrvse.exe"
| where AccountName == "administrator" and AccountDomain == "spacesound"
| project Timestamp, ProcessCommandLine, FolderPath
```
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvse.exe"
| summarize count() by AccountName, AccountDomain
```