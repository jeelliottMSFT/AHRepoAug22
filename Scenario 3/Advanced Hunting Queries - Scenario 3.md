# Scenario 3 Queries

## Query Network Events from TI IOC
```
DeviceNetworkEvents
| where RemoteUrl == "edgeupdator.tv"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort

// 192.168.217.210
```
## Pivot on newly identified IP
```
DeviceNetworkEvents
| where RemoteUrl startswith "192.168.217.210"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```
```
DeviceNetworkEvents
| where RemoteUrl has_any ("192.168.217.210", "edgeupdator.tv")
| distinct InitiatingProcessId, InitiatingProcessFileName
```
## Get more PowerShell activity during time range
```
DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where FileName == "powershell.exe"
| where ProcessId in (3148, 6168)
| project Timestamp, ProcessCommandLine
```
## Find hits of edgeupdate.exe in FileEvents
```
DeviceFileEvents
| where FileName == "edgeupdate.exe" or InitiatingProcessFileName == "edgeupdate.exe"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
```
## Download and execution of payload edge.exe
```
DeviceProcessEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| project Timestamp, ProcessCommandLine, DeviceName
```
## Find hits of edge.exe in FileEvents
```
DeviceFileEvents
| where FileName == "edge.exe"
| project Timestamp, ActionType, FileName, SHA256, InitiatingProcessFileName
```
## Aggregate number of action types associated with edgeupdate.exe
```
DeviceEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| summarize count() by ActionType
```
## Find OpenProcessApiCall events - lsass.exe
```
DeviceEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| where ActionType == "OpenProcessApiCall"
| summarize count() by ProcessCommandLine, DeviceName
```
## Service creation events for Priv Esc
```
DeviceEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| where ActionType == "ServiceInstalled"
```
## PsExec Stage 1
```
DeviceFileEvents
| where FileName has "psexesvc"
| distinct FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, ShareName
```
## PsExec Stage 2: SMB
```
DeviceNetworkEvents
| where InitiatingProcessFileName has "psexec"
| project Timestamp, ActionType, RemotePort, InitiatingProcessCommandLine
```
```
DeviceEvents
| where InitiatingProcessFileName has "psexec"
| where ActionType == "ServiceInstalled"
| extend adf=parse_json(AdditionalFields)
| Project adf.ServiceName, adf.ServiceAccount, InitiatingProcessFileName, InitiatingProcessParentFileName
```
## PsExec Stage 3: Named Pipes
```
DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend adf=parse_json(AdditionalFields)
| where adf.PipeName endswith "PSEXESVC"
| distinct tostring(adf.PipeName), tostring(adf.NamedPipeEnd), InitiatingProcessFileName
```
## SMB
```
DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where InitiatingProcessFileName =~ "rundll32.exe"
| where InitiatingProcessId == 7780
| project Timestamp, ProcessCommandLine, DeviceName
```
```
DeviceFileEvents
| where ShareName == "ADMIN$"
| where DeviceName startswith "DC1"
| project FolderPath, SHA256
```
```
DeviceEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where InitiatingProcessFileName =~ "rundll32.exe"
| where InitiatingProcessId == 7780
```
## Remote Service Creation
```
DeviceEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where DeviceName startswith "DC1"
| where ActionType == "ServiceInstalled"
| where FileName == "msedge.exe"
```
## Volume Shadow Copy
```
DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where DeviceName startswith "DC1"
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| project Timestamp, ProcessCommandLine, DeviceName
```
```
DeviceFileEvents
| where FileName == "msedge.dit"
| project Timestamp, FolderPath, DeviceName, SHA256
```
```
DeviceNetworkEvents
| where InitiatingProcessFileName == "sc.exe"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine
```