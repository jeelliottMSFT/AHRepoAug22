
DeviceNetworkEvents
| where RemoteUrl == |"edgeupdator.tv"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort

"192.168.217.210

DeviceNetworkEvents
| where RemoteUrl has_any ("192.168.217.210", "edgeupdator.tv")
| distinct InitiatingProcessId, InitiatingProcessFileName

DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where FileName == "powershell.exe"
| where ProcessId in (3148, 6168)
| project Timestamp, ProcessCommandLine

DeviceFileEvents
| where FileName == "edgeupdate.exe" or InitiatingProcessFileName == "edgeupdate.exe"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName

DeviceProcessEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| project Timestamp, ProcessCommandLine, DeviceName

DeviceFileEvents
| where FileName == "edge.exe"
| project Timestamp, ActionType, FileName, SHA256, InitiatingProcessFileName

DeviceEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| summarize count() by ActionType

DeviceEvents
| where InitiatingProcessFileName == "edgeupdate.exe"
| where ActionType == "ServiceInstalled"

DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where InitiatingProcessFileName =~ "rundll32.exeS"
| where InitiatingProcessId == 7780
| project Timestamp, ProcessCommandLine, DeviceName

DeviceEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where InitiatingProcessFileName =~ "rundll32.exe"
| where InitiatingProcessId == 7780

DeviceEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where DeviceName startswith "DC1"
| where ActionType == "ServiceInstalled"
| where FileName == "msedge.exe"

DeviceProcessEvents
| where Timestamp between (datetime("2022-08-19") .. datetime("2022-08-20"))
| where DeviceName startswith "DC1"
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| project Timestamp, ProcessCommandLine, DeviceName

DeviceFileEvents
| where FileName == "msedge.dit"
| project Timestamp, FolderPath, DeviceName, SHA256

DeviceNetworkEvents
| where InitiatingProcessFileName == "sc.exe"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine