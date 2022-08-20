DeviceProcessEvents
| where DeviceName startswith "web3"
| where InitiatingProcessFileName in~ ('w3wp.exe')
| where FileName in~ ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe', 'net.exe', 'net1.exe', 'ping.exe', 'whoami.exe')
| project Timestamp, ProcessCommandLine, DeviceName
| sort by Timestamp asc 

DeviceProcessEvents
| where InitiatingProcessFolderPath has @"C:\ProgramData\s.exe"
| project Timestamp, ActionType, FolderPath, AccountDomain, AccountName, DeviceName

DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend ADF=parse_json(AdditionalFields)
| where ADF.PipeName endswith @"pipe\spoolss"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessAccountName, ADF.PipeName, ADF.NamedPipeEnd, ADF.FileOperation, DeviceName

DeviceEvents
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| summarize count() by ActionType

| where ActionType in~ ("NamedPipeEvent", "OpenProcessApiCall", "CreateRemoteThreatApiCall")

DeviceEvents
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| extend ADF=parse_json(AdditionalFields)
| distinct tostring(ADF.PipeName)

DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName =~ "IIS.Transport.exe"
| project Timestamp, ActionType, FileName, ProcessId

DeviceEvents
| where InitiatingProcessFileName == "mqsvc.exe"
| where InitiatingProcessId == 1292
| extend ADF=parse_json(AdditionalFields)
| distinct tostring(ADF.PipeName)

DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend ADF=parse_json(AdditionalFields)
| where tostring(ADF.PipeName) contains "IIS.Transport"
| distinct 
    InitiatingProcessFileName, InitiatingProcessId, 
    InitiatingProcessAccountName, InitiatingProcessAccountDomain, 
    tostring(ADF.PipeName), tostring(ADF.NamedPipeEnd)


search "IIS.transport.exe"
| summarize count() by $table

DeviceEvents
| search "IIS.Transport"
| summarize count() by ActionType

DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where InitiatingProcessParentFileName =~ "IIS.Transport.exe"

DeviceEvents
| where InitiatingProcessFileName == "dllhost.exe"
| where InitiatingProcessId == 592
| summarize count() by ActionType

DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "iis.transport.exe"
| where InitiatingProcessFileName =~ "dllhost.exe"
| summarize count() by ProcessCommandLine, AccountName, AccountDomain, ProcessId

DeviceProcessEvents
| where InitiatingProcessFileName =~ "dllhost.exe"
| where AccountDomain =~ "spacesound" and AccountName =~ "administrator"
| summarize count() by ProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName

DeviceProcessEvents
| where FolderPath startswith @"C:\Windows\Temp"
| summarize count() by FileName

DeviceProcessEvents
| where FileName =~ "PowerShell.exe"
| where ProcessCommandLine has_any ("Get-MpPreference", "Add-MpPreference", "Set-MpPreference")
| project Timestamp, ProcessCommandLine, DeviceName, AccountName

DeviceProcessEvents
| where Timestamp between (datetime("2022-08-18") .. datetime("2022-08-19"))
| where DeviceName startswith "DC1"
| where InitiatingProcessFileName =~ "WmiPrvse.exe"
| where AccountName == "administrator" and AccountDomain == "spacesound"
| project Timestamp, ProcessCommandLine, FolderPath

DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvse.exe"
| summarize count() by AccountName, AccountDomain
