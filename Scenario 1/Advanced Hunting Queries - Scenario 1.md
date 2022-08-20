```
AlertInfo
| join AlertEvidence on AlertId
| where Title =~ "Suspicious Task Scheduler activity"
| project Timestamp, DeviceName, ProcessCommandLine

AlertInfo
| join AlertEvidence on AlertId
| where ProcessCommandLine has @"C:\Windows\OpenSSH\"
| extend ADF=parse_json(AdditionalFields)
| extend ImageFile=parse_json(ADF.ImageFile)
| extend PProc=parse_json(ADF.ParentProcess)
| extend Account=parse_json(ADF.Account)
| extend Host=parse_json(parse_json(ImageFile.Host))
| project Timestamp, AlertId, Host.NetBiosName, Title, ProcessCommandLine, Account.Name, PProc.CommandLine, ImageFile.CreatedTimeUtc

DeviceProcessEvents
| where Timestamp between (datetime(2022-08-08) .. datetime(2022-08-10))
| where 
    FileName has_any ("whoami", "WMIC", "hostname", "dsquery", "wevtutil", "sc", "powershell")
     or InitiatingProcessFileName contains "wmiprvse"
| where InitiatingProcessAccountName has_any ("da_dan", "da_fred")
| summarize make_set(DeviceName) by ProcessCommandLine


DeviceProcessEvents
| where ProcessCommandLine has @"C:\Windows\Temp\data"
| summarize make_set(DeviceName) by ProcessCommandLine
| project ProcessCommandLine, set_DeviceName, array_length(set_DeviceName)

DeviceFileEvents
| where FolderPath startswith @"C:\Windows\Temp\data"
| project Timestamp, InitiatingProcessCommandLine, FolderPath

DeviceEvents
| search @"C:\Windows\Temp\data"
| project Timestamp, ActionType, InitiatingProcessCommandLine

DeviceFileEvents
| where FolderPath startswith @"C:\Windows\Temp\CYG-DC2016-01.7z"
| project Timestamp, InitiatingProcessCommandLine, FolderPath

search  @"AAA.exe"
| summarize count() by $table

DeviceProcessEvents
| where FolderPath has @"C:\Windows\Temp\"

| where FileName has_any (
    "AAA.exe", "PsExec.exe", "UN_A.exe", "lsas.exe"
    )
//| summarize make_set(DeviceName) by ProcessCommandLine
//| project ProcessCommandLine, set_DeviceName, array_length(set_DeviceName)

DeviceFileEvents
| search "AAA.exe"
```