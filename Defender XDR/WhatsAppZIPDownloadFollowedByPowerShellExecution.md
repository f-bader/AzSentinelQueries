# Download Zip file and subsequent execution of PowerShell with certain commands

## Query Information

#### Description

Download Zip file to the default Download folder or the WhatsApp Desktop App download folder
followed by the execution of PowerShell with certain commands like ˋInvoke-Expressionˋ that
are used to load the next stage of the attack.

#### Risk

Very limited coverage of potential obfuscated strings for ˋInvoke-Expressionˋ

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

## Defender XDR
```KQL
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith @"C:\Users\"
| where FolderPath contains "WhatsAppDesktop" or FolderPath has "Downloads"
| where FileName endswith "zip"
| extend DownloadTimestamp = Timestamp
| project DownloadTimestamp, FileName, FolderPath, DeviceId, InitiatingProcessAccountUpn
| join ( DeviceProcessEvents
  | where ProcessVersionInfoInternalFileName has "PowerShell"
  | where ProcessCommandLine has_any ("iwr", "iex", "invoke")
  | extend ExecutionTimestamp = Timestamp)
on DeviceId, InitiatingProcessAccountUpn
| where ExecutionTimestamp > DownloadTimestamp and ExecutionTimestamp < datetime_add('minute', 30, DownloadTimestamp)
| project-reorder DownloadTimestamp, FileName, ExecutionTimestamp, ProcessCommandLine, AccountName
```
