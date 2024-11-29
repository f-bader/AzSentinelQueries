# Installed Defender for Identity version on Domain Controllers

## Query Information

#### Description

This query lists all detected domain controllers and the installed Microsoft Defender for Identity version. \
If there is no MDI agent installed the property `MDIInstalled` is set to false.

#### Risk

Without Defender for Identify coverage there are blindspots in the XDR coverage

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

## Defender XDR
```KQL
ExposureGraphNodes
| where parse_json(NodeProperties)["rawData"]["deviceRole"] has 'DomainController'
| summarize by DeviceName = NodeName
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | where SoftwareName == @"azure_advanced_threat_protection_sensor"
    | summarize by DeviceName, DeviceId, SoftwareName, SoftwareVersion
    )
    on DeviceName
| extend MDIInstalled = tobool(isnotempty(DeviceName1))
```
