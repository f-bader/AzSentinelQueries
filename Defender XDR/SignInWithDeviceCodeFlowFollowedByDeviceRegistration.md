# SignIn with device code flow followed by device registration

## Query Information

#### Description

Results in a list of sign-ins that requested the resource "Device Registration Service" as part of a device code flow. \
This result set is correlated with the Entra ID audit logs, specifically the "Register device", "Add device" operations. \
Based on the User Id the two data sets are merged and only if the device registration happend after the device code flow sign in, the data is returned.

Sign-ins from trusted locations are excluded to minimize BP.

#### Risk

* BP: Teams rooms devices or phones

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

* Function [UnifiedSignInLogs](https://cloudbrothers.info/en/unified-sign-logs-advanced-hunting/) required
* [Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
* [Protect your users from Device Code Flow abuse](https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/)

## Defender XDR
```KQL
UnifiedSignInLogs
| where TimeGenerated > ago(90d)
| where ResultType == 0
// Device Code Flow
| where AuthenticationProtocol == "deviceCode"
| where NetworkLocationDetails !has "trustedNamedLocation"
// Resource Device Registration Service
| where ResourceIdentity == "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
| summarize arg_max(TimeGenerated, *) by UniqueTokenIdentifier
| join kind=inner (AuditLogs
    | extend DeviceRegisteredTimeGenerated = TimeGenerated
    | where OperationName in ("Register device", "Add device")
    | extend UserId = tostring(parse_json(tostring(InitiatedBy.user)).id)
    | extend DeviceRegisteredIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
    | where isnotempty(UserId)
    | where isnotempty(DeviceRegisteredIPAddress))
    on UserId
// Extract DeviceId
| extend DeviceOS = tostring(AdditionalDetails[3].value)
| extend DeviceId = tostring(AdditionalDetails[4].value)
// Only devices registered after the inital sign-in
| where TimeGenerated < DeviceRegisteredTimeGenerated
| project-reorder
    TimeGenerated,
    DeviceRegisteredTimeGenerated,
    UserPrincipalName,
    UserId,
    DeviceOS,
    DeviceId,
    IPAddress,
    DeviceRegisteredIPAddress,
    AppDisplayName,
    AppId,
    ResourceDisplayName,
    ResourceIdentity
```
