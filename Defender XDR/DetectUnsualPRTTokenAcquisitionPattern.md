# Detect Unsual PRT Token Acquisition Pattern

## Query Information

#### Description

This query is looking for behaviour of BAADTokenBroker or similar attack toolkits that (ab)use the `CreateSSOCookie` method to extract an PRT cookie and reuse it on another machine, especially from another IP address.

#### Risk

This detections relies on a change of IP address and therefor won't trigger if the attacker is using the PRT cookie from the same IP address as the inital machine.

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

## Defender XDR or Sentinel

```kql
UnifiedSignInLogs
| where TimeGenerated > ago(90d)
| where AppDisplayName == "Microsoft Authentication Broker"
| where AppId == "29d9ed98-a469-4536-ade2-f981bc1d605e"
| summarize TokenAcquisitionCreatedDateTime =min(CreatedDateTime) by SessionId, TokenAcquisitionIPAddress = IPAddress, UserId
| join (UnifiedSignInLogs
    | where AppDisplayName != "Microsoft Authentication Broker"
    | where AppId != "29d9ed98-a469-4536-ade2-f981bc1d605e"
    | summarize arg_min(CreatedDateTime, *) by SessionId, UserId, IPAddress
    )
    on UserId, SessionId
| where TokenAcquisitionIPAddress != IPAddress 
| where DeviceDetail.operatingSystem startswith "Windows"
| where IncomingTokenType == "primaryRefreshToken"
| extend TimeBetweenTokenAcquisition = datetime_diff( 'second', CreatedDateTime, TokenAcquisitionCreatedDateTime)
| where TimeBetweenTokenAcquisition > 0
```
