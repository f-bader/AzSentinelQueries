# Suspicious Teams messages based on unicode in DisplayName

## Query Information

#### Description

Hunt for Teams chats with people that have a NO-BREAK SPACE unicode character in their DisplayName. \
This could be an indicator of a Teams support scam.

#### Risk

String based matching can be evaded easily by using another unicode character.

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

## Defender XDR
```KQL
CloudAppEvents
| where Application == @"Microsoft Teams"
| where ActionType == @"ChatCreated"
| extend ParticipantInfo = RawEventData.ParticipantInfo
| where ParticipantInfo.HasForeignTenantUsers == true
| where RawEventData.Members matches regex @"[\u00A0]+"
```
