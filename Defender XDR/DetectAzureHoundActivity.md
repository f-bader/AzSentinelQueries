# Detect AzureHound activity

## Query Information

#### Description

Use GraphAPIAuditEvents to identify AzureHound activity in your environment.
Use **ConfidenceScore** and **TotalCount** to tune the query for your environment.

#### Risk

An attacker could go slow and not request all information in one go.

#### Author

- Name: Fabian Bader
- Website: cloudbrothers.info

#### References

* https://cloudbrothers.info/en/detect-threats-graphapiauditevents-part-3/

## Defender XDR
```KQL
let GraphQueries = dynamic([
    "https://graph.microsoft.com/beta/servicePrincipals/<UUID>/owners",
    "https://graph.microsoft.com/beta/groups/<UUID>/owners",
    "https://graph.microsoft.com/beta/groups/<UUID>/members",
    "https://graph.microsoft.com/v1.0/servicePrincipals/<UUID>/appRoleAssignedTo",
    "https://graph.microsoft.com/beta/applications/<UUID>/owners",
    "https://graph.microsoft.com/beta/devices/<UUID>/registeredOwners",
    "https://graph.microsoft.com/v1.0/users",
    "https://graph.microsoft.com/v1.0/applications",
    "https://graph.microsoft.com/v1.0/groups",
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
    "https://graph.microsoft.com/v1.0/devices",
    "https://graph.microsoft.com/v1.0/organization",
    "https://graph.microsoft.com/v1.0/servicePrincipals"
    ]);
GraphAPIAuditEvents
| where ingestion_time() > ago(1h)
| extend ObjectId = coalesce(AccountObjectId, ApplicationId)
| where RequestUri !has "microsoft.graph.delta"
| extend NormalizedRequestUri = replace_regex(RequestUri, @'[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}', @'<UUID>')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\?.*$', @'')
| summarize
    TotalCount = count(),
    GraphEndpointsCalled = make_set(NormalizedRequestUri, 1000),
    arg_min(Timestamp, *)
    by ObjectId, EntityType
| extend MatchingQueries=set_intersect(GraphQueries, GraphEndpointsCalled)
| extend ConfidenceScore = round(todouble(array_length(MatchingQueries)) / todouble(array_length(GraphQueries)), 1)
| where ConfidenceScore > 0.7
| where TotalCount > 1000
| project-away
    NormalizedRequestUri,
    RequestUri,
    ResponseStatusCode,
    RequestMethod,
    RequestDuration,
    ApiVersion
```
