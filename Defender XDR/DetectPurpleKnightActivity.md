# Detect Purple Knight activity

## Query Information

#### Description

Use GraphAPIAuditEvents to identify Purple Knight activity in your environment.
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
      "https:/graph.microsoft.com/version/servicePrincipals/<UUID>/appRoleAssignments",
      "https:/graph.microsoft.com/version/roleManagement/directory/roleEligibilityScheduleInstances",
      "https:/graph.microsoft.com/version/servicePrincipals/",
      "https:/graph.microsoft.com/version/roleManagement/directory/roleAssignments",
      "https:/graph.microsoft.com/version/users/<UUID>/memberOf",
      "https:/graph.microsoft.com/version/directoryRoles/roleTemplateId=<UUID>/members",
      "https:/graph.microsoft.com/version/directoryObjects/<UUID>",
      "https:/graph.microsoft.com/version/identity/conditionalAccess/policies",
      "https:/graph.microsoft.com/version/policies/authorizationPolicy",
      "https:/graph.microsoft.com/version/policies/identitySecurityDefaultsEnforcementPolicy",
      "https:/graph.microsoft.com/version/organization",
      "https:/graph.microsoft.com/version/users",
      "https:/graph.microsoft.com/version/reports/credentialUserRegistrationDetails",
      "https:/graph.microsoft.com/version/directoryRoles",
      "https:/graph.microsoft.com/version/identity/conditionalAccess/namedLocations",
      "https:/graph.microsoft.com/version/auditLogs/signIns",
      "https:/graph.microsoft.com/version/$batch",
      "https:/graph.microsoft.com/version/roleManagement/directory/roleAssignmentScheduleRequests",
      "https:/graph.microsoft.com/version/directory/administrativeUnits",
      "https:/graph.microsoft.com/version/settings",
      "https:/graph.microsoft.com/version/applications",
      "https:/graph.microsoft.com/version/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator",
      "https:/graph.microsoft.com/version/servicePrincipals"
    ]);
GraphAPIAuditEvents
| where ingestion_time() > ago(1h)
| extend ObjectId = coalesce(AccountObjectId, ApplicationId)
| where RequestUri !has "microsoft.graph.delta"
| extend NormalizedRequestUri = replace_regex(RequestUri, @'[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}', @'<UUID>')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\d+$', @'<UUID>')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/+', @'/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/(v1\.0|beta)\/', @'/version/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'%23EXT%23', @'')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/[a-zA-Z0-9+_.\-]+@[a-zA-Z0-9.]+\/', @'/<UUID>/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'^\/<UUID>', @'')
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
