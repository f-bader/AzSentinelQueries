# Microsoft Sentinel hunting queries and Analytics rules

![Azure Attack Paths](./images/AzureDominancePathsColor.png)

Initially the queries and Analytics Rules in this repository were related to the [Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/) blog post. Over time, I also add new Analytics Rules that are related to other blog posts if mine.

All queries are ready to be used in [Microsoft Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/overview).

## HuntingQueries

1. [Azure VM Run Command or Custom Script execution](./HuntingQueries/AzureVMRunCommandorCustomScriptExecution.yaml)
1. [Changes to Azure Lighthouse delegation](./HuntingQueries/ChangesToAzureLighthouseDelegation.yaml)
1. [Grant high privilege Azure AD role to identity](./HuntingQueries/GrantHighPrivilegeAzureADRoleToIdentity.yaml)
1. [Grant high privilege Microsoft Graph permissions](./HuntingQueries/GrantHighPrivilegeMicrosoftGraphPermissions.yaml)

## AnalyticsRules

* [Azure VM Run Command or Custom Script execution detected](./AnalyticsRules/AzureVmRunCommandOrCustomScriptExecutionDetected.yaml)
* [Dangerous API permission consented](./AnalyticsRules/DangerousAPIPermissionConsented.yaml)
* [High Privileged Role assigned](./AnalyticsRules/HighPrivilegedRoleAssigned.yaml)
* [A new Lighthouse service provider was added](./AnalyticsRules/NewLighthouseServiceProviderWasAdded.yaml)
* [Owner added to high privileged application](./AnalyticsRules/OwnerAddedToHighPrivilegedApplication.yaml)
* [Password reset on high privileged user](./AnalyticsRules/PasswordResetOnHighPrivilegedUser.yaml)
* [Secret added to high privileged application](./AnalyticsRules/SecretAddedToHighPrivilegedApplication.yaml)
