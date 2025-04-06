param SentinelWorkspaceName string
param tableName string
param tableSchema array
param retentionInDays int
param plan string

resource SentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: SentinelWorkspaceName
}

resource CustomTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  name: tableName
  parent: SentinelWorkspace
  properties: {
    plan: plan
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: tableSchema
    }
  }
}
output CustomTableName string = CustomTable.id
output SentinelWorkspaceResourceId string = SentinelWorkspace.id
output SentinelWorkspaceResourceLocation string = SentinelWorkspace.location
