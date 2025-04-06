// Creates a custom table in Sentinel and a data collection rule and endpoint  to send data to the custom table.
// This data collection is used to collect data from a local JSON file and send it to the custom table.

// az bicep upgrade
// az account set --subscription YOUSUBSCRIPTION
// az deployment sub create --location westeurope --template-file main.bicep --parameters sample.params.jsonc --what-if

targetScope = 'subscription'

@description('Name of the custom table')
param tableName string
@description('Schema of the custom table')
param tableSchema array
@description('Retention period in days for the data in the custom table. Default is same as the workspace retention period.')
param retentionInDays int = -1
@allowed(['Analytics','Basic', 'Auxiliary'])
@description('Plan of the custom table. Default is Analytics.')
param plan string = 'Analytics'
@description('Path on the local disk for the log file to collect. May include wildcards. Enter multiple file patterns separated by commas (AMA version 1.26 or higher required for multiple file patterns on Linux).')
param filePatterns string

@description('Name of the resource group to create for data collection resources.')
param dataCollectionResourceGroup string
@description('Name of the data collection endpoint.')
param dataCollectionEndpointName string
@description('Unique name for the data collection rule.')
param dataCollectionRuleName string
@description('Region for the data collection rule. Must be the same as the data collection endpoint.')
param dataCollectionRuleDescription string = 'Custom Data Collection Rule'
@description('Optional: KQL query to transform the data before sending it to the table.')
param transformKql string = 'source'

// Sentinel workspace. Has to be already created.
@description('Location of the Sentinel workspace.')
param SentinelWorkspaceLocation string
@description('Resource group of the Sentinel workspace.')
param SentinelWorkspaceResourceGroup string
@description('Resource ID of the Log Analytics workspace with the target table.')
param SentinelWorkspaceName string

// Do not change the following parameters unless you are sure of the changes you are making
var tableStream = 'Custom-Json-${tableName}_CL'
var tableOutputStream = 'Custom-${tableName}_CL'

module ModCustomTable 'customTable.bicep' = {
  name: 'customtable-${tableName}'
  scope: resourceGroup(SentinelWorkspaceResourceGroup)
  params: {
    SentinelWorkspaceName: SentinelWorkspaceName
    tableName: '${tableName}_CL'
    tableSchema: tableSchema
    plan: plan
    retentionInDays: retentionInDays
  }
}

resource ModIngestionResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: dataCollectionResourceGroup
  location: SentinelWorkspaceLocation
}

module ModDataCollectionRule 'dataCollectionResources.bicep' = {
  name: 'datacollection-${dataCollectionRuleName}'
  scope: resourceGroup(dataCollectionResourceGroup)
  params: {
    tableSchema: tableSchema
    filePatterns: filePatterns
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionRuleName: dataCollectionRuleName
    dataCollectionRuleDescription: dataCollectionRuleDescription
    location: ModCustomTable.outputs.SentinelWorkspaceResourceLocation
    tableStream: tableStream
    tableOutputStream: tableOutputStream
    SentinelWorkspaceResourceId: ModCustomTable.outputs.SentinelWorkspaceResourceId
    SentinelWorkspaceResourceLocation: ModCustomTable.outputs.SentinelWorkspaceResourceLocation
    transformKql: transformKql
  }
}
