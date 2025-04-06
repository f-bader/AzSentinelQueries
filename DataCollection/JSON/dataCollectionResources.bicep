@description('Name of the data collection endpoint.')
param dataCollectionEndpointName string
@description('Unique name for the DCR.')
param dataCollectionRuleName string
@description('Region for the data collection rule. Must be the same as the data collection endpoint.')
param location string
@description('Region for the data collection rule. Must be the same as the data collection endpoint.')
param dataCollectionRuleDescription string = 'Custom Data Collection Rule'
@description('Path on the local disk for the log file to collect. May include wildcards. Enter multiple file patterns separated by commas (AMA version 1.26 or higher required for multiple file patterns on Linux).')
param filePatterns string
@description('Schema of the custom table')
param tableSchema array
@description('KQL query to transform the data before sending it to the table.')
param transformKql string = 'source'

param tableStream string
param tableOutputStream string
param SentinelWorkspaceResourceId string
param SentinelWorkspaceResourceLocation string


resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRuleName
  location: SentinelWorkspaceResourceLocation
  properties: {
    description: dataCollectionRuleDescription
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      '${tableStream}': {
        columns: tableSchema
      }
    }
    dataSources: {
      logFiles: [
        {
          streams: [
            tableStream
          ]
          filePatterns: [
            filePatterns
          ]
          format: 'json'
          name: tableStream
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: SentinelWorkspaceResourceId
          name: 'workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          tableStream
        ]
        destinations: [
          'workspace'
        ]
        transformKql: transformKql
        outputStream: tableOutputStream
      }
    ]
  }
}
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId
output dataCollectionRuleResourceId string = dataCollectionRule.id

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dataCollectionEndpointName
  location: location
  properties: {
    networkAcls: { publicNetworkAccess: 'Enabled' }
  }
}
output dataCollectionEndpointLogIngestionEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
