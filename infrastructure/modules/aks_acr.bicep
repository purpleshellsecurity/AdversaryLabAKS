// Layer 1: Foundation - Azure Container Registry

param location string
param namePrefix string
param logAnalyticsWorkspaceId string
param tags object = {}

var acrName = '${toLower(replace(namePrefix, '-', ''))}acr${substring(uniqueString(resourceGroup().id), 0, 6)}'

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: acrName
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
    encryption: { status: 'disabled' }
    dataEndpointEnabled: false
  }
}

resource acrDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'acr-to-law'
  scope: acr
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [ { categoryGroup: 'allLogs', enabled: true } ]
    metrics: [ { category: 'AllMetrics', enabled: true } ]
  }
}

output acrName string = acr.name
output acrResourceId string = acr.id
output acrLoginServer string = acr.properties.loginServer
