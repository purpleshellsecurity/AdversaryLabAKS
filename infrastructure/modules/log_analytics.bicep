// Layer 1: Foundation - Log Analytics Workspace

param location string
param namePrefix string
param retentionInDays int = 90
param tags object = {}

var workspaceName = '${namePrefix}-aks-law'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      disableLocalAuth: false
    }
    workspaceCapping: { dailyQuotaGb: -1 }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceName string = workspace.name
output workspaceId string = workspace.properties.customerId
output workspaceResourceId string = workspace.id
