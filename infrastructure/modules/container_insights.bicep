// Layer 3: Monitoring - Container Insights (Data Collection Rule)

param location string
param namePrefix string
param aksClusterName string
param logAnalyticsWorkspaceResourceId string

var dcrName = '${namePrefix}-aks-ci-dcr'

resource containerInsightsDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Linux'
  properties: {
    dataSources: {
      extensions: [
        {
          name: 'ContainerInsightsExtension'
          extensionName: 'ContainerInsights'
          streams: [
            'Microsoft-ContainerLogV2'
            'Microsoft-KubeEvents'
            'Microsoft-KubePodInventory'
            'Microsoft-KubeNodeInventory'
            'Microsoft-KubeServices'
            'Microsoft-KubeMonAgentEvents'
            'Microsoft-InsightsMetrics'
            'Microsoft-ContainerInventory'
            'Microsoft-ContainerNodeInventory'
            'Microsoft-Perf'
          ]
          extensionSettings: {
            dataCollectionSettings: {
              interval: '1m'
              namespaceFilteringMode: 'Off'
              enableContainerLogV2: true
            }
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceResourceId
          name: 'ciworkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-ContainerLogV2'
          'Microsoft-KubeEvents'
          'Microsoft-KubePodInventory'
          'Microsoft-KubeNodeInventory'
          'Microsoft-KubeServices'
          'Microsoft-KubeMonAgentEvents'
          'Microsoft-InsightsMetrics'
          'Microsoft-ContainerInventory'
          'Microsoft-ContainerNodeInventory'
          'Microsoft-Perf'
        ]
        destinations: [ 'ciworkspace' ]
      }
    ]
  }
}

resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' existing = {
  name: aksClusterName
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'ContainerInsightsExtension'
  scope: aksCluster
  properties: {
    dataCollectionRuleId: containerInsightsDcr.id
    description: 'Container Insights DCR association for AKS adversary lab'
  }
}

output dcrId string = containerInsightsDcr.id
output dcrName string = containerInsightsDcr.name
output dcrAssociationId string = dcrAssociation.id
