// Layer 3: Monitoring - AKS Diagnostic Settings (all 11 categories)

param aksClusterName string
param logAnalyticsWorkspaceId string

resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-02-01' existing = {
  name: aksClusterName
}

resource aksDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${aksClusterName}-full-security-diag'
  scope: aksCluster
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'kube-audit', enabled: true }
      { category: 'kube-audit-admin', enabled: true }
      { category: 'kube-apiserver', enabled: true }
      { category: 'kube-controller-manager', enabled: true }
      { category: 'kube-scheduler', enabled: true }
      { category: 'cluster-autoscaler', enabled: true }
      { category: 'cloud-controller-manager', enabled: true }
      { category: 'guard', enabled: true }
      { category: 'csi-azuredisk-controller', enabled: true }
      { category: 'csi-azurefile-controller', enabled: true }
      { category: 'csi-snapshot-controller', enabled: true }
    ]
    metrics: [ { category: 'AllMetrics', enabled: true } ]
  }
}

output diagnosticSettingsName string = aksDiagnostics.name
output diagnosticSettingsId string = aksDiagnostics.id
