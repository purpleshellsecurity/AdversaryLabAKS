// ============================================================================
// AKS Adversary Lab - Subscription-Level Resources
// ============================================================================

targetScope = 'subscription'

param location string
param logAnalyticsWorkspaceId string
param enableDefenderForContainers bool = true
param enableDefenderForKeyVault bool = true

@description('Forward subscription Activity Log to the workspace. Set false if a Sentinel solution already does this.')
param enableActivityLogForwarding bool = false

resource defenderContainers 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderForContainers) {
  name: 'Containers'
  properties: { pricingTier: 'Standard' }
}

resource defenderKeyVault 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderForKeyVault) {
  name: 'KeyVaults'
  properties: { pricingTier: 'Standard' }
}

resource activityLogDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableActivityLogForwarding) {
  name: 'aks-lab-activity-to-law'
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'Administrative', enabled: true }
      { category: 'Security', enabled: true }
      { category: 'ServiceHealth', enabled: true }
      { category: 'Alert', enabled: true }
      { category: 'Recommendation', enabled: true }
      { category: 'Policy', enabled: true }
      { category: 'Autoscale', enabled: true }
      { category: 'ResourceHealth', enabled: true }
    ]
  }
}

output defenderContainersEnabled bool = enableDefenderForContainers
output defenderKeyVaultEnabled bool = enableDefenderForKeyVault
