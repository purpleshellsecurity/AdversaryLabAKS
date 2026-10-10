// ============================================================================
// AKS Adversary Lab - Subscription-Level Resources
// ============================================================================
// PURPOSE IN THE LAB:
//   Some security controls can only be configured at SUBSCRIPTION scope, not
//   resource-group scope. This companion deployment (targetScope = subscription)
//   handles those: it turns on the Microsoft Defender for Cloud plans that
//   protect the lab's containers and Key Vault, and optionally forwards the
//   subscription Activity Log into the lab's Log Analytics workspace.
//
//   Deployed SEPARATELY from main.bicep (which is resource-group scoped) because
//   Bicep files have a single target scope. Run this against the subscription
//   once, pointing it at the same workspace main.bicep uses.
// ============================================================================

targetScope = 'subscription'

// ── Parameters ───────────────────────────────────────────────────────────────

// The lab's Log Analytics workspace resource ID — where the Activity Log (if
// enabled) is forwarded and where Defender surfaces its data.
param logAnalyticsWorkspaceId string

// Toggle the Defender for Containers plan (runtime threat detection, image
// scanning, K8s hardening) at the subscription level. On by default — it's a
// primary detection engine for the container-focused lab.
param enableDefenderForContainers bool = true

// Toggle the Defender for Key Vault plan (alerts on anomalous secret access) at
// the subscription level. On by default to catch credential-access techniques.
param enableDefenderForKeyVault bool = true

@description('''
Forward subscription Activity Log to the workspace.
Set to false when an existing workspace already has activity logs flowing to it
(e.g. via the Sentinel "Azure Activity" content solution, which auto-creates a
diagnostic setting named "AzureActivity-Sentinel-<id>"). Azure rejects a second
diagnostic setting that forwards the same category from the same source to the
same workspace.
''')
// Defaults to false precisely to avoid the duplicate-diagnostic-setting conflict
// described above; flip to true only for a fresh workspace with no existing
// Activity Log pipe.
param enableActivityLogForwarding bool = false

// ── Defender plan: Containers ────────────────────────────────────────────────
// Setting the 'Containers' pricing to Standard = enabling the Defender for
// Containers plan for the whole subscription. Deployed only when the toggle is on.
resource defenderContainers 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderForContainers) {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
  }
}

// ── Defender plan: Key Vaults ────────────────────────────────────────────────
// 'KeyVaults' Standard tier = enable Defender for Key Vault subscription-wide.
resource defenderKeyVault 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderForKeyVault) {
  name: 'KeyVaults'
  properties: {
    pricingTier: 'Standard'
  }
}

// ── Activity Log forwarding ──────────────────────────────────────────────────
// Subscription-scoped diagnostic setting that pipes control-plane Activity Log
// categories into Log Analytics. This is what makes subscription-level admin,
// policy, and security events queryable by Sentinel/KQL. Conditional to avoid
// colliding with an existing forwarder (see enableActivityLogForwarding note).
resource activityLogDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableActivityLogForwarding) {
  name: 'aks-lab-activity-to-law'
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      // Full set of Activity Log categories — administrative changes, security
      // events, service/resource health, alerts, recommendations, policy
      // evaluations, and autoscale — for maximum detection coverage.
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

// ── Outputs ──────────────────────────────────────────────────────────────────
// Echo back which subscription-level controls ended up enabled — handy for the
// deploying pipeline to confirm/record the resulting posture.
output defenderContainersEnabled bool = enableDefenderForContainers
output defenderKeyVaultEnabled bool = enableDefenderForKeyVault
output activityLogForwardingEnabled bool = enableActivityLogForwarding
