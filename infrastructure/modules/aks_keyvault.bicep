// ============================================================================
// Layer 1: Foundation - Azure Key Vault
// ============================================================================
// PURPOSE IN THE LAB:
//   Provides a secrets store for the cluster. The AKS Key Vault Secrets Provider
//   add-on (enabled in aks_cluster.bicep) mounts secrets from here into pods via
//   CSI. In the adversary lab, Key Vault access is itself a detection target:
//   Defender for Key Vault + diagnostic logs let analysts hunt for suspicious
//   secret-access patterns (e.g. credential theft techniques).
//
//   Deployed in Layer 1 (Foundation) so it exists before the cluster's secrets
//   provider needs it.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

param location string
param namePrefix string
// Log Analytics workspace resource ID — destination for this vault's diagnostics.
param logAnalyticsWorkspaceId string
param tags object = {}

// ── Derived name ─────────────────────────────────────────────────────────────
// Key Vault names are globally unique, 3-24 chars, alphanumeric + dashes. Build
// "kv" + dash-stripped lowercase prefix + 4 hash chars of the RG ID for
// uniqueness, e.g. "kvseclab3f9a".
var keyVaultName = 'kv${toLower(replace(namePrefix, '-', ''))}${substring(uniqueString(resourceGroup().id), 0, 4)}'

// ── Resource: Key Vault ──────────────────────────────────────────────────────
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: { family: 'A', name: 'standard' }
    // Tenant that owns the vault's identities/RBAC — the deploying subscription's.
    tenantId: subscription().tenantId
    // HARDENING (good practice): use Azure RBAC for data-plane authorization
    // instead of legacy vault access policies. Cleaner, auditable, and lets the
    // AKS workload identity be granted precise roles.
    enableRbacAuthorization: true
    // Soft delete on (mandatory anyway) so deleted secrets/vaults are recoverable.
    enableSoftDelete: true
    // 7 days is the minimum retention — chosen so the lab can be torn down and
    // the same vault name reused quickly. Production would keep this higher.
    softDeleteRetentionInDays: 7
    // INTENTIONALLY PERMISSIVE for the lab: the vault data plane is reachable
    // from the public internet. Simplifies access from a workstation. Production
    // would set 'Disabled' and reach the vault via a private endpoint.
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      // defaultAction 'Allow' = no IP/VNet firewall; anyone who passes RBAC can
      // reach it. This is the permissive lab posture; a hardened vault would set
      // 'Deny' and explicitly allow only trusted subnets/IPs.
      defaultAction: 'Allow'
      // Even under a Deny posture, trusted Azure platform services could bypass
      // the firewall — set here for consistency, though it's moot while default
      // is Allow.
      bypass: 'AzureServices'
    }
  }
}

// ── Diagnostic settings ──────────────────────────────────────────────────────
// Forwards all Key Vault audit logs (every secret get/list/set, etc.) and
// metrics to Log Analytics — the raw material for credential-access detections.
resource kvDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-to-law'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [ { categoryGroup: 'allLogs', enabled: true } ]
    metrics: [ { category: 'AllMetrics', enabled: true } ]
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
output keyVaultName string = keyVault.name
output keyVaultResourceId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
