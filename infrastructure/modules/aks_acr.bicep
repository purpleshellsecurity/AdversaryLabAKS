// ============================================================================
// Layer 1: Foundation - Azure Container Registry (ACR)
// ============================================================================
// PURPOSE IN THE LAB:
//   Provides the private container registry that the AKS cluster pulls images
//   from. In the adversary lab this is where "victim" workloads and any
//   attacker-staged images live, so its access model and its logs are both
//   detection-relevant (e.g. spotting anomalous image pushes/pulls).
//
//   Deployed in Layer 1 (Foundation). The kubelet identity of the AKS cluster
//   is later granted AcrPull on this registry by aks_acr_role.bicep, so the
//   cluster can pull without any stored credentials.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

param location string
param namePrefix string
// Log Analytics workspace resource ID — target for this registry's diagnostics.
param logAnalyticsWorkspaceId string
param tags object = {}

// ── Derived name ─────────────────────────────────────────────────────────────
// ACR names must be globally unique and alphanumeric only. We strip dashes from
// the prefix, append "acr", and add 6 chars of a deterministic hash of the RG ID
// to avoid global name collisions, e.g. "seclabacr3f9a1c".
var acrName = '${toLower(replace(namePrefix, '-', ''))}acr${substring(uniqueString(resourceGroup().id), 0, 6)}'

// ── Resource: Container Registry ─────────────────────────────────────────────
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: acrName
  location: location
  tags: tags
  // Standard tier: enough storage/throughput for a lab; Premium would be needed
  // for private endpoints, geo-replication, and content trust.
  sku: { name: 'Standard' }
  properties: {
    // HARDENING (good practice): the admin user (a static username/password with
    // full registry access) is disabled. Access is instead via Entra ID / the
    // AcrPull role assignment granted to the AKS kubelet identity.
    adminUserEnabled: false
    // INTENTIONALLY PERMISSIVE for the lab: the registry is reachable over the
    // public internet. Simplifies image push from a workstation. Production would
    // use 'Disabled' plus a private endpoint (which also requires Premium SKU).
    publicNetworkAccess: 'Enabled'
    // Customer-managed-key encryption disabled — images are still encrypted at
    // rest with Microsoft-managed keys; CMK just isn't layered on for the lab.
    encryption: { status: 'disabled' }
    // Dedicated data endpoints off (a Premium anti-exfiltration / Private Link
    // feature); not applicable on Standard.
    dataEndpointEnabled: false
  }
}

// ── Diagnostic settings ──────────────────────────────────────────────────────
// Ships all ACR log categories and metrics to Log Analytics so registry
// activity (image pushes, pulls, deletes) is queryable by Sentinel detections.
resource acrDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'acr-to-law'
  scope: acr
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [ { categoryGroup: 'allLogs', enabled: true } ]
    metrics: [ { category: 'AllMetrics', enabled: true } ]
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
// acrName is consumed by aks_acr_role.bicep (to look up the registry for the
// role assignment); loginServer is surfaced by main.bicep for docker/kubectl use.
output acrName string = acr.name
output acrResourceId string = acr.id
output acrLoginServer string = acr.properties.loginServer
