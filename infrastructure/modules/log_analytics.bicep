// ============================================================================
// Layer 1: Foundation - Log Analytics Workspace
// ============================================================================
// PURPOSE IN THE LAB:
//   This is the central "brain" for all telemetry in the AKS Adversary Lab.
//   Every other component (AKS control-plane audit logs, ACR, Key Vault,
//   Microsoft Defender for Containers, Container Insights, and Microsoft
//   Sentinel) forwards its logs/metrics here. Analysts run KQL queries and
//   Sentinel detections against this single workspace to hunt for the
//   MITRE ATT&CK techniques the lab is designed to reproduce.
//
//   Because so much detection content depends on it, this workspace is
//   deployed FIRST (Layer 1) and its resource ID is threaded into nearly
//   every downstream module. main.bicep can also skip creating this module
//   entirely and reuse a pre-existing workspace instead.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

// Azure region. Passed down from main.bicep so the workspace lives alongside
// the rest of the lab (co-location avoids cross-region data egress charges).
param location string

// Short prefix used to build a predictable, human-readable workspace name.
param namePrefix string

// How long ingested logs are kept before Azure purges them. 90 days by default
// gives analysts a useful hunting window. main.bicep constrains this to 30-730.
param retentionInDays int = 90

// Resource tags propagated from main.bicep for cost tracking / cleanup.
param tags object = {}

// ── Derived names ────────────────────────────────────────────────────────────

// Deterministic workspace name, e.g. "seclab-aks-law".
var workspaceName = '${namePrefix}-aks-law'

// ── Resource: Log Analytics Workspace ────────────────────────────────────────

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    // PerGB2018 is the standard pay-as-you-go pricing tier (billed per GB
    // ingested). Appropriate for a lab where volume is modest and predictable.
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    features: {
      // Enforce that a user must have Azure RBAC permission on the SOURCE
      // resource to read its logs in this workspace (resource-context RBAC).
      // This is a hardening control: it prevents someone with only workspace
      // access from reading logs of resources they otherwise can't see.
      enableLogAccessUsingOnlyResourcePermissions: true
      // Local (shared-key) auth for ingestion is left ENABLED (disableLocalAuth
      // = false). This is intentionally permissive for a lab so agents/tools
      // that push data with workspace keys keep working; in production you would
      // set this true to force Entra ID (AAD) authentication only.
      disableLocalAuth: false
    }
    // dailyQuotaGb: -1 means NO daily ingestion cap. Convenient for a lab so
    // detections never silently drop data, but it removes a cost guardrail —
    // set a positive number in production to bound spend.
    workspaceCapping: { dailyQuotaGb: -1 }
    // Ingestion and query are reachable over the public internet. Simplifies
    // lab setup (no Private Link plumbing) but is deliberately less locked-down
    // than a production workspace, which would use 'Disabled' + private endpoints.
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────

// Friendly workspace name — used by Sentinel onboarding and detection modules
// that reference the workspace by name within its resource group.
output workspaceName string = workspace.name
// The workspace GUID ("customerId") — the value the OMS/monitoring agents use
// to identify which workspace to send data to.
output workspaceId string = workspace.properties.customerId
// Full ARM resource ID — the canonical handle threaded into diagnostic settings,
// Defender, and Container Insights across the whole deployment.
output workspaceResourceId string = workspace.id
