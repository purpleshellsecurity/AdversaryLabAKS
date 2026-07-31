// ============================================================================
// Layer 2: Compute - ACR Pull Role Assignment
// ============================================================================
// PURPOSE IN THE LAB:
//   Grants the AKS cluster permission to pull container images from the lab's
//   Azure Container Registry WITHOUT any stored credentials. It assigns the
//   built-in "AcrPull" role to the cluster's kubelet managed identity, scoped
//   to just the one registry.
//
//   This runs in Layer 2 (Compute), after both the ACR (Layer 1) and the AKS
//   cluster exist, because it needs the ACR's name and the kubelet identity's
//   principal ID as inputs.
//
//   SECURITY NOTE: This is the least-privilege, credential-free pattern — a
//   genuine hardening control, not a lab shortcut. AcrPull is pull-only (no
//   push/delete) and is scoped to this single registry.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

// Name of the target ACR (from aks_acr.bicep's output).
param acrName string
// Object/principal ID of the AKS kubelet managed identity — the identity the
// nodes actually use to pull images (from aks_cluster.bicep's output).
param aksPrincipalId string

// ── Role definition lookup ───────────────────────────────────────────────────
// Fixed GUID of the built-in "AcrPull" role. subscriptionResourceId() builds the
// full role-definition resource ID from that well-known GUID.
var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')

// ── Existing resource reference ──────────────────────────────────────────────
// Reference (do not create) the already-deployed registry so the role assignment
// can be scoped precisely to it.
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

// ── Role assignment ──────────────────────────────────────────────────────────
resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  // Role assignment names must be GUIDs and stable/deterministic. Deriving the
  // name from (scope + principal + role) makes redeployments idempotent — the
  // same three inputs always yield the same assignment instead of a duplicate.
  name: guid(acr.id, aksPrincipalId, acrPullRoleId)
  // Scope the grant to THIS registry only (least privilege), not the whole RG/sub.
  scope: acr
  properties: {
    principalId: aksPrincipalId
    roleDefinitionId: acrPullRoleId
    // Declaring the principal type as ServicePrincipal (a managed identity is a
    // service principal) avoids replication-lag failures where ARM can't yet
    // resolve a brand-new identity's type.
    principalType: 'ServicePrincipal'
  }
}

// ── Output ───────────────────────────────────────────────────────────────────
output roleAssignmentId string = acrPullAssignment.id
