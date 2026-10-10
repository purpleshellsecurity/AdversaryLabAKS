// ============================================================================
// Layer 4: Governance - Policy Assignment (Resource Group Scope)
// ============================================================================
//
// PURPOSE
//   This module ASSIGNS the custom "MITRE ATT&CK Containers Logging & Security"
//   policy initiative (a policySetDefinition) to a single resource group. The
//   initiative itself — the collection of policy definitions — is authored in
//   aks_policy_defs.bicep at subscription scope. Here we bind that initiative to
//   the lab's resource group so its rules actively evaluate (and, for the
//   DeployIfNotExists policies, remediate) the AKS cluster and Key Vault living
//   in that group.
//
// ROLE IN THE DETECTION / LOGGING PIPELINE
//   Governance is the enforcement backbone of the lab's telemetry. The initiative
//   guarantees that the AKS control-plane diagnostic categories (kube-audit,
//   kube-apiserver, guard, etc.) are flowing into Log Analytics. Without those
//   logs, the Sentinel analytics rules (Layer 3) have nothing to hunt over. So
//   this assignment is what actually "turns on" the audit trail that every
//   downstream MITRE-aligned detection depends on.
//
// WHY A MANAGED IDENTITY + ROLE ASSIGNMENTS
//   DeployIfNotExists (DINE) and AuditIfNotExists (AINE) policies must be able to
//   read resource state and, for DINE, deploy remediation (a diagnosticSettings
//   resource). Azure Policy performs those actions using the assignment's
//   SystemAssigned managed identity. That identity is powerless until we grant it
//   the roles below, so the three roleAssignments are mandatory for remediation
//   to succeed — otherwise remediation tasks fail with authorization errors.
// ============================================================================

// Deploy this module against a resource group. The policy assignment, the
// managed identity, and the role assignments all live at RG scope.
targetScope = 'resourceGroup'

// Resource ID of the policySetDefinition (initiative) produced by
// aks_policy_defs.bicep. We assign this exact initiative — passing the ID in
// (rather than referencing the resource) keeps the two modules loosely coupled
// across their different scopes (subscription vs. resource group).
@description('The resource ID of the policy initiative to assign')
param initiativeId string

// The Log Analytics workspace that the DeployIfNotExists diagnostic policies
// should send AKS/Key Vault logs to. Passed through to the initiative as its
// single parameter so remediated diagnostic settings point at the right sink.
@description('Log Analytics Workspace Resource ID for the initiative parameter')
param logAnalyticsWorkspaceId string

// --- The initiative assignment -------------------------------------------------
// Binds the initiative to this resource group so its policies begin evaluating.
resource initiativeAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: 'aks-lab-mitre-logging'
  location: resourceGroup().location
  // SystemAssigned identity is REQUIRED for DeployIfNotExists/AuditIfNotExists
  // effects: Azure Policy uses it to inspect resources and deploy remediation.
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'AKS Adversary Lab - MITRE Logging Enforcement'
    description: 'DeployIfNotExists enforcement for all 11 AKS diagnostic categories.'
    // The initiative to enforce (authored at subscription scope).
    policyDefinitionId: initiativeId
    // 'Default' = policy effects are actively applied (as opposed to 'DoNotEnforce',
    // which would evaluate compliance but suppress Deny/DINE actions). We want the
    // logging to actually be enforced/remediated, so Default is correct.
    enforcementMode: 'Default'
    parameters: {
      // Feed the workspace ID into the initiative's own logAnalyticsWorkspaceId
      // parameter, wiring diagnostic remediation to the lab's log sink.
      logAnalyticsWorkspaceId: { value: logAnalyticsWorkspaceId }
    }
    // Message surfaced in the Azure Policy compliance blade when a cluster is
    // non-compliant, giving the learner an immediate, human-readable reason.
    nonComplianceMessages: [
      { message: 'This AKS cluster is missing full diagnostic logging.' }
    ]
  }
}

// --- Role grants for the assignment's managed identity ------------------------
// Each roleAssignment below grants the policy's SystemAssigned identity a role it
// needs to inspect resources and deploy the diagnosticSettings remediation.
// The role GUIDs are Azure's well-known built-in role definition IDs.

// Monitoring Contributor (749f88d5-...): lets the identity create/modify
// diagnostic settings — the core action of the DINE diagnostic policies.
resource assignmentMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  // Deterministic GUID name so redeploys are idempotent (same inputs -> same name).
  name: guid(initiativeAssignment.id, 'monitoring-contributor')
  properties: {
    // Grant the role to the policy assignment's managed identity.
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '749f88d5-cbae-40b8-bcfc-e573ddc772fa')
    // Declaring the principal type as ServicePrincipal avoids a race where the
    // freshly-created identity isn't yet replicated in Entra ID at assignment time.
    principalType: 'ServicePrincipal'
  }
}

// Log Analytics Contributor (92aaf0da-...): lets the identity read the target
// workspace and wire diagnostic settings to it (required to satisfy the DINE
// deployment that points logs at Log Analytics).
resource assignmentLogAnalyticsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'log-analytics-contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '92aaf0da-9dab-42b6-94a3-d43ce8d16293')
    principalType: 'ServicePrincipal'
  }
}

// Contributor (b24988ac-...): broad create/manage role. Included so the
// remediation deployment (an ARM sub-deployment that creates the
// diagnosticSettings child resource on the AKS cluster / Key Vault) has
// sufficient rights regardless of resource type.
resource assignmentContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalType: 'ServicePrincipal'
  }
}

// --- Outputs ------------------------------------------------------------------
// Full resource ID of the assignment — useful for creating remediation tasks or
// referencing the assignment from other modules/scripts.
output assignmentId string = initiativeAssignment.id
// The managed identity's principal ID — handy for verifying/auditing the role
// grants that make remediation possible.
output assignmentPrincipalId string = initiativeAssignment.identity.principalId
