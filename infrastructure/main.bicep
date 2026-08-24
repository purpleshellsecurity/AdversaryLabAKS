// ============================================================================
// AKS Adversary Lab - Main Deployment Orchestrator
// MITRE ATT&CK Containers Matrix Coverage
// ============================================================================
// PURPOSE IN THE LAB:
//   This is the top-level, resource-group-scoped entry point that stitches the
//   entire lab together. It doesn't define resources directly; instead it calls
//   the modules in dependency order ("layers") and threads their outputs into
//   one another:
//
//     Layer 1 (Foundation): Log Analytics, networking, ACR, Key Vault
//     Layer 2 (Compute):    AKS cluster + its ACR pull role assignment
//     Layer 3 (Monitoring): AKS diagnostics, Container Insights, Sentinel
//     Layer 3.5 (Content):  detection rules deployed into the workspace
//     Layer 4 (Governance): Azure Policy definitions + assignment
//
//   A central design feature is WORKSPACE RESOLUTION: the lab can either create
//   a fresh Log Analytics workspace or reuse an existing one (even in another
//   resource group or subscription). The variables below compute the right
//   workspace ID/name/location once and reuse them everywhere.
//
//   NOTE: subscription-scoped controls (Defender plans, activity-log
//   forwarding) live in the separate main_subscription.bicep because a Bicep
//   file has a single target scope.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ───────────────────────────────────────────────────────────────

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Name prefix for all resources (lowercase, no special chars)')
@minLength(3)
@maxLength(15)
param namePrefix string

// The Entra group whose members receive Kubernetes cluster-admin (via Azure
// RBAC). This is the human access boundary for the whole cluster.
@description('Entra ID group Object ID for AKS cluster-admin access')
param adminGroupObjectId string

// SECURITY-CRITICAL: the single public IP/CIDR allowed to reach the (public)
// API server. Passed straight into the cluster's authorizedIPRanges. Widening
// this to 0.0.0.0/0 would expose the control plane to the internet.
@description('Your public IP address for API server authorized access')
param authorizedIpRange string

// Only applies when this deployment CREATES a workspace; ignored when reusing an
// existing one (that workspace's own retention already governs its data).
@description('Log Analytics retention in days — ignored when existingWorkspaceResourceId is provided')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 90

// Empty = create a new workspace (the logAnalytics module runs). Non-empty =
// reuse that workspace and skip creation. Drives the whole workspace-resolution
// logic below and enables cross-RG / cross-subscription reuse.
@description('''
Optional: Resource ID of an existing Log Analytics workspace.
Leave empty to create a new workspace.
Format: /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
''')
param existingWorkspaceResourceId string = ''

// Pinned K8s version for reproducibility; forwarded to the cluster module.
@description('Kubernetes version')
param kubernetesVersion string = '1.34.2'

// Control-plane tier. Free by default — a three-node lab does not need the
// SLA that Standard charges ~$73/month for. See modules/aks_cluster.bicep.
@description('AKS control-plane tier. Free = no cluster-management charge.')
@allowed([ 'Free', 'Standard' ])
param clusterTier string = 'Free'

@description('AKS system node pool VM size')
param systemNodeVmSize string = 'Standard_D2s_v3'

@description('AKS user (workload) node pool VM size')
param userNodeVmSize string = 'Standard_D2s_v3'

// Feature toggles forwarded into modules — let the lab be deployed with lighter
// footprint / lower cost when a given detection engine isn't needed.
@description('Enable Microsoft Defender for Containers')
param enableDefender bool = true

@description('Enable Azure Policy add-on for AKS')
param enableAzurePolicy bool = true

// Gates BOTH the Sentinel onboarding module and the detection-content module
// below (detections have nothing to attach to without Sentinel on the workspace).
@description('Deploy Sentinel solutions for AKS/Container monitoring')
param enableSentinelSolutions bool = true

// Applied to every resource for cost attribution, ownership, and easy cleanup.
@description('Tags applied to all resources')
param tags object = {
  Environment: 'SecurityLab'
  Project: 'AKS-Adversary-Lab'
  Purpose: 'MITRE-ATT&CK-Containers'
  ManagedBy: 'Bicep'
}

// ── Workspace resolution ────────────────────────────────────────────────────
// Supports both new workspace creation and existing workspace reuse,
// including cross-resource-group and cross-subscription scenarios.
//
// Resource ID format:
//   /subscriptions/{sub}/resourceGroups/{rg}/providers/
//   Microsoft.OperationalInsights/workspaces/{name}

// True when a workspace ID was supplied → reuse mode; false → create mode.
var useExistingWorkspace = existingWorkspaceResourceId != ''

// The workspace ID every downstream module receives: either the supplied ID or
// the newly-created workspace's output. (The '!' asserts the conditional
// logAnalytics module is present in the create branch.)
var resolvedWorkspaceId = useExistingWorkspace
  ? existingWorkspaceResourceId
  : logAnalytics!.outputs.workspaceResourceId

// The workspace's short name — needed by Sentinel/detection modules that
// reference it by name. Parsed from the last segment of a supplied ID.
var resolvedWorkspaceName = useExistingWorkspace
  ? last(split(existingWorkspaceResourceId, '/'))
  : logAnalytics!.outputs.workspaceName

// Parse workspace location for cross-RG/cross-sub scoping.
// When using an existing workspace, parse from the input ID directly
// (calculable at graph-build time — no dependency on deployed outputs).
// When creating a new workspace, it lives in the current deployment's RG.

var workspaceSubscriptionId = useExistingWorkspace
  ? split(existingWorkspaceResourceId, '/')[2]
  : subscription().subscriptionId

var workspaceResourceGroup = useExistingWorkspace
  ? split(existingWorkspaceResourceId, '/')[4]
  : resourceGroup().name

// ── Layer 1: Foundation ─────────────────────────────────────────────────────
// Independent building blocks with no dependency on the cluster. The 'if'
// guard on logAnalytics is what implements create-vs-reuse of the workspace.

// Log Analytics workspace — created ONLY when not reusing an existing one.
module logAnalytics 'modules/log_analytics.bicep' = if (!useExistingWorkspace) {
  name: 'deploy-log-analytics'
  params: {
    location: location
    namePrefix: namePrefix
    retentionInDays: logRetentionDays
    tags: tags
  }
}

// VNet + subnets + NSGs. Provides the subnet IDs the cluster's node pools use.
module networking 'modules/aks_networking.bicep' = {
  name: 'deploy-aks-networking'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

// Container registry (with diagnostics → resolved workspace).
module acr 'modules/aks_acr.bicep' = {
  name: 'deploy-acr'
  params: {
    location: location
    namePrefix: namePrefix
    logAnalyticsWorkspaceId: resolvedWorkspaceId
    tags: tags
  }
}

// Key Vault (with diagnostics → resolved workspace).
module keyVault 'modules/aks_keyvault.bicep' = {
  name: 'deploy-keyvault'
  params: {
    location: location
    namePrefix: namePrefix
    logAnalyticsWorkspaceId: resolvedWorkspaceId
    tags: tags
  }
}

// ── Layer 2: Compute ────────────────────────────────────────────────────────
// The cluster and its dependent role assignment. Bicep infers ordering from the
// networking.outputs / resolvedWorkspaceId references (no explicit dependsOn).

// The AKS cluster itself — consumes the subnet IDs and the workspace ID, and
// receives the security-critical adminGroupObjectId and authorizedIpRange.
module aksCluster 'modules/aks_cluster.bicep' = {
  name: 'deploy-aks-cluster'
  params: {
    location: location
    namePrefix: namePrefix
    kubernetesVersion: kubernetesVersion
    clusterTier: clusterTier
    systemNodeVmSize: systemNodeVmSize
    userNodeVmSize: userNodeVmSize
    systemSubnetId: networking.outputs.systemSubnetId
    userSubnetId: networking.outputs.userSubnetId
    logAnalyticsWorkspaceResourceId: resolvedWorkspaceId
    adminGroupObjectId: adminGroupObjectId
    authorizedIpRange: authorizedIpRange
    enableDefender: enableDefender
    enableAzurePolicy: enableAzurePolicy
    tags: tags
  }
}

// Grants the cluster's kubelet identity AcrPull on the registry (credential-free
// image pulls). Depends implicitly on both the ACR and the cluster outputs.
module acrRoleAssignment 'modules/aks_acr_role.bicep' = {
  name: 'deploy-acr-role'
  params: {
    acrName: acr.outputs.acrName
    aksPrincipalId: aksCluster.outputs.kubeletIdentityObjectId
  }
}

// ── Layer 3: Monitoring ─────────────────────────────────────────────────────
// Turns the raw cluster into a detection source and onboards Sentinel content.

// Full AKS control-plane diagnostics (incl. kube-audit) → workspace. This is the
// backbone of the lab's detections.
module aksDiagnostics 'modules/aks_diagnostics.bicep' = {
  name: 'deploy-aks-diagnostics'
  params: {
    aksClusterName: aksCluster.outputs.clusterName
    logAnalyticsWorkspaceId: resolvedWorkspaceId
  }
}

// Container Insights (workload-level container telemetry / performance data).
module containerInsights 'modules/container_insights.bicep' = {
  name: 'deploy-container-insights'
  params: {
    location: location
    namePrefix: namePrefix
    aksClusterName: aksCluster.outputs.clusterName
    logAnalyticsWorkspaceResourceId: resolvedWorkspaceId
  }
}

// Sentinel onboarding and content packages must run in the workspace's
// resource group, not the lab's. The 'scope' parameter handles this for
// both same-RG and cross-RG workspaces.
module sentinel 'modules/aks_sentinel.bicep' = if (enableSentinelSolutions) {
  name: 'deploy-aks-sentinel'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: resolvedWorkspaceName
  }
}

// ── Layer 3.5: Detection Content ────────────────────────────────────────────
// Detection content also targets the workspace, so scoped to the workspace's RG.

// T1098.006 keeps its own self-contained package (query + rule + attack script
// in one folder). It is the layout the rest of the library is migrating toward.
module detectionT1098006 '../detections/T1098.006-cluster-role-binding/rule.bicep' = if (enableSentinelSolutions) {
  name: 'deploy-detection-T1098-006'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: resolvedWorkspaceName
  }
  dependsOn: [
    sentinel
  ]
}

// Everything under detections/kql/ — each rule paired with a metadata sidecar
// that carries its severity, ATT&CK mapping, schedule, and entity mappings.
// Without this module those rules were validated and fixture-tested in CI and
// then never deployed, so nothing in Azure ever ran them.
module detectionsKql 'modules/aks_detections.bicep' = if (enableSentinelSolutions) {
  name: 'deploy-detections-kql'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: resolvedWorkspaceName
  }
  dependsOn: [
    sentinel
  ]
}

// ── Layer 4: Governance ─────────────────────────────────────────────────────
// Azure Policy definitions + assignment that codify the lab's compliance
// guardrails and feed compliance state alongside the detections.

// Policy DEFINITIONS/initiative live at SUBSCRIPTION scope (that's where custom
// policy/initiative definitions must be created), hence the explicit scope.
module aksPolicyDefs 'modules/aks_policy_defs.bicep' = {
  name: 'deploy-aks-policy-defs'
  scope: subscription()
}

// Policy ASSIGNMENT (resource-group scoped) that binds the initiative above to
// this RG and routes compliance data to the resolved workspace.
module aksPolicy 'modules/aks_policy.bicep' = {
  name: 'deploy-aks-policy'
  params: {
    initiativeId: aksPolicyDefs.outputs.initiativeId
    logAnalyticsWorkspaceId: resolvedWorkspaceId
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────
// Surfaced to the deploying user/pipeline: enough to connect to the cluster and
// locate the supporting resources without hunting through the portal.

output clusterName string = aksCluster.outputs.clusterName
// Public API-server FQDN.
output clusterFqdn string = aksCluster.outputs.clusterFqdn
// Ready-to-run command to fetch cluster credentials into the local kubeconfig.
output kubectlConnectCommand string = 'az aks get-credentials --resource-group ${resourceGroup().name} --name ${aksCluster.outputs.clusterName}'
// Resolved workspace identifiers (whether newly created or reused).
output logAnalyticsWorkspaceName string = resolvedWorkspaceName
output logAnalyticsWorkspaceId string = resolvedWorkspaceId
// True if this deployment created the workspace; false if an existing one was reused.
output workspaceIsNew bool = !useExistingWorkspace
// ACR endpoint for docker login / image references.
output acrLoginServer string = acr.outputs.acrLoginServer
// Key Vault identifiers for wiring up secrets.
output keyVaultName string = keyVault.outputs.keyVaultName
output keyVaultUri string = keyVault.outputs.keyVaultUri
// Detection content actually shipped, so the deploy job can report it rather
// than leaving "did my rules deploy?" as something to check in the portal.
// Zero when enableSentinelSolutions is false — no workspace, no analytics rules.
// `.?` safe-dereference: the module is conditional, so its outputs are null when
// enableSentinelSolutions is false. `?? 0` supplies the fallback without Bicep
// warning that the access could fail. The `+ 1` accounts for the separately
// deployed T1098.006 package.
output detectionRulesDeployed int = enableSentinelSolutions ? (detectionsKql.?outputs.deployedRuleCount ?? 0) + 1 : 0
output detectionRulesEnabled int = enableSentinelSolutions ? (detectionsKql.?outputs.enabledRuleCount ?? 0) + 1 : 0
