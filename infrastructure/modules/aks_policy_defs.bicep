// ============================================================================
// Layer 4: Governance - Policy Definitions + Initiative (Subscription Scope)
// ============================================================================
//
// PURPOSE
//   Authors the lab's custom Azure Policy definitions and bundles them (together
//   with several Microsoft built-in policies) into a single policy INITIATIVE
//   (policySetDefinition). The initiative is later ASSIGNED to the lab resource
//   group by aks_policy.bicep, which is what actually makes these rules evaluate
//   and remediate.
//
// ROLE IN THE DETECTION / LOGGING PIPELINE
//   This file is the foundation of the whole detection stack. Two kinds of policy
//   appear here:
//     * DeployIfNotExists (DINE) diagnostic policies — guarantee that AKS and Key
//       Vault emit their security logs into Log Analytics. Those logs are the raw
//       material every Sentinel detection queries. No logs => no detections.
//     * Audit policies (custom + built-in) — continuously assess the cluster's
//       security posture (network policy, Defender sensor, Entra RBAC, pod
//       security, API access) and mark drift as non-compliant. This is
//       configuration-drift detection, complementing the runtime detections.
//
//   MITRE ALIGNMENT
//   The AKS control-plane categories enabled here map to adversary behaviour the
//   SOC must see: kube-audit / kube-apiserver (Discovery, Execution via the API),
//   guard (Entra AuthN/AuthZ -> Credential Access, Privilege Escalation), the
//   controller/scheduler logs (Persistence, Impact), and CSI logs (storage abuse).
//
// SCOPE
//   targetScope = 'subscription' because policyDefinitions and policySetDefinitions
//   are subscription-level (or higher) resources. The ASSIGNMENT lives lower, at
//   resource-group scope, in aks_policy.bicep.
// ============================================================================

targetScope = 'subscription'

// ============================================================================
// SECTION 1 - CUSTOM POLICY: AKS full diagnostic logging (DeployIfNotExists)
// ----------------------------------------------------------------------------
// The centerpiece logging policy. It ensures every AKS cluster has a diagnostic
// setting that ships ALL 11 control-plane log categories to Log Analytics in
// resource-specific ("Dedicated") mode. This is the policy that populates the
// tables the MITRE-aligned Sentinel rules hunt over.
// ============================================================================
resource dineDiagPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-dine-all-diag-categories'
  properties: {
    policyType: 'Custom'
    // 'Indexed' = evaluate only resource types that support tags/location, which
    // is the correct mode for policies that target a specific ARM resource type.
    mode: 'Indexed'
    displayName: 'Deploy diagnostic settings for AKS with all 11 log categories'
    description: 'Automatically deploys a diagnostic setting on AKS clusters that enables all 11 log categories in resource-specific mode.'
    metadata: { category: 'Kubernetes', version: '2.0.0' }
    parameters: {
      // The Log Analytics sink. strongType 'omsWorkspace' gives a picker in the
      // portal; assignPermissions:true tells Azure to auto-grant the assignment's
      // managed identity access to this workspace during remediation.
      logAnalyticsWorkspaceId: {
        type: 'String'
        metadata: { displayName: 'Log Analytics Workspace Resource ID', strongType: 'omsWorkspace', assignPermissions: true }
      }
      // Lets the assignment choose enforce (DINE) vs. audit-only (AINE) vs. off.
      // The initiative below actually assigns this as AuditIfNotExists.
      effect: {
        type: 'String'
        metadata: { displayName: 'Effect' }
        allowedValues: [ 'DeployIfNotExists', 'AuditIfNotExists', 'Disabled' ]
        defaultValue: 'DeployIfNotExists'
      }
      // Name given to the diagnostic setting the policy deploys.
      diagnosticSettingName: {
        type: 'String'
        metadata: { displayName: 'Diagnostic Setting Name' }
        defaultValue: 'aks-full-security-diag-policy'
      }
    }
    policyRule: {
      // Scope the rule to AKS managed clusters only.
      if: { field: 'type', equals: 'Microsoft.ContainerService/managedClusters' }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          // The related resource the policy inspects/deploys: a diagnostic setting.
          type: 'Microsoft.Insights/diagnosticSettings'
          name: '[parameters(\'diagnosticSettingName\')]'
          // Roles the remediation identity needs: Monitoring Contributor +
          // Log Analytics Contributor (same GUIDs granted in aks_policy.bicep).
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
            '/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
          ]
          // COMPLIANCE TEST: a cluster is compliant only if a diagnostic setting
          // already exists that (a) points at the correct workspace AND (b) has at
          // least 11 enabled log categories drawn from the required list below.
          // If not, DINE deploys the template; AINE just flags non-compliance.
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Insights/diagnosticSettings/workspaceId', equals: '[parameters(\'logAnalyticsWorkspaceId\')]' }
              {
                // Count enabled log entries whose category is one of the 11 required
                // AKS control-plane categories; require >= 11 (i.e. all present).
                count: {
                  field: 'Microsoft.Insights/diagnosticSettings/logs[*]'
                  where: {
                    allOf: [
                      { field: 'Microsoft.Insights/diagnosticSettings/logs[*].enabled', equals: 'true' }
                      {
                        field: 'Microsoft.Insights/diagnosticSettings/logs[*].category'
                        in: [
                          'kube-audit'                 // full API audit trail (Discovery/Execution) - highest-value log
                          'kube-audit-admin'           // audit minus request/response bodies (lower volume)
                          'kube-apiserver'             // API server activity
                          'kube-controller-manager'    // reconcilers (Persistence/Impact signals)
                          'kube-scheduler'             // pod scheduling decisions
                          'cluster-autoscaler'         // node scaling events
                          'cloud-controller-manager'   // cloud integration ops
                          'guard'                       // Entra ID AuthN/AuthZ (Credential Access / Priv Esc)
                          'csi-azuredisk-controller'   // disk CSI driver (storage abuse)
                          'csi-azurefile-controller'   // file CSI driver
                          'csi-snapshot-controller'    // snapshot CSI driver
                        ]
                      }
                    ]
                  }
                }
                greaterOrEquals: 11
              }
            ]
          }
          // REMEDIATION: an embedded ARM template that creates the diagnostic
          // setting on the offending cluster with all 11 categories enabled.
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                // Template params are fed from the policy via the parameters block below.
                parameters: {
                  clusterName: { type: 'string' }
                  clusterLocation: { type: 'string' }
                  logAnalyticsWorkspaceId: { type: 'string' }
                  diagnosticSettingName: { type: 'string' }
                }
                resources: [
                  {
                    // Child diagnosticSettings resource attached to the AKS cluster.
                    type: 'Microsoft.ContainerService/managedClusters/providers/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: '[concat(parameters(\'clusterName\'), \'/Microsoft.Insights/\', parameters(\'diagnosticSettingName\'))]'
                    location: '[parameters(\'clusterLocation\')]'
                    properties: {
                      workspaceId: '[parameters(\'logAnalyticsWorkspaceId\')]'
                      // 'Dedicated' = resource-specific tables (AKSAudit, AKSControlPlane, ...)
                      // instead of the generic AzureDiagnostics table — cleaner schema and
                      // better query performance for the Sentinel detections.
                      logAnalyticsDestinationType: 'Dedicated'
                      // Enable every one of the 11 categories the existenceCondition checks for.
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
                ]
              }
              // Bind template params to policy values: field() pulls name/location
              // from the non-compliant cluster being remediated.
              parameters: {
                clusterName: { value: '[field(\'name\')]' }
                clusterLocation: { value: '[field(\'location\')]' }
                logAnalyticsWorkspaceId: { value: '[parameters(\'logAnalyticsWorkspaceId\')]' }
                diagnosticSettingName: { value: '[parameters(\'diagnosticSettingName\')]' }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// SECTION 2 - CUSTOM AUDIT POLICIES: AKS security posture
// ----------------------------------------------------------------------------
// Three lightweight Audit policies that flag misconfigurations weakening the
// cluster's defenses. Unlike Section 1 these do not deploy anything — they only
// mark clusters compliant/non-compliant, giving the learner a posture dashboard.
// ============================================================================

// --- 2a. Require a network policy plugin --------------------------------------
// Without a CNI network policy, pods can talk freely east-west, easing lateral
// movement (MITRE: Lateral Movement). Audits that networkProfile.networkPolicy
// is configured (azure/calico/cilium) by flagging clusters where it is unset.
resource customNetPolPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-require-network-policy'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'AKS clusters must have a network policy plugin configured'
    description: 'Audits that networkProfile.networkPolicy is set to azure, calico, or cilium.'
    metadata: { category: 'Kubernetes', version: '1.0.0' }
    parameters: {
      // Audit (report) / Deny (block deploys) / Disabled. Initiative uses Audit.
      effect: {
        type: 'String'
        metadata: { displayName: 'Effect' }
        allowedValues: [ 'Audit', 'Deny', 'Disabled' ]
        defaultValue: 'Audit'
      }
    }
    policyRule: {
      // Non-compliant = an AKS cluster whose networkPolicy field does not exist.
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerService/managedClusters' }
          { field: 'Microsoft.ContainerService/managedClusters/networkProfile.networkPolicy', exists: 'false' }
        ]
      }
      then: { effect: '[parameters(\'effect\')]' }
    }
  }
}

// --- 2b. Require Microsoft Defender sensor ------------------------------------
// The Defender for Containers sensor provides runtime threat detection whose
// alerts flow into Sentinel (see Defender solution in aks_sentinel.bicep).
// Audits that securityProfile.defender.securityMonitoring.enabled == true.
resource customDefenderPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-require-defender-sensor'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'AKS clusters must have Microsoft Defender sensor enabled'
    description: 'Audits AKS clusters for securityProfile.defender.securityMonitoring.enabled = true.'
    metadata: { category: 'Kubernetes', version: '1.0.0' }
    parameters: {
      effect: {
        type: 'String'
        metadata: { displayName: 'Effect' }
        allowedValues: [ 'Audit', 'Deny', 'Disabled' ]
        defaultValue: 'Audit'
      }
    }
    policyRule: {
      // Non-compliant if the Defender monitoring flag is absent OR not 'true'.
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerService/managedClusters' }
          {
            anyOf: [
              { field: 'Microsoft.ContainerService/managedClusters/securityProfile.defender.securityMonitoring.enabled', exists: 'false' }
              { field: 'Microsoft.ContainerService/managedClusters/securityProfile.defender.securityMonitoring.enabled', notEquals: 'true' }
            ]
          }
        ]
      }
      then: { effect: '[parameters(\'effect\')]' }
    }
  }
}

// --- 2c. Require Entra ID RBAC with local accounts disabled -------------------
// Static local admin certs bypass Entra ID auditing (the 'guard' log) and can't
// be centrally revoked — a Credential Access / Persistence risk. Audits that
// disableLocalAccounts == true AND aadProfile.enableAzureRBAC == true.
resource customNoLocalAccounts 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-require-entra-rbac'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'AKS clusters must use Entra ID RBAC with local accounts disabled'
    description: 'Ensures disableLocalAccounts=true and aadProfile.enableAzureRBAC=true.'
    metadata: { category: 'Kubernetes', version: '1.0.0' }
    parameters: {
      effect: {
        type: 'String'
        metadata: { displayName: 'Effect' }
        allowedValues: [ 'Audit', 'Deny', 'Disabled' ]
        defaultValue: 'Audit'
      }
    }
    policyRule: {
      // Non-compliant if local accounts aren't disabled OR Azure RBAC isn't on.
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerService/managedClusters' }
          {
            anyOf: [
              { field: 'Microsoft.ContainerService/managedClusters/disableLocalAccounts', notEquals: 'true' }
              { field: 'Microsoft.ContainerService/managedClusters/aadProfile.enableAzureRBAC', notEquals: 'true' }
            ]
          }
        ]
      }
      then: { effect: '[parameters(\'effect\')]' }
    }
  }
}

// ============================================================================
// SECTION 3 - CUSTOM POLICY: Key Vault diagnostic logging (DeployIfNotExists)
// ----------------------------------------------------------------------------
// Same DINE pattern as Section 1, applied to Key Vault. Ensures vault audit logs
// (secret/key access) reach Log Analytics so the Key Vault Sentinel solution can
// detect secret exfiltration / abuse (MITRE: Credential Access).
// ============================================================================
resource dineKvDiagPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'kv-dine-diagnostic-settings'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Deploy diagnostic settings for Key Vault to Log Analytics'
    description: 'Automatically deploys a diagnostic setting on Key Vaults.'
    metadata: { category: 'Key Vault', version: '1.0.0' }
    parameters: {
      logAnalyticsWorkspaceId: {
        type: 'String'
        metadata: { displayName: 'Log Analytics Workspace Resource ID', strongType: 'omsWorkspace', assignPermissions: true }
      }
      effect: {
        type: 'String'
        metadata: { displayName: 'Effect' }
        allowedValues: [ 'DeployIfNotExists', 'AuditIfNotExists', 'Disabled' ]
        defaultValue: 'DeployIfNotExists'
      }
      diagnosticSettingName: {
        type: 'String'
        metadata: { displayName: 'Diagnostic Setting Name' }
        defaultValue: 'kv-security-diag-policy'
      }
    }
    policyRule: {
      // Target Key Vaults.
      if: { field: 'type', equals: 'Microsoft.KeyVault/vaults' }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          name: '[parameters(\'diagnosticSettingName\')]'
          // Same Monitoring + Log Analytics Contributor roles as the AKS DINE policy.
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
            '/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
          ]
          // Compliant if a diagnostic setting already targets the workspace with at
          // least one enabled log (Key Vault uses the 'allLogs' categoryGroup, so
          // a simpler >=1 check suffices vs. the 11-category AKS check).
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Insights/diagnosticSettings/workspaceId', equals: '[parameters(\'logAnalyticsWorkspaceId\')]' }
              {
                count: {
                  field: 'Microsoft.Insights/diagnosticSettings/logs[*]'
                  where: { field: 'Microsoft.Insights/diagnosticSettings/logs[*].enabled', equals: 'true' }
                }
                greaterOrEquals: 1
              }
            ]
          }
          // Remediation template: create the vault diagnostic setting -> workspace.
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  vaultName: { type: 'string' }
                  vaultLocation: { type: 'string' }
                  logAnalyticsWorkspaceId: { type: 'string' }
                  diagnosticSettingName: { type: 'string' }
                }
                resources: [
                  {
                    type: 'Microsoft.KeyVault/vaults/providers/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: '[concat(parameters(\'vaultName\'), \'/Microsoft.Insights/\', parameters(\'diagnosticSettingName\'))]'
                    location: '[parameters(\'vaultLocation\')]'
                    properties: {
                      workspaceId: '[parameters(\'logAnalyticsWorkspaceId\')]'
                      // 'allLogs' captures every Key Vault log category (incl. AuditEvent).
                      logs: [ { categoryGroup: 'allLogs', enabled: true } ]
                      metrics: [ { category: 'AllMetrics', enabled: true } ]
                    }
                  }
                ]
              }
              parameters: {
                vaultName: { value: '[field(\'name\')]' }
                vaultLocation: { value: '[field(\'location\')]' }
                logAnalyticsWorkspaceId: { value: '[parameters(\'logAnalyticsWorkspaceId\')]' }
                diagnosticSettingName: { value: '[parameters(\'diagnosticSettingName\')]' }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// SECTION 4 - THE INITIATIVE (policySetDefinition)
// ----------------------------------------------------------------------------
// Bundles the 5 custom policies above with 5 Microsoft built-in pod-security /
// network policies into one assignable unit. Assigning ONE initiative (in
// aks_policy.bicep) is simpler and more consistent than assigning 10 policies.
// A single initiative-level logAnalyticsWorkspaceId parameter fans out to every
// DINE policy that needs a sink.
// ============================================================================
resource aksLoggingInitiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: 'aks-adversary-lab-logging-initiative'
  properties: {
    policyType: 'Custom'
    displayName: 'AKS Adversary Lab - MITRE ATT&CK Containers Logging & Security'
    description: 'Audit and DeployIfNotExists policies for AKS logging, security, and pod security.'
    metadata: { category: 'Kubernetes', version: '2.1.0' }
    parameters: {
      // The one shared parameter; injected into each logging policy's own param.
      logAnalyticsWorkspaceId: {
        type: 'String'
        metadata: { displayName: 'Log Analytics Workspace Resource ID', strongType: 'omsWorkspace', assignPermissions: true }
      }
    }
    // --- Member policies. Each entry references a definition, gives it a stable
    //     policyDefinitionReferenceId, sets its parameters, and tags it with a
    //     group (see policyDefinitionGroups) for reporting. ---------------------
    policyDefinitions: [
      // AKS full diagnostic logging (Section 1). Note: assigned as AuditIfNotExists
      // here — the initiative reports on missing logging rather than auto-deploying.
      {
        policyDefinitionId: dineDiagPolicy.id
        policyDefinitionReferenceId: 'aksDineAllDiagCategories'
        parameters: {
          logAnalyticsWorkspaceId: { value: '[parameters(\'logAnalyticsWorkspaceId\')]' }
          effect: { value: 'AuditIfNotExists' }
          diagnosticSettingName: { value: 'aks-full-security-diag-policy' }
        }
        groupNames: [ 'Logging' ]
      }
      // Require network policy plugin (Section 2a) - Lateral Movement hardening.
      {
        policyDefinitionId: customNetPolPolicy.id
        policyDefinitionReferenceId: 'aksNetworkPolicyRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Network' ]
      }
      // Require Defender sensor (Section 2b) - runtime threat detection.
      {
        policyDefinitionId: customDefenderPolicy.id
        policyDefinitionReferenceId: 'aksDefenderRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Security' ]
      }
      // Require Entra RBAC / no local accounts (Section 2c) - Credential Access hardening.
      {
        policyDefinitionId: customNoLocalAccounts.id
        policyDefinitionReferenceId: 'aksEntraRbacRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Identity' ]
      }
      // Key Vault diagnostic logging (Section 3), also assigned as AuditIfNotExists.
      {
        policyDefinitionId: dineKvDiagPolicy.id
        policyDefinitionReferenceId: 'kvDineAllDiagCategories'
        parameters: {
          logAnalyticsWorkspaceId: { value: '[parameters(\'logAnalyticsWorkspaceId\')]' }
          effect: { value: 'AuditIfNotExists' }
          diagnosticSettingName: { value: 'kv-security-diag-policy' }
        }
        groupNames: [ 'Logging' ]
      }
      // --- Microsoft BUILT-IN pod-security / network policies (referenced by their
      //     well-known policyDefinition GUIDs). These enforce Kubernetes Pod Security
      //     Standards via the Azure Policy Gatekeeper add-on. ---------------------

      // Built-in: no privileged containers. A privileged container can escape to the
      // node (MITRE: Privilege Escalation, Escape to Host / T1611).
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4'
        policyDefinitionReferenceId: 'aksNoPrivilegedContainers'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      // Built-in: no privilege escalation (allowPrivilegeEscalation=false).
      // Blocks setuid-style in-container escalation (MITRE: Privilege Escalation).
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/1c6e92c9-99f0-4e55-9cf2-0c234dc48f99'
        policyDefinitionReferenceId: 'aksNoPrivilegeEscalation'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      // Built-in: block host namespace sharing (hostPID/hostIPC/hostNetwork).
      // Host namespace access enables snooping/escape (MITRE: Escape to Host).
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/47a1ee2f-2a2a-4576-bf2a-e0e36709c2b8'
        policyDefinitionReferenceId: 'aksBlockHostNamespace'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      // Built-in: restrict host filesystem (hostPath) mounts. An empty allow-list
      // means no hostPath is permitted — blocks reads of node secrets/sockets
      // (MITRE: Credential Access, Escape to Host).
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/098fc59e-46c7-4d99-9b16-64990e543d75'
        policyDefinitionReferenceId: 'aksRestrictHostFilesystem'
        parameters: {
          effect: { value: 'Audit' }
          allowedHostPaths: { value: { paths: [] } }
        }
        groupNames: [ 'PodSecurity' ]
      }
      // Built-in: API server authorized IP ranges. Restricting who can reach the
      // API server shrinks the attack surface (MITRE: Initial Access, Discovery).
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/0e246bcf-5f6f-4f87-bc6f-775d4712c7ea'
        policyDefinitionReferenceId: 'aksAuthorizedIpRanges'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Network' ]
      }
    ]
    // --- Reporting groups. Purely organizational: they cluster the compliance
    //     results in the portal by theme (each member above cites one by name). ---
    policyDefinitionGroups: [
      {
        name: 'Logging'
        displayName: 'Logging & Diagnostics'
        description: 'Diagnostic settings and log collection policies'
      }
      {
        name: 'Security'
        displayName: 'Security Controls'
        description: 'Runtime security monitoring policies'
      }
      {
        name: 'PodSecurity'
        displayName: 'Pod Security Standards'
        description: 'Pod security admission policies'
      }
      {
        name: 'Network'
        displayName: 'Network Security'
        description: 'Network segmentation and access policies'
      }
      {
        name: 'Identity'
        displayName: 'Identity & Access'
        description: 'Entra ID integration and RBAC policies'
      }
    ]
  }
}

// --- Outputs ------------------------------------------------------------------
output initiativeId string = aksLoggingInitiative.id       // consumed by aks_policy.bicep to assign it
output initiativeName string = aksLoggingInitiative.name   // initiative name for reference
output policyCount int = 10                                // total member policies (5 custom + 5 built-in)
output customPolicyCount int = 5                           // custom definitions authored in this file
output builtInPolicyCount int = 5                          // Microsoft built-in policies referenced by GUID
