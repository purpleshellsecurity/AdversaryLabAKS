// Layer 4: Governance - Policy Definitions + Initiative (Subscription Scope)

targetScope = 'subscription'

resource dineDiagPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-dine-all-diag-categories'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Deploy diagnostic settings for AKS with all 11 log categories'
    description: 'Automatically deploys a diagnostic setting on AKS clusters that enables all 11 log categories in resource-specific mode.'
    metadata: { category: 'Kubernetes', version: '2.0.0' }
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
        defaultValue: 'aks-full-security-diag-policy'
      }
    }
    policyRule: {
      if: { field: 'type', equals: 'Microsoft.ContainerService/managedClusters' }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          name: '[parameters(\'diagnosticSettingName\')]'
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
            '/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Insights/diagnosticSettings/workspaceId', equals: '[parameters(\'logAnalyticsWorkspaceId\')]' }
              {
                count: {
                  field: 'Microsoft.Insights/diagnosticSettings/logs[*]'
                  where: {
                    allOf: [
                      { field: 'Microsoft.Insights/diagnosticSettings/logs[*].enabled', equals: 'true' }
                      {
                        field: 'Microsoft.Insights/diagnosticSettings/logs[*].category'
                        in: [
                          'kube-audit', 'kube-audit-admin', 'kube-apiserver',
                          'kube-controller-manager', 'kube-scheduler', 'cluster-autoscaler',
                          'cloud-controller-manager', 'guard', 'csi-azuredisk-controller',
                          'csi-azurefile-controller', 'csi-snapshot-controller'
                        ]
                      }
                    ]
                  }
                }
                greaterOrEquals: 11
              }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  clusterName: { type: 'string' }
                  clusterLocation: { type: 'string' }
                  logAnalyticsWorkspaceId: { type: 'string' }
                  diagnosticSettingName: { type: 'string' }
                }
                resources: [
                  {
                    type: 'Microsoft.ContainerService/managedClusters/providers/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: '[concat(parameters(\'clusterName\'), \'/Microsoft.Insights/\', parameters(\'diagnosticSettingName\'))]'
                    location: '[parameters(\'clusterLocation\')]'
                    properties: {
                      workspaceId: '[parameters(\'logAnalyticsWorkspaceId\')]'
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
                ]
              }
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

resource customNetPolPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'aks-require-network-policy'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'AKS clusters must have a network policy plugin configured'
    description: 'Audits that networkProfile.networkPolicy is set to azure, calico, or cilium.'
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
      if: { field: 'type', equals: 'Microsoft.KeyVault/vaults' }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          name: '[parameters(\'diagnosticSettingName\')]'
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
            '/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
          ]
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

resource aksLoggingInitiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: 'aks-adversary-lab-logging-initiative'
  properties: {
    policyType: 'Custom'
    displayName: 'AKS Adversary Lab - MITRE ATT&CK Containers Logging & Security'
    description: 'Audit and DeployIfNotExists policies for AKS logging, security, and pod security.'
    metadata: { category: 'Kubernetes', version: '2.1.0' }
    parameters: {
      logAnalyticsWorkspaceId: {
        type: 'String'
        metadata: { displayName: 'Log Analytics Workspace Resource ID', strongType: 'omsWorkspace', assignPermissions: true }
      }
    }
    policyDefinitions: [
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
      {
        policyDefinitionId: customNetPolPolicy.id
        policyDefinitionReferenceId: 'aksNetworkPolicyRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Network' ]
      }
      {
        policyDefinitionId: customDefenderPolicy.id
        policyDefinitionReferenceId: 'aksDefenderRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Security' ]
      }
      {
        policyDefinitionId: customNoLocalAccounts.id
        policyDefinitionReferenceId: 'aksEntraRbacRequired'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Identity' ]
      }
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
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4'
        policyDefinitionReferenceId: 'aksNoPrivilegedContainers'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/1c6e92c9-99f0-4e55-9cf2-0c234dc48f99'
        policyDefinitionReferenceId: 'aksNoPrivilegeEscalation'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/47a1ee2f-2a2a-4576-bf2a-e0e36709c2b8'
        policyDefinitionReferenceId: 'aksBlockHostNamespace'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'PodSecurity' ]
      }
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/098fc59e-46c7-4d99-9b16-64990e543d75'
        policyDefinitionReferenceId: 'aksRestrictHostFilesystem'
        parameters: {
          effect: { value: 'Audit' }
          allowedHostPaths: { value: { paths: [] } }
        }
        groupNames: [ 'PodSecurity' ]
      }
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/0e246bcf-5f6f-4f87-bc6f-775d4712c7ea'
        policyDefinitionReferenceId: 'aksAuthorizedIpRanges'
        parameters: { effect: { value: 'Audit' } }
        groupNames: [ 'Network' ]
      }
    ]
    policyDefinitionGroups: [
      { name: 'Logging', displayName: 'Logging & Diagnostics' }
      { name: 'Security', displayName: 'Security Controls' }
      { name: 'PodSecurity', displayName: 'Pod Security Standards' }
      { name: 'Network', displayName: 'Network Security' }
      { name: 'Identity', displayName: 'Identity & Access' }
    ]
  }
}

output initiativeId string = aksLoggingInitiative.id
output initiativeName string = aksLoggingInitiative.name
output policyCount int = 10
output customPolicyCount int = 5
output builtInPolicyCount int = 5
