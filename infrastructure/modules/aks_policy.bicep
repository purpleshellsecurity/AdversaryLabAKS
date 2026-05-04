// Layer 4: Governance - Policy Assignment (Resource Group Scope)

targetScope = 'resourceGroup'

@description('The resource ID of the policy initiative to assign')
param initiativeId string

@description('Log Analytics Workspace Resource ID for the initiative parameter')
param logAnalyticsWorkspaceId string

resource initiativeAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: 'aks-lab-mitre-logging'
  location: resourceGroup().location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'AKS Adversary Lab - MITRE Logging Enforcement'
    description: 'DeployIfNotExists enforcement for all 11 AKS diagnostic categories.'
    policyDefinitionId: initiativeId
    enforcementMode: 'Default'
    parameters: {
      logAnalyticsWorkspaceId: { value: logAnalyticsWorkspaceId }
    }
    nonComplianceMessages: [
      { message: 'This AKS cluster is missing full diagnostic logging.' }
    ]
  }
}

resource assignmentMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'monitoring-contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '749f88d5-cbae-40b8-bcfc-e573ddc772fa')
    principalType: 'ServicePrincipal'
  }
}

resource assignmentLogAnalyticsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'log-analytics-contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '92aaf0da-9dab-42b6-94a3-d43ce8d16293')
    principalType: 'ServicePrincipal'
  }
}

resource assignmentContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalType: 'ServicePrincipal'
  }
}

output assignmentId string = initiativeAssignment.id
output assignmentPrincipalId string = initiativeAssignment.identity.principalId
