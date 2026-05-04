// Layer 2: Compute - ACR Role Assignment

param acrName string
param aksPrincipalId string

var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, aksPrincipalId, acrPullRoleId)
  scope: acr
  properties: {
    principalId: aksPrincipalId
    roleDefinitionId: acrPullRoleId
    principalType: 'ServicePrincipal'
  }
}

output roleAssignmentId string = acrPullAssignment.id
