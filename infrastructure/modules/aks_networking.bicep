// Layer 1: Foundation - AKS Networking

param location string
param namePrefix string
param tags object = {}

param vnetAddressPrefix string = '10.0.0.0/16'
param systemSubnetPrefix string = '10.0.0.0/23'
param userSubnetPrefix string = '10.0.2.0/23'
param endpointsSubnetPrefix string = '10.0.5.0/24'

var vnetName = '${namePrefix}-aks-vnet'
var systemSubnetName = 'sn-aks-system'
var userSubnetName = 'sn-aks-user'
var endpointsSubnetName = 'sn-endpoints'
var nsgSystemName = '${namePrefix}-nsg-aks-system'
var nsgUserName = '${namePrefix}-nsg-aks-user'

resource nsgSystem 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: nsgSystemName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4000
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Default deny all internet inbound'
        }
      }
    ]
  }
}

resource nsgUser 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: nsgUserName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPSInbound'
        properties: {
          priority: 1000
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          description: 'Allow HTTPS for ingress controller testing'
        }
      }
      {
        name: 'AllowHTTPInbound'
        properties: {
          priority: 1010
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
          description: 'Allow HTTP for victim app testing'
        }
      }
      {
        name: 'DenyAllOtherInbound'
        properties: {
          priority: 4000
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [ vnetAddressPrefix ] }
    subnets: [
      {
        name: systemSubnetName
        properties: {
          addressPrefix: systemSubnetPrefix
          networkSecurityGroup: { id: nsgSystem.id }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: userSubnetName
        properties: {
          addressPrefix: userSubnetPrefix
          networkSecurityGroup: { id: nsgUser.id }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: endpointsSubnetName
        properties: {
          addressPrefix: endpointsSubnetPrefix
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output systemSubnetId string = '${vnet.id}/subnets/${systemSubnetName}'
output userSubnetId string = '${vnet.id}/subnets/${userSubnetName}'
output endpointsSubnetId string = '${vnet.id}/subnets/${endpointsSubnetName}'
output nsgSystemId string = nsgSystem.id
output nsgUserId string = nsgUser.id
