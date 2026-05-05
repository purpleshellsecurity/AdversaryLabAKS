// Layer 2: Compute - AKS Cluster

param location string
param namePrefix string
param kubernetesVersion string = '1.34.2'
param systemNodeVmSize string = 'Standard_D2s_v3'
param userNodeVmSize string = 'Standard_D2s_v3'
param systemSubnetId string
param userSubnetId string
param logAnalyticsWorkspaceResourceId string
param adminGroupObjectId string
param authorizedIpRange string
param enableDefender bool = true
param enableAzurePolicy bool = true
param tags object = {}

var clusterName = '${namePrefix}-aks'
var nodeResourceGroup = '${namePrefix}-aks-nodes'

resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' = {
  name: clusterName
  location: location
  tags: tags
  sku: { name: 'Base', tier: 'Standard' }
  identity: { type: 'SystemAssigned' }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: '${clusterName}-dns'
    enableRBAC: true
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      adminGroupObjectIDs: [ adminGroupObjectId ]
    }
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.245.0.0/16'
      dnsServiceIP: '10.245.0.10'
      loadBalancerSku: 'standard'
      outboundType: 'loadBalancer'
      loadBalancerProfile: { managedOutboundIPs: { count: 1 } }
    }
    securityProfile: {
      workloadIdentity: { enabled: true }
      defender: enableDefender ? {
        logAnalyticsWorkspaceResourceId: logAnalyticsWorkspaceResourceId
        securityMonitoring: { enabled: true }
      } : null
      imageCleaner: { enabled: true, intervalHours: 48 }
    }
    oidcIssuerProfile: { enabled: true }
    addonProfiles: {
      azurepolicy: { enabled: enableAzurePolicy }
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: { enableSecretRotation: 'true', rotationPollInterval: '2m' }
      }
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceResourceId
          useAADAuth: 'true'
        }
      }
    }
    azureMonitorProfile: { metrics: { enabled: true } }
    agentPoolProfiles: [
      {
        name: 'system'
        count: 1
        vmSize: systemNodeVmSize
        mode: 'System'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        vnetSubnetID: systemSubnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 3
        maxPods: 110
        nodeTaints: [ 'CriticalAddonsOnly=true:NoSchedule' ]
        nodeLabels: { 'adversary-lab/pool': 'system' }
        upgradeSettings: { maxSurge: '33%' }
      }
      {
        name: 'seclab'
        count: 1
        vmSize: userNodeVmSize
        mode: 'User'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        vnetSubnetID: userSubnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 6
        maxPods: 110
        nodeLabels: { 'adversary-lab/pool': 'workload' }
        upgradeSettings: { maxSurge: '33%' }
      }
    ]
    apiServerAccessProfile: {
      enablePrivateCluster: false
      authorizedIPRanges: [ authorizedIpRange ]
    }
    nodeResourceGroup: nodeResourceGroup
    nodeResourceGroupProfile: { restrictionLevel: 'ReadOnly' }
    autoUpgradeProfile: {
      upgradeChannel: 'stable'
      nodeOSUpgradeChannel: 'NodeImage'
    }
    storageProfile: {
      diskCSIDriver: { enabled: true }
      fileCSIDriver: { enabled: true }
      snapshotController: { enabled: true }
    }
  }
}

output clusterName string = aksCluster.name
output clusterResourceId string = aksCluster.id
output clusterFqdn string = aksCluster.properties.fqdn
output kubeletIdentityObjectId string = aksCluster.properties.identityProfile.kubeletidentity.objectId
output clusterPrincipalId string = aksCluster.identity.principalId
output oidcIssuerUrl string = aksCluster.properties.oidcIssuerProfile.issuerURL
output nodeResourceGroup string = aksCluster.properties.nodeResourceGroup
