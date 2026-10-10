// ============================================================================
// Layer 1: Foundation - AKS Networking (VNet, Subnets, NSGs)
// ============================================================================
// PURPOSE IN THE LAB:
//   Builds the private network fabric the AKS cluster runs on. It creates a
//   single virtual network carved into three purpose-built subnets and attaches
//   Network Security Groups (NSGs) that define the coarse north-south firewall
//   posture around the cluster nodes.
//
//   Deployed in Layer 1 (before compute) because the AKS node pools in
//   aks_cluster.bicep must be injected into these subnets, and the subnet IDs
//   are handed upward as outputs for that wiring.
//
//   SECURITY NOTE: This is a lab. The user subnet's NSG deliberately allows
//   inbound HTTP/HTTPS from the entire internet so a "victim" web app and
//   ingress controller can be reached and attacked for detection exercises.
//   In production you would never expose 0.0.0.0/0 like this.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

param location string
param namePrefix string
param tags object = {}

// Address plan for the VNet and its subnets. Defaults are chosen to be
// non-overlapping and to leave room for growth. Note these are the NODE/VNet
// address ranges — pod and service CIDRs (overlay) are configured separately
// in aks_cluster.bicep and intentionally do NOT overlap these.
param vnetAddressPrefix string = '10.0.0.0/16'
param systemSubnetPrefix string = '10.0.0.0/23'    // system (add-on) node pool
param userSubnetPrefix string = '10.0.2.0/23'       // workload / "seclab" node pool
param endpointsSubnetPrefix string = '10.0.5.0/24'  // reserved for private endpoints

// ── Derived names ────────────────────────────────────────────────────────────

var vnetName = '${namePrefix}-aks-vnet'
var systemSubnetName = 'sn-aks-system'
var userSubnetName = 'sn-aks-user'
var endpointsSubnetName = 'sn-endpoints'
var nsgSystemName = '${namePrefix}-nsg-aks-system'
var nsgUserName = '${namePrefix}-nsg-aks-user'

// ── NSG: System node pool ─────────────────────────────────────────────────────
// Guards the subnet hosting the cluster's system/add-on nodes. These nodes run
// no public-facing workloads, so the posture is strict: deny all inbound from
// the internet. (Intra-VNet and Azure-required traffic is still permitted by
// Azure's default NSG rules, which sit at a lower priority than this rule.)
resource nsgSystem 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: nsgSystemName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'DenyAllInbound'
        properties: {
          // Priority 4000 is low (rules evaluate low-number-first), so it acts
          // as a catch-all after Azure's built-in allow rules for the VNet.
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

// ── NSG: User / workload node pool ────────────────────────────────────────────
// Guards the subnet hosting the "seclab" workload nodes where the intentionally
// vulnerable / victim applications live. INTENTIONALLY PERMISSIVE: it exposes
// HTTP and HTTPS to the whole internet so attacks and ingress traffic can reach
// the lab targets. This is insecure-by-design for teaching, not a hardening model.
resource nsgUser 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: nsgUserName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        // Allow 443 from anywhere so an ingress controller / TLS victim app is
        // reachable from the internet for testing. (source '*' = 0.0.0.0/0.)
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
        // Allow 80 from anywhere for the plain-HTTP victim application.
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
        // Everything else from the internet is denied. Because 80/443 above have
        // higher priority (lower numbers) they win; this catch-all blocks the rest.
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

// ── VNet + Subnets ────────────────────────────────────────────────────────────
// The single virtual network for the whole lab, subdivided into three subnets.
resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [ vnetAddressPrefix ] }
    subnets: [
      {
        // System node pool subnet — locked down by the strict system NSG.
        name: systemSubnetName
        properties: {
          addressPrefix: systemSubnetPrefix
          networkSecurityGroup: { id: nsgSystem.id }
          // Private-endpoint network policies disabled: not used to host PEs here,
          // and disabling avoids policy interference with AKS node networking.
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        // Workload node pool subnet — attached to the internet-exposed user NSG.
        name: userSubnetName
        properties: {
          addressPrefix: userSubnetPrefix
          networkSecurityGroup: { id: nsgUser.id }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        // Dedicated subnet reserved for Private Endpoints (e.g. to reach ACR /
        // Key Vault privately). No NSG here; PE network policies are ENABLED so
        // NSG/route rules can be applied to private endpoints placed in it.
        name: endpointsSubnetName
        properties: {
          addressPrefix: endpointsSubnetPrefix
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
// Subnet IDs are the key deliverable: aks_cluster.bicep injects its node pools
// into the system and user subnets using these values.
output vnetId string = vnet.id
output vnetName string = vnet.name
output systemSubnetId string = '${vnet.id}/subnets/${systemSubnetName}'
output userSubnetId string = '${vnet.id}/subnets/${userSubnetName}'
output endpointsSubnetId string = '${vnet.id}/subnets/${endpointsSubnetName}'
output nsgSystemId string = nsgSystem.id
output nsgUserId string = nsgUser.id
