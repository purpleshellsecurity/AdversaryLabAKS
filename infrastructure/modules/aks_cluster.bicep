// ============================================================================
// Layer 2: Compute - AKS Managed Cluster
// ============================================================================
// PURPOSE IN THE LAB:
//   Deploys the Azure Kubernetes Service cluster that is the centerpiece of the
//   whole adversary lab — the "target" environment where MITRE ATT&CK Containers
//   techniques are performed and detected. Nearly every security feature that
//   generates detection signal (Entra RBAC, Defender for Containers, workload
//   identity, Cilium network policy/observability, Managed Prometheus, Container
//   Insights) is wired up here.
//
//   Deployed in Layer 2 (Compute) after networking (needs the subnet IDs) and
//   the workspace (needs its resource ID). Its outputs feed the ACR role
//   assignment, the diagnostic settings, and Container Insights downstream.
//
//   Overall posture: control-plane access is HARDENED (Entra-only, local
//   accounts disabled, API server IP-restricted), while the workload side is
//   left reachable so attacks can actually be staged against it.
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

param location string
param namePrefix string
// Kubernetes version to pin. Explicit pinning keeps the lab reproducible.
param kubernetesVersion string = '1.34.2'
param systemNodeVmSize string = 'Standard_D2s_v3'   // → 'Standard_D2s_v3' is fine for system
param userNodeVmSize string = 'Standard_D4s_v3'     // → change to 'Standard_D4s_v3'
// Subnet IDs from aks_networking.bicep — node pools are injected into these.
param systemSubnetId string
param userSubnetId string
// Workspace resource ID used by both Defender and the omsagent (Container Insights).
param logAnalyticsWorkspaceResourceId string
// Entra ID group Object ID granted Kubernetes cluster-admin via Azure RBAC.
param adminGroupObjectId string
// The single public IP/CIDR allowed to reach the API server (typically the
// operator's own IP). This is the primary control-plane exposure control.
param authorizedIpRange string
// Toggle Microsoft Defender for Containers threat detection on the cluster.
param enableDefender bool = true
// Toggle the Azure Policy add-on (Gatekeeper) for admission-control governance.
param enableAzurePolicy bool = true
// Advanced Container Networking Services (ACNS) — turns on Cilium's Hubble layer
// for pod-to-pod (east-west) network observability. Requires the Cilium dataplane
// (already set below). Billed per node-hour; disable to avoid the cost.
param enableAdvancedNetworking bool = true
param tags object = {}

// ── Derived names ────────────────────────────────────────────────────────────
var clusterName = '${namePrefix}-aks'
// The auto-created, AKS-managed resource group that holds node VMs, disks, LBs,
// etc. Named explicitly so it's predictable.
var nodeResourceGroup = '${namePrefix}-aks-nodes'

// ── Resource: Managed Cluster ────────────────────────────────────────────────
resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' = {
  name: clusterName
  location: location
  tags: tags
  // Base SKU with Standard tier: Standard tier gives the SLA-backed, financially
  // guaranteed API server uptime (vs. Free) — reasonable for a persistent lab.
  sku: { name: 'Base', tier: 'Standard' }
  // System-assigned managed identity for the cluster control plane — no stored
  // credentials; Azure manages the identity lifecycle. This principal is what
  // grants the cluster access to VNet, LBs, etc.
  identity: { type: 'SystemAssigned' }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: '${clusterName}-dns'
    // Kubernetes RBAC enabled — required for meaningful authorization and for the
    // audit logs to be interesting.
    enableRBAC: true
    // HARDENING: local (static kubeconfig / certificate) admin accounts are
    // DISABLED. All access must go through Entra ID, so every action is tied to a
    // real identity and shows up in the guard/audit logs.
    disableLocalAccounts: true
    aadProfile: {
      // AKS-managed Entra integration (no manually-managed server/client apps).
      managed: true
      // HARDENING: use Azure RBAC (not Kubernetes RBAC role bindings) to decide
      // who can do what — authorization decisions become Azure-auditable.
      enableAzureRBAC: true
      // The Entra group whose members get cluster-admin. Membership is the lab's
      // human access-control boundary.
      adminGroupObjectIDs: [ adminGroupObjectId ]
    }
    networkProfile: {
      // Azure CNI in OVERLAY mode: pods get IPs from the podCidr overlay rather
      // than consuming VNet address space, so the subnets stay small.
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      // Cilium (eBPF) dataplane + Cilium network policy: high-performance policy
      // enforcement and the foundation for the Hubble observability below. Network
      // policy support is what lets the lab demonstrate lateral-movement controls.
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      // Pod and service CIDRs are the OVERLAY ranges — deliberately distinct from
      // the 10.0.0.0/16 VNet in aks_networking.bicep so nothing overlaps.
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.245.0.0/16'
      dnsServiceIP: '10.245.0.10'
      // Standard Load Balancer with LB-based egress and one managed outbound IP.
      loadBalancerSku: 'standard'
      outboundType: 'loadBalancer'
      loadBalancerProfile: { managedOutboundIPs: { count: 1 } }
      // ACNS / Hubble — the pod-to-pod network plane. Observability emits Hubble
      // flow metrics (to the Managed Prometheus enabled in azureMonitorProfile) and
      // makes flows queryable. Stored flow logs to Log Analytics (the KQL-queryable
      // "Container Network Logs") are a SEPARATE follow-on step — see
      // detections/kql/network-lateral-movement.kql header for enablement notes.
      advancedNetworking: enableAdvancedNetworking ? {
        enabled: true
        observability: { enabled: true }
        security: { enabled: true }
      } : null
    }
    securityProfile: {
      // Workload Identity (federated) enabled — pods can authenticate to Azure as
      // their own Entra identity without secrets. A key detection/attack surface
      // (token abuse) the lab exercises. Paired with oidcIssuerProfile below.
      workloadIdentity: { enabled: true }
      // Microsoft Defender for Containers: runtime threat detection that emits
      // security alerts into the same workspace. One of the core detection engines
      // in the lab. Null (off) when enableDefender is false.
      defender: enableDefender ? {
        logAnalyticsWorkspaceResourceId: logAnalyticsWorkspaceResourceId
        securityMonitoring: { enabled: true }
      } : null
      // Image Cleaner (eraser) removes stale/vulnerable images from nodes every
      // 48h, shrinking the attack surface on the hosts.
      imageCleaner: { enabled: true, intervalHours: 48 }
    }
    // OIDC issuer must be on for Workload Identity federation to function.
    oidcIssuerProfile: { enabled: true }
    addonProfiles: {
      // Azure Policy (Gatekeeper) admission controller — enforces governance
      // guardrails and reports compliance. Toggleable via param.
      azurepolicy: { enabled: enableAzurePolicy }
      // Key Vault Secrets Provider (CSI) — mounts secrets from the lab's Key Vault
      // into pods, with automatic rotation polled every 2 minutes.
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: { enableSecretRotation: 'true', rotationPollInterval: '2m' }
      }
      // omsagent = the Container Insights / Log Analytics agent. Ships container
      // stdout/stderr, inventory, and metrics to the workspace using Entra
      // (AAD) auth rather than the legacy workspace key (hardening).
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceResourceId
          useAADAuth: 'true'
        }
      }
    }
    // Managed Prometheus — scrapes cluster + Hubble metrics for dashboards/alerts.
    azureMonitorProfile: { metrics: { enabled: true } }
    agentPoolProfiles: [
      {
        // SYSTEM pool: runs cluster add-ons/critical system pods only.
        name: 'system'
        count: 1
        vmSize: systemNodeVmSize
        mode: 'System'
        osType: 'Linux'
        // Azure Linux (Mariner) — Microsoft's hardened, minimal container host OS.
        osSKU: 'AzureLinux'
        vnetSubnetID: systemSubnetId
        // Autoscale 1→3 nodes based on demand.
        enableAutoScaling: true
        minCount: 1
        maxCount: 3
        maxPods: 110
        // Taint reserves these nodes for critical add-ons so untrusted workloads
        // can't schedule onto the system pool (isolation between system and
        // attacker-facing workloads).
        nodeTaints: [ 'CriticalAddonsOnly=true:NoSchedule' ]
        nodeLabels: { 'adversary-lab/pool': 'system' }
        // Surge up to 33% extra nodes during upgrades to keep capacity.
        upgradeSettings: { maxSurge: '33%' }
      }
      {
        // "seclab" USER pool: where the victim / attacker workloads actually run.
        name: 'seclab'
        count: 1
        vmSize: userNodeVmSize
        mode: 'User'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        vnetSubnetID: userSubnetId
        // Autoscale up to 6 nodes — more headroom since this pool carries the
        // lab exercises.
        enableAutoScaling: true
        minCount: 1
        maxCount: 6
        maxPods: 110
        // No taint: workloads schedule here freely. Labeled so manifests can
        // target it with nodeSelector.
        nodeLabels: { 'adversary-lab/pool': 'workload' }
        upgradeSettings: { maxSurge: '33%' }
      }
    ]
    apiServerAccessProfile: {
      // PUBLIC cluster (not private): the API server has a public endpoint, which
      // is why the IP allow-list below matters so much. A private cluster would
      // remove the public endpoint entirely but complicate lab access.
      enablePrivateCluster: false
      // HARDENING: the API server only accepts traffic from this single IP/CIDR
      // (the operator's IP). This is the main guardrail on an otherwise-public
      // control plane — set it wrong (e.g. 0.0.0.0/0) and the API server is open
      // to the internet.
      authorizedIPRanges: [ authorizedIpRange ]
    }
    nodeResourceGroup: nodeResourceGroup
    // Lock down the auto-generated node resource group to read-only so users
    // can't accidentally (or maliciously) mutate the managed node infrastructure.
    nodeResourceGroupProfile: { restrictionLevel: 'ReadOnly' }
    autoUpgradeProfile: {
      // Auto-patch to the latest stable Kubernetes patch and node OS image —
      // keeps the lab current with security fixes without manual intervention.
      upgradeChannel: 'stable'
      nodeOSUpgradeChannel: 'NodeImage'
    }
    storageProfile: {
      // Enable the CSI storage drivers + snapshotting so workloads can use Azure
      // Disk/File persistent volumes (and so those actions are logged).
      diskCSIDriver: { enabled: true }
      fileCSIDriver: { enabled: true }
      snapshotController: { enabled: true }
    }
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
output clusterName string = aksCluster.name
output clusterResourceId string = aksCluster.id
// Public FQDN of the API server (surfaced by main.bicep).
output clusterFqdn string = aksCluster.properties.fqdn
// Kubelet identity principal ID — consumed by aks_acr_role.bicep to grant AcrPull.
output kubeletIdentityObjectId string = aksCluster.properties.identityProfile.kubeletidentity.objectId
// The cluster (control-plane) identity principal ID — available for further RBAC.
output clusterPrincipalId string = aksCluster.identity.principalId
// OIDC issuer URL — needed to configure federated Workload Identity credentials.
output oidcIssuerUrl string = aksCluster.properties.oidcIssuerProfile.issuerURL
output nodeResourceGroup string = aksCluster.properties.nodeResourceGroup
