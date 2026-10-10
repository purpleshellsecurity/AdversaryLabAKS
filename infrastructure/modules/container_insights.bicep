// ============================================================================
// Layer 3: Monitoring - Container Insights (Data Collection Rule)
// ============================================================================
//
// PURPOSE
//   Creates an Azure Monitor Data Collection Rule (DCR) for Container Insights and
//   associates it with the AKS cluster. Where aks_policy_defs.bicep captures the
//   AKS CONTROL PLANE (audit logs), this module captures the DATA PLANE: container
//   stdout/stderr, Kubernetes events, pod/node inventory, and node/pod metrics.
//
// ROLE IN THE DETECTION / LOGGING PIPELINE
//   A DCR is the modern replacement for the legacy omsagent config. It declares
//   (1) WHAT streams to collect, (2) WHERE to send them, and (3) the data flow
//   binding the two. The DCR association then attaches this collection profile to
//   the AKS cluster's Container Insights extension.
//
//   The container/workload telemetry produced here feeds tables like ContainerLogV2
//   and KubeEvents in Log Analytics. Sentinel analytics rules (see
//   sentinel_analytics_rule.bicep) hunt over these tables to detect adversary
//   behaviour INSIDE containers — e.g. suspicious process execution, crypto-mining,
//   or reverse shells (MITRE ATT&CK Execution / Command-and-Control), which the
//   control-plane audit log alone cannot see.
// ============================================================================

// Azure region for the DCR. Should match the cluster/workspace region; DCRs are
// regional resources and the association requires region alignment.
param location string

// Prefix used to build consistent, collision-free resource names across the lab.
param namePrefix string

// Name of the existing AKS cluster this DCR will be associated with.
param aksClusterName string

// Resource ID of the Log Analytics workspace that will receive the collected
// container telemetry (the destination sink).
param logAnalyticsWorkspaceResourceId string

// Deterministic DCR name derived from the prefix ("...-aks-ci-dcr").
var dcrName = '${namePrefix}-aks-ci-dcr'

// --- The Data Collection Rule --------------------------------------------------
resource containerInsightsDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  // 'Linux' kind matches AKS Linux node pools; it governs which extension data
  // sources are valid for this DCR.
  kind: 'Linux'
  properties: {
    // (1) WHAT to collect. The ContainerInsights extension emits a fixed set of
    //     named streams; listing them here enables each one.
    dataSources: {
      extensions: [
        {
          name: 'ContainerInsightsExtension'
          extensionName: 'ContainerInsights'
          // Each stream maps to a Log Analytics table and a slice of cluster
          // telemetry the detections may query:
          streams: [
            'Microsoft-ContainerLogV2'        // container stdout/stderr -> ContainerLogV2 (process/command evidence)
            'Microsoft-KubeEvents'            // Kubernetes events (pod scheduling, OOMs, warnings)
            'Microsoft-KubePodInventory'      // running pods + state (what was deployed/where)
            'Microsoft-KubeNodeInventory'     // node inventory/health
            'Microsoft-KubeServices'          // service objects (exposure surface)
            'Microsoft-KubeMonAgentEvents'    // monitoring agent health/errors
            'Microsoft-InsightsMetrics'       // Prometheus-style insights metrics
            'Microsoft-ContainerInventory'    // container images/instances (detect unexpected images)
            'Microsoft-ContainerNodeInventory'// container-to-node mapping
            'Microsoft-Perf'                  // node/pod CPU/mem/disk perf (crypto-mining signal)
          ]
          extensionSettings: {
            dataCollectionSettings: {
              // Sampling/collection interval for inventory & metrics.
              interval: '1m'
              // 'Off' = collect from ALL namespaces (no include/exclude filtering),
              // so kube-system and workload namespaces are all in scope for hunting.
              namespaceFilteringMode: 'Off'
              // ContainerLogV2 is the richer, schematized log table (vs legacy
              // ContainerLog); required for reliable container-log detections.
              enableContainerLogV2: true
            }
          }
        }
      ]
    }
    // (2) WHERE the data goes: the lab's Log Analytics workspace. The 'name' is a
    //     local alias referenced by the dataFlows below.
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceResourceId
          name: 'ciworkspace'
        }
      ]
    }
    // (3) The data flow: route every collected stream to the 'ciworkspace'
    //     destination. The stream list mirrors dataSources above.
    dataFlows: [
      {
        streams: [
          'Microsoft-ContainerLogV2'
          'Microsoft-KubeEvents'
          'Microsoft-KubePodInventory'
          'Microsoft-KubeNodeInventory'
          'Microsoft-KubeServices'
          'Microsoft-KubeMonAgentEvents'
          'Microsoft-InsightsMetrics'
          'Microsoft-ContainerInventory'
          'Microsoft-ContainerNodeInventory'
          'Microsoft-Perf'
        ]
        destinations: [ 'ciworkspace' ]
      }
    ]
  }
}

// Reference (not create) the already-deployed AKS cluster so we can scope the
// association to it.
resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' existing = {
  name: aksClusterName
}

// --- DCR association -----------------------------------------------------------
// Binds the DCR to the AKS cluster. Until this association exists, the DCR is
// defined but collects nothing — the association is what activates Container
// Insights data collection on the cluster.
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  // 'ContainerInsightsExtension' is the conventional association name Azure
  // expects for the Container Insights extension binding.
  name: 'ContainerInsightsExtension'
  scope: aksCluster
  properties: {
    dataCollectionRuleId: containerInsightsDcr.id
    description: 'Container Insights DCR association for AKS adversary lab'
  }
}

// --- Outputs ------------------------------------------------------------------
output dcrId string = containerInsightsDcr.id                 // full DCR resource ID
output dcrName string = containerInsightsDcr.name             // DCR name for reference
output dcrAssociationId string = dcrAssociation.id           // association ID (proof collection is wired up)
