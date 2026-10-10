// ============================================================================
// Layer 3: Monitoring - AKS Control-Plane Diagnostic Settings
// ============================================================================
// PURPOSE IN THE LAB:
//   This is arguably the single most important detection source in the lab.
//   It turns on FULL AKS control-plane logging and streams every category —
//   most critically the Kubernetes AUDIT logs — into Log Analytics.
//
//   Kubernetes audit logs are how you observe an attacker interacting with the
//   API server (creating pods, reading secrets, binding cluster roles, etc.),
//   which underpins most of the MITRE ATT&CK Containers-matrix detections the
//   lab teaches. Without this module those events would never reach the SIEM.
//
//   Runs in Layer 3 (Monitoring), after the AKS cluster exists (it references
//   the cluster as an existing resource).
// ============================================================================

// ── Parameters ───────────────────────────────────────────────────────────────

// Name of the already-deployed AKS cluster (from aks_cluster.bicep's output).
param aksClusterName string
// Log Analytics workspace resource ID — where all these logs are sent.
param logAnalyticsWorkspaceId string

// ── Existing resource reference ──────────────────────────────────────────────
// Reference (not create) the cluster so the diagnostic setting attaches to it.
resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-02-01' existing = {
  name: aksClusterName
}

// ── Diagnostic settings: all 11 control-plane log categories ─────────────────
resource aksDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${aksClusterName}-full-security-diag'
  scope: aksCluster
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    // 'Dedicated' sends each category to its own dedicated, well-typed table
    // (e.g. AKSAudit) instead of the generic AzureDiagnostics table. Dedicated
    // tables make KQL detections cleaner and faster — a deliberate choice to
    // support the lab's hunting queries.
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      // kube-audit: the FULL audit trail of every API-server request, including
      // reads. The richest (and noisiest) source for attack detection.
      { category: 'kube-audit', enabled: true }
      // kube-audit-admin: the same audit stream but with high-volume read events
      // filtered out — a lower-noise view focused on mutating/admin actions.
      { category: 'kube-audit-admin', enabled: true }
      // kube-apiserver: API server process logs.
      { category: 'kube-apiserver', enabled: true }
      // kube-controller-manager: reconciliation loop activity.
      { category: 'kube-controller-manager', enabled: true }
      // kube-scheduler: pod scheduling decisions.
      { category: 'kube-scheduler', enabled: true }
      // cluster-autoscaler: scale-up/down events for the node pools.
      { category: 'cluster-autoscaler', enabled: true }
      // cloud-controller-manager: Azure cloud integration (LBs, routes, etc.).
      { category: 'cloud-controller-manager', enabled: true }
      // guard: Entra ID (AAD) authN/authZ decisions at the API server — useful
      // for spotting failed/anomalous authentication.
      { category: 'guard', enabled: true }
      // CSI storage controller logs (disk / file / snapshot) — completeness so
      // storage-related activity is also captured.
      { category: 'csi-azuredisk-controller', enabled: true }
      { category: 'csi-azurefile-controller', enabled: true }
      { category: 'csi-snapshot-controller', enabled: true }
    ]
    metrics: [ { category: 'AllMetrics', enabled: true } ]
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
output diagnosticSettingsName string = aksDiagnostics.name
output diagnosticSettingsId string = aksDiagnostics.id
