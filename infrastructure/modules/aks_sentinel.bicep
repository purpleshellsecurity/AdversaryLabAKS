// ============================================================================
// Layer 3: Monitoring - Microsoft Sentinel + Content Solutions
// ============================================================================
//
// PURPOSE
//   Turns an existing Log Analytics workspace into a Microsoft Sentinel (SIEM)
//   workspace and installs a curated set of Sentinel "content solutions"
//   (content packages). Onboarding is what makes SecurityInsights features —
//   incidents, analytics rules, hunting, workbooks — available on the workspace.
//
// ROLE IN THE DETECTION / LOGGING PIPELINE
//   Layer 4 (governance) guarantees the LOGS exist; this module stands up the
//   ANALYTICS PLANE that reasons over them. Sentinel onboarding must happen
//   before any alertRule (see sentinel_analytics_rule.bicep) can be created, so
//   this module is an upstream dependency of every custom detection.
//
//   Each contentPackage below is a Microsoft-published solution bundling
//   connectors, parsers, analytics rules, hunting queries, and workbooks for a
//   specific data source. Installing them gives the lab ready-made, MITRE-aligned
//   detection content mapped to the telemetry the lab collects (Azure activity,
//   identity sign-ins, Key Vault access, NSG flow, DNS, Defender alerts).
//
// NOTE ON THE PINNED VERSIONS / CONTENT IDs
//   The version, contentId, contentProductId, and source fields are exact
//   identifiers from the Sentinel content hub catalog. They are pinned so the lab
//   deploys a known-good, reproducible content set. Do not treat them as arbitrary
//   strings — each is a catalog coordinate for one specific solution release.
// ============================================================================

// Name of the pre-existing Log Analytics workspace to onboard into Sentinel.
param workspaceName string

// Reference (not create) the existing workspace; every resource below is scoped
// to it.
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// --- Sentinel onboarding -------------------------------------------------------
// The 'default' onboardingState is the switch that enables Microsoft Sentinel on
// the workspace. Empty properties are correct — its mere existence onboards the
// workspace. Every contentPackage below dependsOn this so solutions install only
// after Sentinel is active.
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

// --- Content solutions (one contentPackage each) -------------------------------

// Azure Activity: ingests subscription-level control-plane operations (who did
// what in Azure). Underpins detections for suspicious resource changes / RBAC
// abuse (MITRE: Persistence, Privilege Escalation, Impact).
resource azureActivitySolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azureactivity'
  properties: {
    version: '3.0.3'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azureactivity'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azureactivit-sl-x6rxfrmsjp3pw'
    contentKind: 'Solution'
    displayName: 'Azure Activity'
    source: { kind: 'Solution', name: 'Azure Activity', sourceId: 'azuresentinel.azure-sentinel-solution-azureactivity' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// Microsoft Entra ID: sign-in and audit logs for the identity provider fronting
// AKS Entra RBAC. Powers detections for credential access / anomalous logins
// (MITRE: Credential Access, Initial Access, Defense Evasion).
resource entraIdSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
  properties: {
    version: '3.3.3'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azureactived-sl-ysutelafuvsa2'
    contentKind: 'Solution'
    displayName: 'Microsoft Entra ID'
    source: { kind: 'Solution', name: 'Microsoft Entra ID', sourceId: 'azuresentinel.azure-sentinel-solution-azureactivedirectory' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// Azure Key Vault: content for Key Vault data-plane audit logs (secret/key
// access). Complements the Key Vault DINE diagnostic policy in
// aks_policy_defs.bicep. Detects secret exfil / abuse (MITRE: Credential Access).
resource azureKeyVaultSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
  properties: {
    version: '3.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azurekeyvaul-sl-3m323kndkg22c'
    contentKind: 'Solution'
    displayName: 'Azure Key Vault'
    source: { kind: 'Solution', name: 'Azure Key Vault', sourceId: 'azuresentinel.azure-sentinel-solution-azurekeyvault' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// Azure Network Security Groups: NSG flow-log analytics content. Detects
// suspicious network access to/from the cluster (MITRE: Command-and-Control,
// Lateral Movement, Exfiltration).
resource networkSecurityGroupsSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
  properties: {
    version: '2.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
    contentProductId: 'azuresentinel.azure-sentinel-solution-networksecur-sl-bdnl6w63teo7m'
    contentKind: 'Solution'
    displayName: 'Azure Network Security Groups'
    source: { kind: 'Solution', name: 'Azure Network Security Groups', sourceId: 'azuresentinel.azure-sentinel-solution-networksecuritygroup' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// Azure Security Benchmark: maps telemetry to the Microsoft cloud security
// benchmark controls, adding compliance-oriented analytics/workbooks that frame
// the lab's findings against a recognized control set.
resource secBenchmarkSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
  properties: {
    version: '3.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azuresecurit-sl-cbis4wtefs3lm'
    contentKind: 'Solution'
    displayName: 'Azure Security Benchmark'
    source: { kind: 'Solution', name: 'AzureSecurityBenchmark', sourceId: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// Microsoft Defender for Cloud: ingests Defender (incl. Defender for Containers)
// alerts into Sentinel so cluster runtime alerts become correlatable incidents.
// Directly complements the "require Defender sensor" policy (MITRE: broad).
resource defenderForCloudSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-microsoftdefenderforcloud'
  properties: {
    version: '3.0.3'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-microsoftdefenderforcloud'
    contentProductId: 'azuresentinel.azure-sentinel-solution-microsoftdefe-sl-lmxphhfyonlti'
    contentKind: 'Solution'
    displayName: 'Microsoft Defender for Cloud'
    source: { kind: 'Solution', name: 'Microsoft Defender for Cloud', sourceId: 'azuresentinel.azure-sentinel-solution-microsoftdefenderforcloud' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// DNS Essentials: DNS query analytics. Surfaces beaconing, DGA, and DNS
// tunneling from compromised pods (MITRE: Command-and-Control, Exfiltration).
resource dnsEssentialsSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-dns-domain'
  properties: {
    version: '3.0.4'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-dns-domain'
    contentProductId: 'azuresentinel.azure-sentinel-solution-dns-domain-sl-ekdkjxal4jlhc'
    contentKind: 'Solution'
    displayName: 'DNS Essentials'
    source: { kind: 'Solution', name: 'DNS Essentials', sourceId: 'azuresentinel.azure-sentinel-solution-dns-domain' }
  }
  dependsOn: [ sentinelOnboarding ]
}

// --- Output -------------------------------------------------------------------
// Simple signal that onboarding + solutions completed, so dependent modules can
// gate on Sentinel being ready.
output sentinelOnboarded bool = true
