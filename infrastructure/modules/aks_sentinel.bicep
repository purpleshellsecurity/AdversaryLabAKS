// Layer 3: Monitoring - Microsoft Sentinel + Container Solutions

param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

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

output sentinelOnboarded bool = true
