// ============================================================================
// Generic Sentinel Scheduled Analytics Rule deployer
// Used by per-detection rule.bicep wrappers in detections/<technique>/
// ============================================================================

@description('Log Analytics workspace name')
param workspaceName string

@description('Rule name (no spaces, alphanumeric + dashes)')
param ruleName string

@description('Display name shown in Sentinel UI')
param displayName string

@description('Description of what the rule detects')
param ruleDescription string

@description('Severity: Informational, Low, Medium, High')
@allowed([ 'Informational', 'Low', 'Medium', 'High' ])
param severity string

@description('The KQL query content (loaded via loadTextContent in caller)')
param queryContent string

@description('How often the rule runs (ISO 8601 duration, e.g. PT15M)')
param queryFrequency string = 'PT15M'

@description('How far back the query looks (ISO 8601 duration)')
param queryPeriod string = 'PT1H'

@description('Threshold above which to fire — 0 means any match fires')
param triggerThreshold int = 0

@description('MITRE ATT&CK tactics')
param tactics array = []

@description('MITRE ATT&CK technique IDs (without sub-technique suffix)')
param techniques array = []

@description('Whether the rule is enabled')
param enabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-12-01-preview' = {
  scope: workspace
  name: ruleName
  kind: 'Scheduled'
  properties: {
    displayName: displayName
    description: ruleDescription
    severity: severity
    enabled: enabled
    query: queryContent
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: tactics
    techniques: techniques
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Username' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'SourceIp' }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

output ruleId string = analyticsRule.id
output ruleName string = analyticsRule.name
