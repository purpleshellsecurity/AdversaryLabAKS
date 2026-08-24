// ============================================================================
// Generic Sentinel Scheduled Analytics Rule deployer
// Used by per-detection rule.bicep wrappers in detections/<technique>/
// ============================================================================
//
// PURPOSE
//   A reusable factory for Microsoft Sentinel "Scheduled" analytics rules. Each
//   concrete detection in detections/<technique>/ supplies its own KQL query,
//   severity, and MITRE mapping, and this module wraps those into a deployable
//   alertRule. Centralizing the rule shape here means every detection gets the
//   same incident/grouping/entity behaviour for free — only the query and
//   metadata differ.
//
// ROLE IN THE DETECTION / LOGGING PIPELINE
//   This is the top of the pipeline — the DETECTION LOGIC itself. It runs on the
//   telemetry that Layers 3-4 collected (control-plane audit logs via policy,
//   container/data-plane logs via Container Insights) inside the Sentinel
//   workspace (onboarded by aks_sentinel.bicep). A scheduled rule periodically
//   executes its KQL query; when the result count exceeds the threshold it raises
//   an alert and (per config below) opens a Sentinel incident tagged with MITRE
//   ATT&CK tactics/techniques for the analyst.
// ============================================================================

// Target workspace name — the onboarded Sentinel workspace the rule is created in.
@description('Log Analytics workspace name')
param workspaceName string

// Immutable rule name (used as the resource name / logical ID). Kept
// dash/alphanumeric so it is a valid Azure resource name.
@description('Rule name (no spaces, alphanumeric + dashes)')
param ruleName string

// Human-friendly title shown in the Sentinel Analytics blade and on incidents.
@description('Display name shown in Sentinel UI')
param displayName string

// Analyst-facing explanation of what behaviour the rule detects and why it matters.
@description('Description of what the rule detects')
param ruleDescription string

// Alert severity. Constrained to Sentinel's four valid levels; drives incident
// prioritization and triage order.
@description('Severity: Informational, Low, Medium, High')
@allowed([ 'Informational', 'Low', 'Medium', 'High' ])
param severity string

// The KQL detection query. Callers typically load this from a .kql file via
// loadTextContent() so the query lives as reviewable source alongside the wrapper.
@description('The KQL query content (loaded via loadTextContent in caller)')
param queryContent string

// How often the query runs. PT15M (every 15 min) balances detection latency
// against workspace query cost for a lab.
@description('How often the rule runs (ISO 8601 duration, e.g. PT15M)')
param queryFrequency string = 'PT15M'

// The lookback window each run scans. PT1H (last hour) is wider than the 15-min
// frequency, giving overlap so events near a run boundary are not missed.
@description('How far back the query looks (ISO 8601 duration)')
param queryPeriod string = 'PT1H'

// Result-count threshold that fires the rule. Default 0 combined with the
// 'GreaterThan' operator below means "fire if there is ANY matching row" — the
// right default for high-signal adversary techniques where one hit matters.
@description('Threshold above which to fire — 0 means any match fires')
param triggerThreshold int = 0

// MITRE ATT&CK tactic names (e.g. 'Execution', 'CredentialAccess'). Surface on the
// incident so the analyst sees where the activity sits in the kill chain.
@description('MITRE ATT&CK tactics')
param tactics array = []

// MITRE ATT&CK technique IDs (e.g. 'T1059'), without sub-technique suffix per the
// Sentinel schema. Ties the detection to the ATT&CK knowledge base.
@description('MITRE ATT&CK technique IDs (without sub-technique suffix)')
param techniques array = []

// Toggle to deploy the rule disabled (e.g. while tuning) without deleting it.
@description('Whether the rule is enabled')
param enabled bool = true

// Entity mappings promote raw query columns into first-class Sentinel entities,
// which is what powers correlation, entity pages, and the investigation graph.
//
// These MUST name columns the query actually projects. They are a parameter and
// not a fixed shape because the detections legitimately return different columns:
// the audit-plane rules project `User` + `ClientIp`, lateral-movement projects
// `Username`, and the ContainerLogV2 backstops project neither. Only T1098.006
// projects the `Username` + `SourceIp` pair that used to be hardcoded here, so
// every other rule would map columns its query never returns.
//
// The default preserves the original Username/SourceIp pair so existing callers
// (detections/T1098.006-cluster-role-binding/rule.bicep) keep working unchanged.
@description('Sentinel entity mappings — must reference columns the query projects')
param entityMappings array = [
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

// How alerts are grouped into a single incident. 'AllEntities' keeps grouped
// incidents tightly correlated, but it only makes sense when the rule HAS mapped
// entities — a rule with none should use 'AnyAlert' instead, or its alerts will
// not group at all.
@description('Incident grouping strategy')
@allowed([ 'AllEntities', 'AnyAlert', 'Selected' ])
param groupingMatchingMethod string = 'AllEntities'

// Reference the existing onboarded workspace; the rule is scoped to it.
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// --- The scheduled analytics rule ---------------------------------------------
resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-12-01-preview' = {
  scope: workspace
  name: ruleName
  // 'Scheduled' = KQL runs on a timer (vs. Fusion/ML/NRT rule kinds).
  kind: 'Scheduled'
  properties: {
    displayName: displayName
    description: ruleDescription
    severity: severity
    enabled: enabled
    query: queryContent
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    // Fire when result count is GreaterThan triggerThreshold. With the default
    // threshold of 0, any single matching row triggers an alert.
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    // Suppression disabled: every qualifying run can alert. suppressionDuration is
    // required by the schema even when suppression is off, hence the placeholder.
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    // MITRE mapping attached to every alert/incident for kill-chain context.
    tactics: tactics
    techniques: techniques
    // Supplied per-detection — see the entityMappings param above for why.
    entityMappings: entityMappings
    incidentConfiguration: {
      // Auto-create a Sentinel incident on alert so triage happens in one place.
      createIncident: true
      groupingConfiguration: {
        // Group related alerts into a single incident to cut noise/alert fatigue.
        enabled: true
        // Don't reopen an already-closed incident — a closed investigation stays closed.
        reopenClosedIncident: false
        // Alerts within a 5-hour window are eligible to be grouped together.
        lookbackDuration: 'PT5H'
        // Per-detection: 'AllEntities' for rules with mapped entities, 'AnyAlert'
        // for those without (see the groupingMatchingMethod param above).
        matchingMethod: groupingMatchingMethod
      }
    }
  }
}

// --- Outputs ------------------------------------------------------------------
output ruleId string = analyticsRule.id       // full rule resource ID
output ruleName string = analyticsRule.name   // rule name for reference/wiring
