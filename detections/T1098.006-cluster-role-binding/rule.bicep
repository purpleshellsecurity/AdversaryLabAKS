// ============================================================================
// Detection: T1098.006 - Additional Container Cluster Roles
// Deploys the analytics rule for ClusterRoleBinding/RoleBinding creation
// by non-system principals.
// ============================================================================

// This is the ALERTING half of the bundle. It is Bicep (Azure infra-as-code) that
// deploys query.kql as a scheduled Microsoft Sentinel analytics rule, so the
// detection runs automatically and raises an incident when the attack occurs.

// Caller supplies the target Log Analytics / Sentinel workspace (the one holding
// the AKSAudit logs — see creategroup.ps1 for how to get its ID).
param workspaceName string

// Instantiate the shared Sentinel-rule module rather than hand-writing the
// resource — every detection in this repo deploys through the same module.
module rule '../../infrastructure/modules/sentinel_analytics_rule.bicep' = {
  name: 'rule-T1098-006'                 // deployment name for this module instance
  params: {
    workspaceName: workspaceName         // where the rule is created
    ruleName: 'T1098-006-ClusterRoleBindingCreation'                       // internal rule id
    displayName: 'T1098.006 - RBAC Binding Created by Non-System Principal' // shown in the Sentinel UI
    ruleDescription: 'Detects ClusterRoleBinding or RoleBinding creation by principals outside the K8s system controller set. Likely indicator of persistence via additional cluster roles (MITRE T1098.006).'
    severity: 'High'                     // incident severity when it fires
    queryContent: loadTextContent('query.kql')  // the detection logic — reads query.kql at build time so rule + hunt query never drift
    queryFrequency: 'PT15M'              // ISO-8601 duration: run the query every 15 minutes
    queryPeriod: 'PT1H'                  // each run scans the last 1 hour of logs
    triggerThreshold: 0                  // alert when result count > 0 (any matching event fires)
    tactics: [ 'Persistence', 'PrivilegeEscalation' ]  // ATT&CK tactics for the incident
    techniques: [ 'T1098' ]              // ATT&CK technique (parent of T1098.006)
  }
}

// Return the created rule's resource ID so a parent deployment can reference it.
output ruleId string = rule.outputs.ruleId
