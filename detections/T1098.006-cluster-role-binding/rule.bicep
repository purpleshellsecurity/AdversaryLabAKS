// ============================================================================
// Detection: T1098.006 - Additional Container Cluster Roles
// Deploys the analytics rule for ClusterRoleBinding/RoleBinding creation
// by non-system principals.
// ============================================================================

param workspaceName string

module rule '../../infrastructure/modules/sentinel_analytics_rule.bicep' = {
  name: 'rule-T1098-006'
  params: {
    workspaceName: workspaceName
    ruleName: 'T1098-006-ClusterRoleBindingCreation'
    displayName: 'T1098.006 - RBAC Binding Created by Non-System Principal'
    ruleDescription: 'Detects ClusterRoleBinding or RoleBinding creation by principals outside the K8s system controller set. Likely indicator of persistence via additional cluster roles (MITRE T1098.006).'
    severity: 'High'
    queryContent: loadTextContent('query.kql')
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerThreshold: 0
    tactics: [ 'Persistence', 'PrivilegeEscalation' ]
    techniques: [ 'T1098' ]
  }
}

output ruleId string = rule.outputs.ruleId
