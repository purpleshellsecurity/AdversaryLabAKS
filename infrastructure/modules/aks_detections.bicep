// ============================================================================
// AKS Adversary Lab - Detection content deployer (detections/kql/)
// ============================================================================
//
// PURPOSE
//   Deploys every KQL detection in detections/kql/ as a scheduled Microsoft
//   Sentinel analytics rule, so the rules actually ALERT rather than sitting in
//   the repo as hunting queries an analyst must paste by hand.
//
// WHY THIS MODULE EXISTS
//   Detection-as-code is a five-stage loop: author -> validate -> test -> deploy
//   -> measure. This repo had the first three (validate.py, then kql_test.py
//   running each rule against fixtures in a real Kusto engine) but only ONE
//   detection was ever deployed: T1098.006, via its own rule.bicep wrapper. The
//   other ten were validated, tested, and then went nowhere. That inverted the
//   value of the CI — the harder the rules were tested, the more it mattered
//   that nothing ran them. This module closes that gap for the whole library.
//
// SINGLE SOURCE OF TRUTH
//   Each detection is a PAIR of files under detections/kql/:
//     <name>.kql            - the detection logic
//     <name>.metadata.json  - severity, ATT&CK mapping, schedule, entity mappings
//
//   Both are read at COMPILE time (loadTextContent / loadJsonContent), so the
//   deployed rule can never drift from the reviewed query — the same principle
//   applied to Falco rules by tools/build-falco-rules.py, and to T1098.006 by
//   its rule.bicep. Editing a .kql file is sufficient; nothing needs re-syncing.
//
//   JSON rather than YAML for the metadata because loadJsonContent() is the only
//   structured-data loader Bicep has. The trade-off is no comments in the
//   sidecars, so per-detection rationale lives in this file and in the .kql
//   header block.
//
// WHY THE PATHS ARE SPELLED OUT ONE BY ONE
//   loadTextContent() and loadJsonContent() require a COMPILE-TIME CONSTANT
//   path — they cannot take a variable, so the array below cannot be built by
//   looping over a directory listing. Adding a detection therefore means adding
//   one entry here. That is a deliberate, reviewable step: a new rule does not
//   start alerting in a live workspace without someone approving this diff.
// ============================================================================

// Target workspace — the Sentinel-onboarded workspace holding the AKS audit logs.
@description('Log Analytics workspace name')
param workspaceName string

// ── The detection library ───────────────────────────────────────────────────
// union() merges each metadata sidecar with its query text into one object, so
// every field the rule factory needs travels together.
var detections = [
  union(loadJsonContent('../../detections/kql/privileged-pod.metadata.json'), {
    query: loadTextContent('../../detections/kql/privileged-pod.kql')
  })
  union(loadJsonContent('../../detections/kql/hostpath-volume.metadata.json'), {
    query: loadTextContent('../../detections/kql/hostpath-volume.kql')
  })
  union(loadJsonContent('../../detections/kql/nodes-proxy-grant.metadata.json'), {
    query: loadTextContent('../../detections/kql/nodes-proxy-grant.kql')
  })
  union(loadJsonContent('../../detections/kql/dump-secrets.metadata.json'), {
    query: loadTextContent('../../detections/kql/dump-secrets.kql')
  })
  union(loadJsonContent('../../detections/kql/create-token.metadata.json'), {
    query: loadTextContent('../../detections/kql/create-token.kql')
  })
  union(loadJsonContent('../../detections/kql/create-client-certificate.metadata.json'), {
    query: loadTextContent('../../detections/kql/create-client-certificate.kql')
  })
  union(loadJsonContent('../../detections/kql/container-escape.metadata.json'), {
    query: loadTextContent('../../detections/kql/container-escape.kql')
  })
  union(loadJsonContent('../../detections/kql/crypto-mining.metadata.json'), {
    query: loadTextContent('../../detections/kql/crypto-mining.kql')
  })
  union(loadJsonContent('../../detections/kql/lateral-movement.metadata.json'), {
    query: loadTextContent('../../detections/kql/lateral-movement.kql')
  })
  // NOT deployed — see its metadata sidecar. The query reads a placeholder table
  // name for the Container Network Logs plane, which this lab does not enable, so
  // a deployed rule would error on every run. It is listed here (rather than
  // omitted) so the array stays a complete inventory of the library, and the
  // `deploy` flag below is what excludes it.
  union(loadJsonContent('../../detections/kql/network-lateral-movement.metadata.json'), {
    query: loadTextContent('../../detections/kql/network-lateral-movement.kql')
  })
]

// Skipping a deployment is a declared property of the detection, not an absence
// — which keeps "why isn't this rule live?" answerable from the metadata alone.
var deployableDetections = filter(detections, d => d.deploy)

// ── Deploy one scheduled analytics rule per detection ───────────────────────
// Every rule goes through the same factory module, so incident grouping, entity
// promotion, and trigger semantics stay identical across the library.
module detectionRules 'sentinel_analytics_rule.bicep' = [for d in deployableDetections: {
  name: 'detection-${d.ruleName}'
  params: {
    workspaceName: workspaceName
    ruleName: d.ruleName
    displayName: d.displayName
    ruleDescription: d.description
    severity: d.severity
    queryContent: d.query
    queryFrequency: d.queryFrequency
    queryPeriod: d.queryPeriod
    triggerThreshold: d.triggerThreshold
    tactics: d.tactics
    techniques: d.techniques
    // A rule may deploy DISABLED — see lateral-movement, which the coverage
    // matrix rates Draft. Shipping a known-noisy rule enabled would train an
    // analyst to ignore it; shipping it disabled keeps it reviewed and ready.
    enabled: d.enabled
    entityMappings: d.entityMappings
    groupingMatchingMethod: d.groupingMatchingMethod
  }
}]

// ── Outputs ─────────────────────────────────────────────────────────────────
// Surfaced so the deploy job can report what actually shipped, and so a caller
// can assert the expected number of rules exists.
output deployedRuleNames array = [for (d, i) in deployableDetections: d.ruleName]
output deployedRuleCount int = length(deployableDetections)
output enabledRuleCount int = length(filter(deployableDetections, d => d.enabled))
