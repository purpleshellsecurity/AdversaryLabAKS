# KQL Container Log Reference

Quick reference for querying AKS log tables in the Adversary Lab environment.

> Where the dynamic-column parsing patterns come from and how they were verified:
> [KQL-AUDIT-PARSING.md](KQL-AUDIT-PARSING.md)

## Table Overview

| Table | Source | Primary Use |
|-------|--------|-------------|
| AKSAudit | API server (all operations) | Full audit trail |
| AKSAuditAdmin | API server (mutations only) | State changes |
| AKSControlPlane | guard, kube-apiserver, scheduler | Auth decisions |
| ContainerLogV2 | Container stdout/stderr | Application logs |
| KubeEvents | Kubernetes events | Pod lifecycle |
| KubePodInventory | Pod metadata snapshots | Pod status |
| InsightsMetrics | Prometheus metrics | CPU, memory, network |
| SecurityAlert | Defender for Containers | Runtime threat detections |
| AzureActivity | ARM control plane | Resource CRUD |

## AKSAudit

```kql
// Detect exec into container (T1609)
AKSAudit
| where TimeGenerated > ago(1h)
| where Verb == "create"
| where tostring(ObjectRef.subresource) == "exec"
| project TimeGenerated, User = tostring(User.username), PodName = tostring(ObjectRef.name), Namespace = tostring(ObjectRef.namespace)

// Detect secret enumeration (T1552.007)
AKSAudit
| where TimeGenerated > ago(1h)
| where Verb in ("get", "list")
| where tostring(ObjectRef.resource) == "secrets"
| project TimeGenerated, User = tostring(User.username), Namespace = tostring(ObjectRef.namespace)

// Detect RBAC escalation (T1098.006)
AKSAuditAdmin
| where TimeGenerated > ago(1h)
| where Verb in ("create", "update", "patch")
| where tostring(ObjectRef.resource) in ("clusterrolebindings", "rolebindings")
| project TimeGenerated, User = tostring(User.username), Resource = tostring(ObjectRef.name)
```

## ContainerLogV2

```kql
// Crypto mining detection (T1496)
ContainerLogV2
| where TimeGenerated > ago(1h)
| where LogMessage has_any ("xmrig", "minerd", "stratum+tcp", "cryptonight")
| project TimeGenerated, PodName, PodNamespace, ContainerName, LogMessage

// Reverse shell detection (T1059)
ContainerLogV2
| where TimeGenerated > ago(1h)
| where LogMessage has_any ("bash -i", "/dev/tcp/", "nc -e")
| project TimeGenerated, PodName, PodNamespace, LogMessage
```

## InsightsMetrics

```kql
// High CPU — potential mining (T1496)
InsightsMetrics
| where TimeGenerated > ago(1h)
| where Namespace == "container.azm.ms/cpu"
| where Name == "cpuUsageNanoCores"
| extend Tags = parse_json(Tags)
| where todouble(Val) > 1800000000
| project TimeGenerated, PodName = tostring(Tags.podName), CpuCores = Val / 1000000000
```

## SecurityAlert

```kql
// All Defender alerts
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProductName has "Defender"
| project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques
| order by AlertSeverity asc
```

## AzureActivity

```kql
// AKS resource changes
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "ContainerService"
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup
```
