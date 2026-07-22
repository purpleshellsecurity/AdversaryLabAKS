# Detection tuning — expected identities & exceptions

The KQL detections in `detections/kql/` suppress noise with a blanket
`!startswith "system:"`. That's fine for the lab, but for a real environment it has
a hole: **`steal-serviceaccount-token` gives an attacker a `system:serviceaccount:…`
identity.** Blanket-excluding the `system:` prefix means a stolen SA token walks past
every detection — the exact thing this lab exists to catch.

So allowlist by **(identity × action)**, not by identity alone. Each controller is
expected to do *its own* job and nothing else — a `replicaset-controller` token that
suddenly lists all secrets is not on the *secrets* allowlist, so it still fires.

## Core Kubernetes controllers (stable across clusters)

All are `system:serviceaccount:kube-system:<name>`:

| Identity | Legitimately does | Relevant detection |
|----------|-------------------|--------------------|
| `replicaset` / `daemonset` / `job` / `statefulset` / `cronjob`-controller | create **pods** | privileged-pod, hostpath-volume |
| `system:node:<node>` (kubelets) | mint **serviceaccounts/token**, patch **nodes**, create **CSRs** | create-token, nodes-proxy, create-client-certificate |
| `certificate-controller` | approve/sign **CSRs** | create-client-certificate |
| `generic-garbage-collector`, `resourcequota-controller`, `namespace-controller` | list/delete **secrets** cluster-wide | dump-secrets |
| `clusterrole-aggregation-controller` | update aggregated **ClusterRoles** | cluster-role-binding (T1098.006) |
| `root-ca-cert-publisher`, `service-account-controller` | **serviceaccounts** / token plumbing | create-token |
| `aksService` (AKS RP identity) | reconcile managed **ClusterRoles**, cluster config | nodes-proxy, cluster-role-binding |

## AKS addon service accounts (present only if the addon is enabled)

Names are version-dependent — verify against your cluster: `metrics-server`,
`konnectivity-agent`, `coredns`, `cloud-node-manager`, `kube-proxy`, the CSI drivers
(`csi-azuredisk-*`, `csi-azurefile-*` — privileged + hostPath), `ama-logs`/`omsagent`
(Container Insights), `secrets-store-csi-driver` (Key Vault — legitimately reads
secrets), `azure-wi-webhook-*` (workload identity), `gatekeeper`/`azure-policy`.

## Scope allowlists per detection

Use a `let` list scoped to each detection rather than one global filter. Example for
the noisiest one (`create-token`):

```kql
let token_minters = dynamic(["aksService"]);   // add named kube-system SAs you baseline
AKSAuditAdmin
| where Verb == "create" and ObjectRef.resource == "serviceaccounts" and ObjectRef.subresource == "token"
| where User.username !in (token_minters)
| where User.username !startswith "system:node:"                        // kubelet projected tokens
| where User.username !startswith "system:serviceaccount:kube-system:"  // control-plane SAs ONLY
| project TimeGenerated, User=tostring(User.username), ServiceAccount=tostring(ObjectRef.name), RequestUri
```

Note it allowlists `system:serviceaccount:**kube-system**:` specifically — not all
namespaces. A token mint by a service account in a *workload* namespace still surfaces.

- **`pods/exec` needs almost no allowlist** — automation essentially never execs. Keep it loud.
- **Cluster RBAC creates by any human should always surface.**

## Baselining — the authoritative list for *your* cluster

One query over a quiet window (no attack simulations running) — swap the `where` per detection:

```kql
AKSAuditAdmin
| where Verb == "create" and ObjectRef.resource == "serviceaccounts" and ObjectRef.subresource == "token"
| summarize count() by User = tostring(User.username)
| sort by count_ desc      // this list IS your allowlist
```

Prefer "alert when a *new* identity does X for the first time in 30d" over a static
list where you can — allowlists rot as addons and operators come and go.
