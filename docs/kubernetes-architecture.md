# Kubernetes Architecture — a control-plane & audit-log field guide

A working reference for detection engineering on AKS: what the moving parts are,
why the API server is the one place every action is recorded, and how components,
identities, and resources map onto the events you query in `AKSAudit` /
`AKSAuditAdmin`. Companion to the AKS Adversary Lab.

## 1. Control plane vs. data plane

On AKS the **control plane is managed for you**; the **data plane (nodes)** is yours.

### Control plane (managed by AKS)

| Component | What it does |
|-----------|--------------|
| **kube-apiserver** | The front door. Every create/read/change is authenticated → authorized → admitted → persisted, in that order. **This is what emits the kube-audit logs.** |
| **etcd** | Cluster state store. Secrets live here — base64, *not* encrypted by default. |
| **kube-scheduler** | Assigns pods to nodes. |
| **kube-controller-manager** | Runs the built-in controllers (replicaset, node, namespace, certificate, garbage-collector…). These are the `system:*` identities in your logs. |
| **cloud-controller-manager** | Azure integration — load balancers, node lifecycle, disks (`cloud-node-manager` & friends). |

### Data plane (your nodes)

| Component | What it does |
|-----------|--------------|
| **kubelet** | Node agent. Talks to the API server, starts pods, mints projected tokens, rotates its certs. Identity: `system:node:<node>`. |
| **kube-proxy** | Service networking. Privileged, hostNetwork. |
| **containerd** | Pulls images, runs containers. |
| **pods → containers** | Your workloads. `securityContext` & `volumes` decide the blast radius. |

## 2. One request, four gates — and the field each one writes

Every call through the API server passes the same gates. That pipeline is *why*
your log columns exist:

```
client ──▶ Authentication ──▶ Authorization (RBAC) ──▶ Admission ──▶ Persist to etcd
              │                     │                      │              │
        User.username        Annotations            Annotations     ResponseStatus.code
        User.groups          authorization.k8s.io   mutation.webhook ResponseObject
                             /decision              …
```

- The request body you inspect is **`RequestObject`**.
- The target is **`ObjectRef`** (`.resource`, `.namespace`, `.subresource`, `.name`).
- The action is **`Verb`**.

Every detection is just a filter over these, plus a lookup inside `RequestObject`.

## 3. Where it lands — the three AKS tables

| Table | Category | Contents |
|-------|----------|----------|
| **`AKSAudit`** | `kube-audit` | The full firehose, **including reads** (get/list). Noisy. The only table where a secret *dump* shows up. |
| **`AKSAuditAdmin`** | `kube-audit-admin` | **Writes only** — drops read-only get/list. The calm table to build write-technique detections on. |
| **`guard`** | `guard` | Microsoft Entra (AAD) authorization decisions. |

## 4. Who's asking — four kinds of caller

| Kind | Username form | Notes |
|------|---------------|-------|
| **Human** | `alice@corp.com`, `<object-id>` | Entra-authenticated. Should rarely touch cluster-wide secrets or RBAC. |
| **ServiceAccount** | `system:serviceaccount:<ns>:<name>` | In-cluster workloads & controllers. A **stolen** token looks exactly like this — don't blanket-trust the prefix. |
| **Node / kubelet** | `system:node:aks-nodepool1-…` | Huge routine volume: token minting, node-status patches, cert rotation. |
| **system:masters** | `masterclient`, `clusterAdmin` | The god group. The admin kubeconfig. Bypasses RBAC checks. |

## 5. Attack surface → audit signal (the 8 Stratus k8s techniques)

| Resource / API | Technique | What to match | Table |
|----------------|-----------|---------------|-------|
| `pods` · securityContext | privileged-pod | `create pods` + container `privileged:true` | Admin |
| `pods` · volumes | hostpath-volume | `create pods` + volume `hostPath` | Admin |
| `secrets` | dump-secrets | `list` on `/api/v1/secrets` (cluster-wide) | Audit |
| `serviceaccounts/token` | create-token | `create` TokenRequest for a privileged SA | Admin |
| `pods/exec` | steal-serviceaccount-token | `create pods/exec` (token read itself is off-log) | Admin |
| `clusterroles` · `clusterrolebindings` | create-admin-clusterrole | `create` cluster RBAC by a non-system user | Admin |
| `certificatesigningrequests` | create-client-certificate | `create` + self-`approval`, one principal | Admin |
| `clusterroles` · rules | nodes-proxy | ClusterRole granting `nodes/proxy` | Admin |

Notice how many collapse to one primitive: **create a pod**, **create RBAC**,
**mint/steal a credential**. Learn those three and the eight techniques stop being
eight separate things.

## 6. Field names: the docs vs. your table

Stratus's technique pages document the raw upstream Kubernetes audit event
(camelCase). AKS's resource-specific tables lift the same fields into PascalCase
`dynamic` columns — same event, renamed:

| Raw k8s audit (docs) | AKSAudit column |
|----------------------|-----------------|
| `http.method` | `Verb` |
| `objectRef.resource` | `ObjectRef.resource` |
| `user.username` | `User.username` |
| `requestObject.spec…` | `RequestObject.spec…` |
| `responseStatus.code` | `ResponseStatus.code` |
| `annotations["authorization.k8s.io/decision"]` | `Annotations["authorization.k8s.io/decision"]` |

Arrays (`spec.containers`, `spec.volumes`, RBAC `rules`) need `mv-apply` to inspect
each element individually — see the detection rules in `detections/kql/` and the drafting bench in [DETECTION-DRAFTING.md](./DETECTION-DRAFTING.md).

---

*Names and attribution are Kubernetes-version- and AKS-addon-dependent. Baseline
your own cluster to confirm the expected set — see "Tuning: expected identities"
in the README.*
