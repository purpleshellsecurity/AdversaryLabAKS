# Drafting detections — API server & runtime

A working bench for quickly writing detections on both planes. Each plane has **one
skeleton**; you swap the two or three marked parts and you have a detection.

- **Management plane** (what was *asked* of the cluster) → KQL over `AKSAudit` / `AKSAuditAdmin`
- **Runtime plane** (what a process *did* on the node) → Falco rules over syscalls

The two planes are the same brain pointed at different chokepoints:

| Concept | Management (KQL) | Runtime (Falco) |
|---------|------------------|-----------------|
| Chokepoint | kube-apiserver | syscall / kernel |
| The "verb" | `Verb` (create/get/list/delete) | `spawned_process` / `open_read` / `outbound` |
| The "target" | `ObjectRef.resource` | `proc.name` / `fd.name` / `fd.sip` |
| Identity | `User.username` | process lineage (`proc.pname`) |
| Baseline | `!in (allowlist)` | `and not (list)` |
| Rule body | `where` | `condition` |
| Output | `project` | `output` |

---

# Plane 1 — API server (KQL)

## The two tables — which to use

| Table | Category | Use it for |
|-------|----------|-----------|
| `AKSAudit` | `kube-audit` | **reads** (get/list) — the only table with them. Noisy. e.g. dump-secrets. |
| `AKSAuditAdmin` | `kube-audit-admin` | **writes** (create/delete/patch) — calmer, no read noise. Default choice. |

## Step 1 — flatten the nested JSON (paste-and-go)

Most columns are `dynamic` JSON. This lifts every field you care about into a flat
column you can filter and eyeball. Start here, then add `where`s.

```kql
AKSAuditAdmin        // swap to AKSAudit when you need reads (get/list)
| where TimeGenerated > ago(1h)
| extend
    Username     = tostring(User.username),
    UserGroups   = strcat_array(User.groups, ", "),
    ClientIp     = tostring(SourceIps[0]),
    Resource     = tostring(ObjectRef.resource),
    SubResource  = tostring(ObjectRef.subresource),
    Namespace    = tostring(ObjectRef.namespace),
    Name         = tostring(ObjectRef.name),
    ApiGroup     = tostring(ObjectRef.apiGroup),
    Decision     = tostring(Annotations["authorization.k8s.io/decision"]),
    StatusCode   = toint(ResponseStatus.code),
    StatusReason = tostring(ResponseStatus.reason)
| project TimeGenerated, Verb, Username, UserGroups, ClientIp, Resource, SubResource,
          Namespace, Name, ApiGroup, Decision, StatusCode, StatusReason, RequestUri
| sort by TimeGenerated desc
```

## Step 2 — the detection skeleton

```kql
AKSAuditAdmin
| where TimeGenerated > ago(1h)
| where Verb == "<VERB>" and ObjectRef.resource == "<RESOURCE>"        // 1. WHAT
| where User.username != "aksService" and User.username !startswith "system:"  // 2. WHO (drop noise)
| extend Username=tostring(User.username), Namespace=tostring(ObjectRef.namespace), Name=tostring(ObjectRef.name)
| project TimeGenerated, Username, ClientIp=tostring(SourceIps[0]), Namespace, Name, RequestUri
```

Swap `<VERB>` and `<RESOURCE>`. That's a detection. Tune the `system:` filter per
detection (see README → Tuning) — blanket-excluding `system:` blinds you to stolen SA tokens.

## Where each field lives (the nested-JSON map)

| Field | AKS path | Type | Note |
|-------|----------|------|------|
| action | `Verb` | string | already flat |
| who | `User.username`, `User.groups[]` | dynamic | groups is an array |
| target | `ObjectRef.resource` / `.namespace` / `.name` / `.subresource` / `.apiGroup` | dynamic | |
| request body | `RequestObject.spec…` | dynamic | **arrays → need `mv-apply`** |
| result | `ResponseStatus.code` (int), `.reason` | dynamic | 201=created, 403=denied |
| authz | `Annotations["authorization.k8s.io/decision"]` | dynamic | bracket syntax for dotted keys |
| source | `SourceIps[0]` | array | client IP is element 0 |
| scope of a list | `RequestUri` | string | `/api/v1/secrets` = cluster-wide vs `/api/v1/namespaces/<ns>/secrets` = scoped |

## Reaching inside an array (`mv-apply`)

When the signal is inside a list — containers, volumes, RBAC rules — expand it and
test each element. One output row per matching element (names the offender):

```kql
| mv-apply item = RequestObject.spec.containers on (
    where item.securityContext.privileged == true       // condition per element
    | project ContainerName = tostring(item.name), Image = tostring(item.image)
  )
```

Common array targets: `RequestObject.spec.containers` (+ `initContainers`,
`ephemeralContainers`), `RequestObject.spec.volumes`, `RequestObject.rules` (ClusterRole).

## Verb / resource quick-pick

| Want to catch | `Verb` | `ObjectRef.resource` | Extra match | Table |
|---------------|--------|----------------------|-------------|-------|
| Privileged pod | create | pods | container `privileged:true` (mv-apply) | Admin |
| hostPath mount | create | pods | volume `hostPath` (mv-apply) | Admin |
| Secret dump | list | secrets | `RequestUri startswith "/api/v1/secrets"` | Audit |
| Long-lived token | create | serviceaccounts/token | — | Admin |
| Pod exec | create | pods/exec | — | Admin |
| Cluster RBAC | create | clusterroles / clusterrolebindings | — | Admin |
| Client cert | create/update | certificatesigningrequests | `subresource == "approval"` | Admin |
| nodes/proxy grant | create | clusterroles | rule has `nodes/proxy` (mv-apply) | Admin |

---

# Plane 2 — Runtime (Falco)

## The rule skeleton

```yaml
- rule: <NAME>
  desc: <what it catches>
  condition: >
    <VERB-MACRO>              # the action
    and container             # scope to containers, not the node
    and <TARGET-MATCH>        # the binary / path / IP
    and not <KNOWN-GOOD>      # baseline / allowlist
  output: >
    <message> (pod=%k8s.pod.name proc=%proc.name parent=%proc.pname
    cmdline=%proc.cmdline image=%container.image.repository user=%user.name)
  priority: <WARNING|CRITICAL>
  tags: [container, mitre_<tactic>]
```

Swap **VERB-MACRO**, **TARGET-MATCH**, **KNOWN-GOOD**. That's a rule.

## The three verbs → macro → target field

| Verb | Macro (what you write) | Unwraps to | Target field |
|------|------------------------|-----------|--------------|
| **exec** | `spawned_process` | `evt.type in (execve,execveat) and evt.dir=<` | `proc.name` (a binary) |
| **open** | `open_read` / `open_write` | `evt.type in (open,openat,openat2) and evt.is_open_read/write=true and fd.typechar='f'` | `fd.name` (a path) |
| **connect** | `outbound` / `inbound` | `evt.type=connect and evt.dir=< and (fd.typechar=4 or 6)` | `fd.sip` (an IP) |
| *privilege* | `change_thread_namespace`, `chmod`, `rename`, `remove` | `setns` / `chmod` / `rename…` / `unlink…` | varies |

## Macro/list decoder (wrapped → unwrapped)

| Token | Unwraps to |
|-------|-----------|
| `container` | `container.id != host` |
| `container_started` | `evt.type=container or (spawned_process and proc.vpid=1)` |
| `open_read` | `evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0` |
| `open_write` | `evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0` |
| `modify` | `rename or remove` |
| `change_thread_namespace` | `evt.type=setns and evt.dir=<` (escape signal) |
| `shell_binaries` (list) | `[ash, bash, csh, ksh, sh, tcsh, zsh, dash]` |
| `bin_dir` (list) | `[/bin, /sbin, /usr/bin, /usr/sbin]` |
| `sensitive_file_names` (list) | `/etc/shadow`, `/etc/sudoers`, … |

> Definitions live in `falco_rules.yaml`; search `macro: <name>` / `list: <name>` to
> confirm for your version. Expand macros until every token is a **field** or an `evt.type`.

## Field reference (the primitives — where unwrapping stops)

| Field | Is |
|-------|-----|
| `evt.type` | the syscall (`execve`, `openat`, `connect`) |
| `evt.dir` | `>` enter / `<` return |
| `proc.name` | the process |
| `proc.pname` | the **parent** (lineage — usually where the signal is) |
| `proc.cmdline` | full command line |
| `fd.name` | file path, or connection string |
| `fd.sip` / `fd.sport` | remote IP / port |
| `fd.typechar` | `f`=file, `4`=IPv4, `6`=IPv6, `u`=unix socket |
| `container.image.repository` | the image |
| `k8s.pod.name` / `k8s.ns.name` | pod / namespace |
| `user.name` / `user.uid` | who |

## Worked examples — one per verb

```yaml
# EXEC — a shell spawned inside a container (webshell if parent is the app)
- rule: Shell in container
  condition: spawned_process and container and proc.name in (shell_binaries)
  output: "Shell in container (pod=%k8s.pod.name proc=%proc.name parent=%proc.pname)"
  priority: WARNING
```

```yaml
# OPEN — service-account token read by an unexpected process
- rule: SA token read
  condition: >
    open_read and container
    and fd.name startswith /run/secrets/kubernetes.io/serviceaccount
    and not proc.name in (expected_token_readers)
  output: "SA token read (pod=%k8s.pod.name proc=%proc.name parent=%proc.pname)"
  priority: CRITICAL
```

```yaml
# CONNECT — a pod reaching Azure IMDS (managed-identity pivot)
- rule: Pod contacted IMDS
  condition: outbound and container and fd.sip = "169.254.169.254"
  output: "Pod reached IMDS (pod=%k8s.pod.name proc=%proc.name image=%container.image.repository)"
  priority: CRITICAL
```

---

# Which plane catches which technique

The API-server cookbook catches the **loud middle** (control-plane writes). The runtime
plane catches the **post-exploitation** audit is blind to. Cloud (Azure Activity / Entra)
catches the pivot after that.

| Technique / step | Plane | Draft with |
|------------------|-------|-----------|
| privileged-pod, hostpath (the *create*) | API | KQL skeleton + mv-apply |
| dump-secrets | API | KQL, `AKSAudit`, cluster-wide URI |
| create-token, clusterrole, CSR, nodes-proxy | API | KQL skeleton |
| **the container breakout payload** | Runtime | Falco `open`/exec on host paths |
| **SA token *read*** (steal-sa-token) | Runtime | Falco `open_read` on the token path |
| reverse shell / miner | Runtime | Falco `spawned_process` + lineage |
| **IMDS → Azure pivot (the reach)** | Runtime | Falco `outbound` to `169.254.169.254` |
| use of stolen identity in Azure | Cloud | Azure Activity Log / Entra (not in this repo) |

See [`kubernetes-architecture.md`](./kubernetes-architecture.md) for the architecture
behind this, [`DETECTION-TUNING.md`](./DETECTION-TUNING.md) for the expected-identity
allowlists, and [`KQL_Container_Reference.md`](./KQL_Container_Reference.md) for the full
table reference. Detection rules live in `detections/kql/` and `detections/falco/`.
