# Detections explained — a beginner's walkthrough

A ground-up guide to every detection in this repo, written for someone newer to
security operations (e.g. a junior SOC analyst). It assumes no prior Kubernetes
or KQL knowledge and builds up from what the logs *are* to why each rule is
shaped the way it is.

Companion docs:
- [`DETECTION-DRAFTING.md`](./DETECTION-DRAFTING.md) — the reusable skeletons for writing new detections
- [`DETECTION-TUNING.md`](./DETECTION-TUNING.md) — the expected-identity allowlists and the `system:` trap
- [`KQL_Container_Reference.md`](./KQL_Container_Reference.md) — the full log-table field reference

---

## Part 1 — The two things you're watching

Every attack against a Kubernetes cluster leaves fingerprints in one of two
places, and this repo is organized entirely around that split. Internalize this
first, because every detection is on one side or the other.

**The management plane** is the cluster's front desk. Anything anyone wants the
cluster to do — create a pod, read a secret, delete a deployment — goes as a
request to one component called the **kube-apiserver**. Think of it like a bank
teller: every transaction passes through the window, and there's a camera on the
window. That camera footage is the **audit log**. In AKS, Microsoft ships that
footage into a database called Log Analytics, where you query it with a language
called **KQL** (Kusto Query Language). A management-plane detection is a saved
KQL query that says "show me audit events that look like an attack."

**The runtime plane** is what happens *inside* a container after someone's
already in. Once an attacker has a foothold in a pod, they run programs, read
files, and open network connections. None of that goes through the apiserver —
it happens directly on the worker machine (the "node") at the level of
**syscalls** (the low-level requests a program makes to the operating system:
"run this program," "open this file," "connect to this IP"). A tool called
**Falco** sits on every node watching that syscall stream and fires when it sees
a suspicious pattern. A runtime-plane detection is a **Falco rule**.

The one-line reason both exist: **the audit log cannot see inside a container,
and Falco cannot see cluster API calls.** They're blind to each other. You need
both cameras.

```
Attacker → [ kube-apiserver ] → audit log → Log Analytics → KQL detections   (management plane)
Attacker → [ runs stuff in pod ] → syscalls → Falco → alerts                 (runtime plane)
```

| | Management plane (KQL) | Runtime plane (Falco) |
|---|---|---|
| Chokepoint | kube-apiserver | syscalls on the node |
| Sees | API requests (create/read/delete) | processes, file opens, network |
| Blind to | anything inside a container | any cluster API call |
| Lives in | `detections/kql/` | `detections/falco/` |

---

## Part 2 — How to read a management-plane (KQL) audit event

When someone runs `kubectl create pod`, the apiserver writes a JSON record. The
fields that matter to you:

| Field | Plain meaning | Example |
|---|---|---|
| `Verb` | the *action* | `create`, `get`, `list`, `delete`, `update`, `patch` |
| `User.username` | *who* did it | `charles@corp.com`, or `system:serviceaccount:attacker:red-team-operator` |
| `User.groups` | groups they belong to | `["system:authenticated"]` |
| `ObjectRef.resource` | *what kind of thing* | `pods`, `secrets`, `clusterroles` |
| `ObjectRef.namespace` | *where* (the "folder") | `victim`, `kube-system` |
| `ObjectRef.name` | the specific object's name | `my-pod` |
| `ObjectRef.subresource` | a sub-action on the object | `token`, `exec`, `approval` |
| `RequestObject` | the *full body* they submitted | the entire pod spec, as nested JSON |
| `RequestUri` | the URL path they hit | `/api/v1/secrets` vs `/api/v1/namespaces/victim/secrets` |
| `SourceIps[0]` | the client IP | `10.1.2.3` |
| `ResponseStatus.code` | did it work? | `201`=created, `403`=denied |

Two things trip up every beginner:

**1. Identities that start with `system:` are usually robots, not people.**
Kubernetes runs dozens of internal automated controllers, and they all
authenticate as `system:serviceaccount:kube-system:<something>` or
`system:node:<node-name>`. These do millions of legitimate operations. A human
shows up as an email or Entra ID identity. This distinction is *the* central
tuning lever in this repo — and, as Part 6 shows, also its biggest trap.

**2. The interesting data is buried in nested JSON.**
`RequestObject.spec.containers` isn't a flat column — it's an array of objects
inside a JSON blob. To inspect it you need two moves you'll see repeatedly:
- `tostring(...)` — pull a nested value out as a plain string so you can filter/display it.
- `mv-apply` — "for each element in this array, run this test." It's how you check
  *every* container in a pod, not just the first.

**The KQL skeleton.** Almost every detection in `detections/kql/` is this shape:

```kql
AKSAuditAdmin                       // 1. WHICH camera (table)
| where TimeGenerated > ago(1h)     // 2. time window
| where Verb == "create" and ObjectRef.resource == "pods"   // 3. WHAT happened
| where User.username !startswith "system:"                 // 4. drop the robots (noise)
| project TimeGenerated, User=tostring(User.username), ...   // 5. columns to show
```

Read top to bottom; each `|` is a pipe passing rows to the next filter. Lines 3
and 4 are the whole game: **line 3 says what the attack looks like, line 4 says
"and it wasn't one of the expected robots."**

**Which camera (line 1) matters.** There are two audit tables, and picking the
wrong one means your detection sees nothing:

- **`AKSAuditAdmin`** = writes only (create/delete/patch). Quiet. **Default choice.**
- **`AKSAudit`** = everything, *including reads* (get/list). Noisy, but the **only**
  table with reads.

So the rule is mechanical: if your attack is a *read* (dumping secrets, listing
things), you *must* use `AKSAudit`. Otherwise use `AKSAuditAdmin` and enjoy the quiet.

---

## Part 3 — How to read a runtime-plane (Falco) rule

A Falco rule is YAML with a `condition` (when to fire), an `output` (what to
say), and a `priority`. The condition is written in terms of *syscalls*, but
Falco gives you friendly shortcuts called **macros**:

| Macro you write | What it actually means |
|---|---|
| `spawned_process` | a program was executed |
| `container` | this happened inside a container (not on the bare node) |
| `open_read` | a file was opened for reading |
| `outbound` | an outbound network connection was made |

Fields you match on:

| Field | Meaning |
|---|---|
| `proc.name` | the program that ran (e.g. `nsenter`, `xmrig`) |
| `proc.pname` | its **parent** program — often where the real signal is |
| `proc.cmdline` | the full command line |
| `fd.name` | a file path, or a connection string |
| `fd.sip` | the remote IP of a connection |
| `k8s.pod.name` / `k8s.ns.name` | which pod / namespace |

**The Falco skeleton**, from `shell-in-container.yaml`:

```yaml
- rule: Shell Spawned in Container
  condition: >
    spawned_process and         # a program ran
    container and               # inside a container
    proc.name in (shell_binaries)   # and it was a shell (bash, sh, zsh...)
  output: "Shell spawned (pod=%k8s.pod.name proc=%proc.name parent=%proc.pname ...)"
  priority: WARNING
```

`shell_binaries` is a built-in **list** — `[ash, bash, csh, ksh, sh, tcsh, zsh,
dash]`. The `%`-fields in the output get filled in with live values when it
fires, so the alert names the exact pod and process. That `parent=%proc.pname` is
deliberate: if a shell's *parent* is the web-app process, that's a webshell —
someone got code execution through the app.

---

## Part 4 — Every detection, paired with its attack

For each one: what the attacker does, what lands in the logs, why the rule looks
the way it does, and how you'd triage it.

### Privileged pod creation — `kql/privileged-pod.kql` (T1610)

**The attack.** A privileged container (`securityContext.privileged: true`) drops
almost all the walls between the container and the host — the most common way to
turn "I can run a pod" into "I own the node." An attacker who can create pods
just adds that one line.

```kql
| where Verb == "create" and ObjectRef.resource == "pods"
| extend allContainers = array_concat(
    coalesce(RequestObject.spec.containers,          dynamic([])),
    coalesce(RequestObject.spec.initContainers,      dynamic([])),
    coalesce(RequestObject.spec.ephemeralContainers, dynamic([])))
| mv-apply container = allContainers on (
    where container.securityContext.privileged == true
    | project ContainerName = tostring(container.name), Image = tostring(container.image))
| where User.username != "aksService" and User.username !startswith "system:"
```

**Why it's built this way.** Privilege can hide in a *sidecar*, an *init*
container (runs first), or an *ephemeral* container (attached for "debugging").
The rule glues all three lists together, then `mv-apply` checks each and reports
the specific offending container by name. `coalesce(..., dynamic([]))` means "if
that list is missing, treat it as empty" so the query doesn't error. `== true` is
null-safe: a container that never sets the flag reads as null, which isn't equal
to true, so it's correctly ignored.

**Triage.** Real → a workload namespace (`victim`, `default`) creating a
privileged pod. Benign → `kube-system` DaemonSets like `kube-proxy` and CSI
storage drivers are *legitimately* privileged, which is why the last line drops
`system:` and `aksService`.

### hostPath volume mount — `kql/hostpath-volume.kql` (T1611)

**The attack.** A `hostPath` volume mounts a directory from the *node's*
filesystem into the container. Mount `/`, `/etc`, or the kubelet's credential
directory and you've got a window onto the host — no `privileged` needed.

**The detection.** Same skeleton, but `mv-apply` walks `RequestObject.spec.volumes`
and fires on `isnotempty(volume.hostPath)`. It keys on "the field exists" rather
than a specific path because the attacker chooses the path — you can't enumerate
the bad ones. Same triage shape: CSI drivers and monitoring agents in
`kube-system` mount hostPath legitimately; a hostPath in `victim` is the alert.

### Cluster-wide secret dump — `kql/dump-secrets.kql` (T1552.007)

**The attack.** `kubectl get secrets --all-namespaces` — one command that reads
every secret in the cluster, which is a single `list` call to `/api/v1/secrets`.

**The wrong model:** "alert when a user reads more than N secrets." Wrong, because
the attack isn't 500 small reads — it's *one* big read. Counting misses it.

**The right detection:**
```kql
AKSAudit                                        // reads → MUST be the full table
| where ObjectRef.resource == "secrets" and Verb == "list"
| where RequestUri startswith "/api/v1/secrets" // cluster-wide, ALL namespaces
| where User.username != "aksService" and User.username !startswith "system:"
```

The tell is the **URI shape**. A scoped read is
`/api/v1/namespaces/victim/secrets` (one namespace); the cluster-wide grab is
`/api/v1/secrets` (no namespace in the path). That single distinction separates
"an app reading its own secret" from "an attacker vacuuming the whole cluster."
Table is `AKSAudit` because reads only live in the full table.

### Long-lived service-account token minted — `kql/create-token.kql` (T1098)

**The attack.** Service-account tokens are the passwords robots use. Normally
they're short-lived and auto-rotated. An attacker mints a long-lived token via
the TokenRequest API — especially against an already-powerful `kube-system`
service account — for durable access that survives reboots.

**The detection.** Fires on `create serviceaccounts/token` (note
`subresource == "token"`). Subtlety from the rule's comment: this *and* the
nodes-proxy technique both mint tokens — tell them apart by *which* service
account is targeted (existing privileged one = this; fresh purpose-built one =
nodes-proxy). Kubelets (`system:node:*`) mint projected tokens constantly, so
they're allowlisted.

### Self-approved client certificate — `kql/create-client-certificate.kql` (T1098)

**The attack.** Kubernetes has a certificate-request system (CSR = Certificate
Signing Request). Normally it's two-party: one identity *requests*, a *different*
trusted controller *approves* — like needing a second person to countersign a
check. An attacker with enough rights does both: create the CSR, then approve
their own CSR, walking away with a valid, non-expiring client certificate.

```kql
| where ObjectRef.resource == "certificatesigningrequests"
| where (Verb == "create") or (Verb == "update" and ObjectRef.subresource == "approval")
| where User.username !startswith "system:"
| sort by TimeGenerated asc
```

**The signal:** the **same non-system user appearing twice** — once creating, once
hitting the `/approval` subresource. Legitimate PKI *separates* those actors
(kubelets create, `certificate-controller` approves — both `system:`). One human
doing both is the anomaly. `sort asc` puts create-then-approve in order so you can
*see* the self-signing sequence.

### ClusterRole granting nodes/proxy — `kql/nodes-proxy-grant.kql` (T1611)

**The attack.** The kubelet (agent on each node) has its own API. Reach it via
`nodes/proxy` and you can run commands on the node — another road to host
compromise.

**Detect the grant, not the act.** The actual `nodes/proxy` call goes *straight to
the kubelet* and never touches the apiserver audit log — so **you cannot detect
the action itself.** What you *can* detect is the RBAC permission being handed
out:
```kql
| where Verb == "create" and ObjectRef.resource == "clusterroles"
| mv-apply rule = RequestObject.rules on (
    where set_has_element(rule.resources, "nodes/proxy"))
```

The mindset every analyst needs: when the attack is invisible at your chokepoint,
back up and detect the *enabling step* that isn't.

### Cross-namespace lateral movement — `kql/lateral-movement.kql` (T1550.001)

**The attack** (`attack-simulations/lateral-movement.sh`): an attacker in the
`attacker` namespace uses a service-account token to reach into the `victim`
namespace (`kubectl get secrets -n victim`). Namespaces are meant to be walls; a
token from one poking at another is a strong "moving sideways" signal.

```kql
| extend SourceNamespace = extract("system:serviceaccount:([^:]+):", 1, Username)
| extend TargetNamespace = tostring(ObjectRef.namespace)
| where SourceNamespace != TargetNamespace
```

A service-account username is literally `system:serviceaccount:<namespace>:<name>`.
The regex pulls the namespace out of the *identity*; the object tells you the
namespace being *touched*. When they don't match, the token is acting outside its
home.

### Log-string fallbacks — `kql/container-escape.kql` & `kql/crypto-mining.kql`

These watch `ContainerLogV2` (container stdout/stderr) for telltale strings:
`nsenter` (a container-breakout tool, T1611) and miner strings like `xmrig`,
`stratum+tcp`, `cryptonight` (T1496).

Be honest about these: they're **weaker** than the Falco versions, because they
only fire if the tool prints its name to the logs — an attacker can stay quiet.
They're a backstop for when Falco isn't watching. The crypto rule also carries a
commented-out second angle — a CPU-usage anomaly over `InsightsMetrics` (mining
pins the CPU) — which catches miners that *don't* announce themselves. "Two
independent angles on one technique" is worth copying.

### The honest template — `kql/network-lateral-movement.kql` (T1046)

Read this for the engineering-discipline lesson. Its own header says **TEMPLATE /
UNVERIFIED**. It aims to catch pod-to-pod network flows between namespaces that
normally never talk — but that requires network flow logs (ACNS/Hubble) that
aren't on by default, and the table name in the query (`RetinaNetworkFlowLogs`)
is a *placeholder* to confirm against real data. It's checked in as clearly
labeled scaffolding. Good detection engineering states what it *doesn't* know.

### The fully-productized one — `T1098.006-cluster-role-binding/`

**The attack** (`attack.sh`): the attacker binds their own service account to
`cluster-admin` via a ClusterRoleBinding. That's game over — cluster-admin is
root for the cluster — and it's persistence: even if you kick them out, the
binding keeps their access.

**Why this folder looks different.** Every other detection is a lone `.kql` file.
This one is a complete *package* showing what "production" looks like:

- `query.kql` — the detection.
- `attack.sh` — performs the attack (creates a binding named `adversary-lab-test-crb-<timestamp>`).
- `test.kql` — a **test** that looks for that test binding name and returns a
  count. The *intent* is: run the attack, then this query, and assert count > 0 —
  proving *the attack actually trips the detection*. **The most valuable idea in
  the repo: you don't trust a detection until you've fired the real attack at it
  and watched it catch it.** ⚠️ **Important honesty note:** this end-to-end loop
  is **not yet wired into CI** — `test.kql` is the ingredient, but no workflow runs
  it against a live cluster today. So this detection is *proof-ready*, not proven.
  See [`DETECTION-COVERAGE.md`](./DETECTION-COVERAGE.md) for how proof is actually
  being built (offline logic tests + live end-to-end).
- `rule.bicep` — infrastructure-as-code that deploys this as a live Microsoft
  Sentinel analytics rule (High severity, runs every 15 min, looks back 1 hour).
  This is how a detection stops being a text file and becomes an alert that pages
  someone.

The query also does two things the simpler ones don't: `ResponseStatus.code
between (200..299)` (only count *successful* bindings — a denied attempt is
different) and `Stage == "ResponseComplete"` (audit logs each request at multiple
stages; take the final one so you don't double-count).

---

## Part 5 — The runtime (Falco) rules, as an attacker's session

The Falco rules make the most sense read in the order an intrusion unfolds
*inside* a pod. Picture an attacker who just got code execution in a web app:

1. **`falco/shell-in-container.yaml` (T1059, WARNING)** — first they get a shell.
   Fires when a shell binary spawns in a container. If the parent (`proc.pname`)
   is the app, that's a webshell. WARNING not CRITICAL, because legit debugging
   also spawns shells — a lead, not a smoking gun.
2. **`falco/reverse-shell.yaml` (T1059, CRITICAL)** — they upgrade to a reverse
   shell for interactive control from outside. Fires on `/dev/tcp/`, `bash -i`, or
   `nc/ncat/nmap -e`. CRITICAL — almost nothing legitimate does this.
3. **`falco/token-theft.yaml` (T1528, WARNING)** — they read the mounted
   service-account token to steal the pod's identity. This is
   `attack-simulations/token-theft.sh`, literally
   `cat /var/run/secrets/kubernetes.io/serviceaccount/token`. Fires on `open_read`
   of that exact path. **The runtime counterpart to the KQL token detections** —
   it catches the *read of the file*, which the audit log never sees.
4. **`falco/imds-access.yaml` (T1552.005, CRITICAL)** — the pivot to the cloud.
   `169.254.169.254` is the **Azure Instance Metadata Service (IMDS)** — a magic
   IP every Azure VM can reach to get its own managed-identity credentials. A
   container connecting there is trying to steal the *node's* Azure identity and
   break out of Kubernetes into your Azure subscription. Rule:
   `outbound and container and fd.sip = "169.254.169.254"`. Simple, high-value — a
   container almost never has a legitimate reason to hit IMDS.
5. **`falco/container-escape.yaml` (T1611, CRITICAL)** — `nsenter` spawned in a
   container, the tool of choice for breaking out to the host. The stronger
   sibling of the KQL log-string version, because it sees the *execution*.
6. **`falco/crypto-mining.yaml` (T1496.001, CRITICAL)** — if the goal was money,
   they drop a miner. Fires on miner process names or pool strings in the cmdline.

These interlock with the management plane. The IMDS pivot (Falco) and the stolen
token being *used* against the apiserver (KQL lateral-movement) are the same
attacker, two planes, two detections. That's the whole thesis of the lab.

---

## Part 6 — The one trap that will bite you: the `system:` blind spot

This is in [`DETECTION-TUNING.md`](./DETECTION-TUNING.md) and it's the most
important thing to understand, because it's a place where the *obvious* tuning is
*wrong*.

Every KQL detection drops noise with `!startswith "system:"` — "ignore the
robots." Reasonable, because system controllers generate mountains of legitimate
activity. **The hole:** one of the attacks in this lab is *stealing a
service-account token*, and a stolen token authenticates as
`system:serviceaccount:...`. So a blanket "ignore everything starting with
`system:`" means **a stolen token walks straight past every detection** — the
exact attack the lab is built to catch.

**The fix, and the career principle: allowlist by (identity × action), not
identity alone.** Don't say "the replicaset-controller is trusted." Say "the
replicaset-controller is trusted *to create pods*." Then if that controller's
token suddenly lists every secret in the cluster, it's not on the *secrets*
allowlist, and it still fires — because a stolen token does things the real
controller never does.

The tuning doc gives you the machinery: a per-detection `let` list of expected
identities (scoped — e.g. only `kube-system` service accounts, not all
namespaces), a **baselining query** you run during a quiet period to discover
what's *normally* doing each action (that output literally *is* your allowlist),
and advice to prefer "alert when a *new* identity does X for the first time in 30
days" over static lists, which rot as the cluster changes.

**Triage takeaway:** when you get one of these alerts, "the actor is a `system:`
account" is **not** a reason to close it. Ask whether *that specific* account
doing *that specific* action is normal.

---

## Part 7 — How you'd actually triage one of these alerts

Put it together. Say you get the **T1098.006 RBAC binding** alert. Your loop:

1. **Who** — look at `Username`. A human email? A workload service account? A
   `kube-system` controller? (Remember Part 6: `system:` is not an all-clear.)
2. **What exactly** — `BindingName`, and what role it grants. Binding to
   `cluster-admin` is a five-alarm fire; binding to a read-only role is a shrug.
3. **Did it succeed** — `ResponseCode`. 2xx means it happened; 403 means it was
   blocked (still note it — someone *tried*).
4. **Where from** — `SourceIp` and `UserAgent`. A `kubectl` from a pod IP in the
   `attacker` namespace is very different from your CI/CD system's IP.
5. **Corroborate across planes** — the senior move. Is there a Falco alert from
   the same pod around the same time? A token-theft read, then a cross-namespace
   API call, then an RBAC binding is a *chain* — and the chain is the story you
   escalate, not three isolated blips.
6. **Decide** — real attack (escalate with the timeline), known-good automation
   you should *add to the allowlist* (tune it), or a gap where you need more data
   (like the network template that isn't wired up yet).

---

## One-page mental model

- **Two planes** because attacks live in two places the other plane can't see.
- **One reusable skeleton per plane** (`DETECTION-DRAFTING.md`) so you write new
  detections fast: swap the verb, the target, and the allowlist.
- **`AKSAuditAdmin` for writes, `AKSAudit` for reads** — reads only exist in the
  full table.
- **MITRE technique IDs on everything** so you can talk about coverage.
- **Attack scripts paired with detections** so nothing is trusted until it's been
  fired at (the T1098.006 package is the model).
- **Detect the enabling grant** when the action itself is invisible (nodes/proxy).
- **Allowlist by identity × action**, never identity alone — or a stolen `system:`
  token blinds you.
- **The chain is the story** — correlate management-plane and runtime-plane
  alerts from the same pod/time before you escalate.
