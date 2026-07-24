# Detection coverage matrix — MITRE ATT&CK × detections × triggers

The single source of truth mapping **every detection in this repo** to its MITRE
ATT&CK technique, the plane it runs on, the log source it reads, the **trigger
script** that fires it, and an honest **maturity** rating.

- Machine-readable visual version: [`attack-navigator-layer.json`](./attack-navigator-layer.json)
  — load it at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
  (Open Existing Layer → Upload from local) for a color-coded coverage map.
- Beginner walkthrough of *why* each rule is shaped the way it is:
  [`DETECTIONS-FOR-BEGINNERS.md`](./DETECTIONS-FOR-BEGINNERS.md).
- Provenance: the 8 management-plane techniques are derived from the
  [Stratus Red Team](https://github.com/DataDog/stratus-red-team) Kubernetes
  technique set (see [`kubernetes-architecture.md`](./kubernetes-architecture.md) §5).

---

## Maturity legend

Maturity answers "how much do I trust this alert?" — it is **not** the same as
"does the file pass CI." CI (`tools/detection-validator/validate.py`) only checks
*structure* (required fields, MITRE tag, time filter); it never runs a rule against
data. Only a fired attack proves a detection.

| Badge | Meaning |
|-------|---------|
| ✅ **Proven** | An automated CI test asserts the detection matches the attack's event and stays silent on benign input — regression-protected on every PR. This can be *logic-level* (offline event fixture run through the real query — Tier 1) or *end-to-end* (live attack on a real cluster — Tier 3). See [Proving detections in CI](#proving-detections-in-ci-what-actually-runs). |
| 🔵 **Proof-ready** | Has both an attack script and a `test.kql`/fixture, but **no CI job runs them yet**. One harness step away from Proven. |
| 🟩 **Sound** | Stratus-derived documented audit event, or a clear syscall signal. Trigger script present; no test fixture or CI test yet. |
| 🟨 **Draft** | Real signal, but needs tuning (allowlist/baseline) before production — will be noisy as-is. |
| 🟧 **Backstop** | Weak / evadable; exists as a secondary net behind a stronger rule for the same technique. |
| ⬜ **Template** | Non-functional until a data source is enabled; schema unverified. |

> **Reality check (2026-07):** the CI now runs two things — a *structure* check
> (`validate.py`) and a **Tier 1 logic test** (`kql_test.py`) that executes the real
> `.kql` against recorded fixtures in the Kusto emulator, **and** a Tier 2 harness
> that runs the real Falco rules against live syscalls — both on every PR. Current
> state: **8 KQL rules Proven at Tier 1** (privileged-pod, hostpath-volume,
> nodes-proxy-grant, dump-secrets, create-token, create-client-certificate,
> cluster-role-binding, lateral-movement), **6 Falco rules Proven at Tier 2** (shell,
> reverse-shell, token-theft, imds, container-escape, crypto-mining), the two
> log-string backstops **logic-tested** (still Backstop — see gaps), and one Template.
> Tier 3 (live AKS end-to-end) is still a follow-up.

---

## Management plane — KQL (kube-apiserver audit)

| Tactic | Technique | Detection | Log table | Trigger script | Stratus | Maturity |
|--------|-----------|-----------|-----------|----------------|:------:|:--------:|
| Privilege Escalation | **T1610** Deploy Container | `kql/privileged-pod.kql` | `AKSAuditAdmin` | `attack-simulations/privileged-pod.sh` | ✔ | ✅ Proven (Tier 1) |
| Privilege Escalation | **T1611** Escape to Host | `kql/hostpath-volume.kql` | `AKSAuditAdmin` | `attack-simulations/hostpath-volume.sh` | ✔ | ✅ Proven (Tier 1) |
| Privilege Escalation | **T1611** Escape to Host | `kql/nodes-proxy-grant.kql` | `AKSAuditAdmin` | `attack-simulations/nodes-proxy.sh` | ✔ | ✅ Proven (Tier 1) |
| Credential Access | **T1552.007** Container API | `kql/dump-secrets.kql` | `AKSAudit` | `attack-simulations/dump-secrets.sh` | ✔ | ✅ Proven (Tier 1) |
| Credential Access | **T1552.007** Container API | *(create pods/exec)* | `AKSAuditAdmin` | `attack-simulations/pod-exec.sh` | ✔ | 🟩 Sound |
| Persistence | **T1098** Account Manipulation | `kql/create-token.kql` | `AKSAuditAdmin` | `attack-simulations/create-token.sh` | ✔ | ✅ Proven (Tier 1) |
| Persistence | **T1098** Account Manipulation | `kql/create-client-certificate.kql` | `AKSAuditAdmin` | `attack-simulations/create-client-certificate.sh` | ✔ | ✅ Proven (Tier 1) |
| Persistence | **T1098.006** Additional Cluster Roles | `T1098.006-cluster-role-binding/query.kql` | `AKSAudit` | `T1098.006-cluster-role-binding/attack.sh` + Tier 1 test | ✔ | ✅ Proven (Tier 1) |
| Lateral Movement | **T1550.001** Application Access Token | `kql/lateral-movement.kql` | `AKSAudit` | `attack-simulations/lateral-movement.sh` | ✘ | ✅ Proven (Tier 1) |
| Discovery | **T1046** Network Service Discovery | `kql/network-lateral-movement.kql` | *(ACNS/Hubble flow logs)* | — *(requires flow-log plane)* | ✘ | ⬜ Template |
| Impact | **T1496** Resource Hijacking | `kql/crypto-mining.kql` | `ContainerLogV2` | `attack-simulations/crypto-mining.sh` | ✘ | 🟧 Backstop (Tier 1 logic) |
| Privilege Escalation | **T1611** Escape to Host | `kql/container-escape.kql` | `ContainerLogV2` | `attack-simulations/container-escape.sh` | ✘ | 🟧 Backstop (Tier 1 logic) |

## Runtime plane — Falco (node syscalls)

| Tactic | Technique | Detection | Priority | Trigger script | Maturity |
|--------|-----------|-----------|----------|----------------|:--------:|
| Execution | **T1059** Command & Scripting Interpreter | `falco/shell-in-container.yaml` | WARNING | `attack-simulations/shell-in-container.sh` | ✅ Proven (Tier 2) |
| Execution | **T1059** Command & Scripting Interpreter | `falco/reverse-shell.yaml` | CRITICAL | `attack-simulations/reverse-shell.sh` | ✅ Proven (Tier 2) |
| Credential Access | **T1528** Steal Application Access Token | `falco/token-theft.yaml` | WARNING | `attack-simulations/token-theft.sh` | ✅ Proven (Tier 2) |
| Credential Access | **T1552.005** Cloud Instance Metadata API | `falco/imds-access.yaml` | CRITICAL | `attack-simulations/imds-access.sh` | ✅ Proven (Tier 2) |
| Privilege Escalation | **T1611** Escape to Host | `falco/container-escape.yaml` | CRITICAL | `attack-simulations/container-escape.sh` | ✅ Proven (Tier 2) |
| Impact | **T1496.001** Compute Hijacking | `falco/crypto-mining.yaml` | CRITICAL | `attack-simulations/crypto-mining.sh` | ✅ Proven (Tier 2) |

---

## How to run a trigger and confirm the detection fired

**Management-plane techniques** run from a pod with cluster API access:

```bash
kubectl exec -it -n attacker \
  $(kubectl get pod -n attacker -l app=kubectl -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh

# inside the pod:
bash /attack-simulations/privileged-pod.sh     # (or any management-plane script)
```

Then confirm in Log Analytics (adjust technique/table):

```kql
AKSAuditAdmin
| where TimeGenerated > ago(15m)
| where Verb == "create" and ObjectRef.resource == "pods"
| extend priv = RequestObject.spec.containers
// ...or just run the matching detection query from detections/kql/
```

**Runtime-plane techniques** run *inside a target container*, then show up as Falco
alerts (stdout of the Falco pods in `monitoring`, and in `ContainerLogV2`):

```bash
kubectl exec -it -n victim <victim-pod> -- sh /attack-simulations/reverse-shell.sh
kubectl logs -n monitoring -l app.kubernetes.io/name=falco --tail=50 | grep -i "reverse shell"
```

---

## Proving detections in CI (what actually runs)

"Maturity" above is only meaningful if something *checks* it. There are four
levels of automated proof, cheapest first. Today the repo runs levels 0–2 on
every PR; only level 3 (live cloud) is still a follow-up.

| Level | What runs | Proves | Cost | Cadence |
|-------|-----------|--------|------|---------|
| **0 — structure** | `tools/detection-validator/validate.py` | the rule is well-formed (has MITRE tag, time filter, required fields) | free | every PR |
| **1 — KQL logic (Tier 1)** | `tools/detection-tester/kql_test.py` against the **Kusto emulator** | the real `.kql` fires on a recorded malicious event and stays silent on a benign one | free | every PR — **10 KQL rules covered** |
| **2 — Falco runtime (Tier 2)** | `tools/detection-tester/falco_test.py` with **Falco (modern eBPF)** | the real Falco rule fires on live syscalls from a safe trigger container | free | every PR — **6 Falco rules covered** |
| **3 — end-to-end (Tier 3)** | deploy AKS + run `attack-simulations/*.sh` + query Log Analytics | the live attack, in a real cluster, actually trips the detection | ~$ + ~20 min | nightly / manual |

### How the Tier 1 logic test works

It needs **no cloud** and **no ingestion pipeline**. The GitHub Actions job
(`detection-logic-test` in `validate.yaml`) starts the Kusto emulator
(`kustainer-linux`) as a service container. For each test it binds the audit
table name to recorded fixture rows with a `let` datatable, injects a fresh
timestamp, then appends the **unmodified** detection query and counts rows:

```kql
let AKSAuditAdmin = datatable(Verb:string, User:dynamic, ObjectRef:dynamic, ...)
[ ...recorded event... ] | extend TimeGenerated = now();
<contents of detections/kql/privileged-pod.kql>   // runs verbatim — real logic
| count
```

Because the `let` shadows the table name, the shipped query runs against the
fixture. A malicious fixture must return > 0 rows; a benign one must return 0.

### Adding a Tier 1 test to another rule (turning 🟩 → ✅)

1. `mkdir detections/kql/tests/<rule-name>/`
2. Add `malicious.json` (events that SHOULD fire) and `benign.json` (events that
   should NOT — include the tricky suppression cases, e.g. a `system:` actor).
3. Add `test.json` declaring the rule path, the audit table, the column `schema`,
   and the `cases`. Copy `privileged-pod/test.json` as the template.
4. That's it — the CI job discovers `*/test.json` automatically. Run it locally
   first with `python tools/detection-tester/kql_test.py --dry-run` to eyeball the
   composed query.

> **Tip:** capture your `malicious.json` from a *real* attack run once (copy the
> actual `AKSAuditAdmin` row the attack produced), so the fixture reflects the
> real event shape rather than an assumption. That is what makes Tier 1 trustworthy
> as a stand-in for the full end-to-end test.

### How the Tier 2 Falco runtime test works

There is no faithful *offline* Falco engine — a syscall rule can only be proven by
generating the syscalls. So the `falco-runtime-test` job runs **real Falco** (modern
eBPF) on the runner with the repo's rules mounted into `/etc/falco/rules.d`, then
`tools/detection-tester/falco_test.py` fires one **safe** trigger container per rule
(a refused reverse shell, a `stratum+tcp` echo, a fake token read, …) and asserts the
expected `rule:` name appears in Falco's JSON output (read via `docker logs`).

Add a rule to it the same way as Tier 1: drop a `detections/falco/tests/<rule>/test.json`
with `image`, `cmd`, and `expect_rule`. **Gotcha:** Falco emits only the *first*
matching rule per event, so a built-in rule can pre-empt yours (this is why the
crypto trigger uses the `stratum+tcp` cmdline branch, not a renamed binary — the
renamed binary is claimed by the built-in "Drop and execute new binary" rule).

## Coverage gaps (read before you trust the green)

Honesty column — what this matrix does **not** yet claim:

1. **Tier 1/2 prove LOGIC + runtime, not the live cloud pipeline.** 8 KQL rules pass
   a logic test and 6 Falco rules pass a live-syscall test on every PR — real
   regression protection. But Tier 1 asserts the query is correct against a *recorded*
   event (not that the live attack still produces it, or that AKS ingests it), and
   Tier 2 proves the Falco rule fires on syscalls but without the real K8s metadata
   fields. Only a **Tier 3** live run proves the full cloud pipeline — still a follow-up.
2. **The two `ContainerLogV2` log-string rules (🟧) stay Backstop even though
   logic-tested.** `crypto-mining.kql` and `container-escape.kql` are evadable (rename
   the binary / stay quiet) and duplicate techniques Falco now catches end-to-end at
   the syscall level — trust the Falco rule; these are the safety net.
3. **`network-lateral-movement.kql` (⬜)** cannot run until ACNS/Hubble Container
   Network Logs are enabled and its placeholder table/schema are confirmed.
