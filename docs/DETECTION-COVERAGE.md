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
| ✅ **Proven** | Has an attack script **and** an automated `test.kql` that CI asserts fires (true-positive proven on every change). |
| 🟩 **Sound** | Stratus-derived documented audit event, or a clear syscall signal. Trigger script present; not yet wired into an automated CI true-positive test. |
| 🟨 **Draft** | Real signal, but needs tuning (allowlist/baseline) before production — will be noisy as-is. |
| 🟧 **Backstop** | Weak / evadable; exists as a secondary net behind a stronger rule for the same technique. |
| ⬜ **Template** | Non-functional until a data source is enabled; schema unverified. |

---

## Management plane — KQL (kube-apiserver audit)

| Tactic | Technique | Detection | Log table | Trigger script | Stratus | Maturity |
|--------|-----------|-----------|-----------|----------------|:------:|:--------:|
| Privilege Escalation | **T1610** Deploy Container | `kql/privileged-pod.kql` | `AKSAuditAdmin` | `attack-simulations/privileged-pod.sh` | ✔ | 🟩 Sound |
| Privilege Escalation | **T1611** Escape to Host | `kql/hostpath-volume.kql` | `AKSAuditAdmin` | `attack-simulations/hostpath-volume.sh` | ✔ | 🟩 Sound |
| Privilege Escalation | **T1611** Escape to Host | `kql/nodes-proxy-grant.kql` | `AKSAuditAdmin` | `attack-simulations/nodes-proxy.sh` | ✔ | 🟩 Sound |
| Credential Access | **T1552.007** Container API | `kql/dump-secrets.kql` | `AKSAudit` | `attack-simulations/dump-secrets.sh` | ✔ | 🟩 Sound |
| Credential Access | **T1552.007** Container API | *(create pods/exec)* | `AKSAuditAdmin` | `attack-simulations/pod-exec.sh` | ✔ | 🟩 Sound |
| Persistence | **T1098** Account Manipulation | `kql/create-token.kql` | `AKSAuditAdmin` | `attack-simulations/create-token.sh` | ✔ | 🟩 Sound |
| Persistence | **T1098** Account Manipulation | `kql/create-client-certificate.kql` | `AKSAuditAdmin` | `attack-simulations/create-client-certificate.sh` | ✔ | 🟩 Sound |
| Persistence | **T1098.006** Additional Cluster Roles | `T1098.006-cluster-role-binding/query.kql` | `AKSAudit` | `T1098.006-cluster-role-binding/attack.sh` + `test.kql` | ✔ | ✅ Proven |
| Lateral Movement | **T1550.001** Application Access Token | `kql/lateral-movement.kql` | `AKSAudit` | `attack-simulations/lateral-movement.sh` | ✘ | 🟨 Draft |
| Discovery | **T1046** Network Service Discovery | `kql/network-lateral-movement.kql` | *(ACNS/Hubble flow logs)* | — *(requires flow-log plane)* | ✘ | ⬜ Template |
| Impact | **T1496** Resource Hijacking | `kql/crypto-mining.kql` | `ContainerLogV2` | `attack-simulations/crypto-mining.sh` | ✘ | 🟧 Backstop |
| Privilege Escalation | **T1611** Escape to Host | `kql/container-escape.kql` | `ContainerLogV2` | `attack-simulations/container-escape.sh` | ✘ | 🟧 Backstop |

## Runtime plane — Falco (node syscalls)

| Tactic | Technique | Detection | Priority | Trigger script | Maturity |
|--------|-----------|-----------|----------|----------------|:--------:|
| Execution | **T1059** Command & Scripting Interpreter | `falco/shell-in-container.yaml` | WARNING | `attack-simulations/shell-in-container.sh` | 🟩 Sound |
| Execution | **T1059** Command & Scripting Interpreter | `falco/reverse-shell.yaml` | CRITICAL | `attack-simulations/reverse-shell.sh` | 🟩 Sound |
| Credential Access | **T1528** Steal Application Access Token | `falco/token-theft.yaml` | WARNING | `attack-simulations/token-theft.sh` | 🟩 Sound |
| Credential Access | **T1552.005** Cloud Instance Metadata API | `falco/imds-access.yaml` | CRITICAL | `attack-simulations/imds-access.sh` | 🟩 Sound |
| Privilege Escalation | **T1611** Escape to Host | `falco/container-escape.yaml` | CRITICAL | `attack-simulations/container-escape.sh` | 🟩 Sound |
| Impact | **T1496.001** Compute Hijacking | `falco/crypto-mining.yaml` | CRITICAL | `attack-simulations/crypto-mining.sh` | 🟩 Sound |

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

## Coverage gaps (read before you trust the green)

Honesty column — what this matrix does **not** yet claim:

1. **Only `T1098.006` is CI-proven.** Every other row has a trigger script now, but
   nothing asserts automatically that the attack still fires the detection. The next
   step to raise a 🟩 to ✅ is to add a `test.kql` + CI assertion the way the
   T1098.006 package does.
2. **`lateral-movement.kql` (🟨) has no allowlist.** It fires on any cross-namespace
   service-account use, including legitimate `kube-system` controllers — expect heavy
   false positives until baselined. See [`DETECTION-TUNING.md`](./DETECTION-TUNING.md).
3. **The two `ContainerLogV2` log-string rules (🟧)** — `crypto-mining.kql` and
   `container-escape.kql` — are evadable (rename the binary / stay quiet) and
   duplicate techniques Falco catches at the syscall level. `container-escape.kql`
   in particular may not fire from `container-escape.sh` at all. Trust the Falco rule.
4. **`network-lateral-movement.kql` (⬜)** cannot run until ACNS/Hubble Container
   Network Logs are enabled and its placeholder table/schema are confirmed.
