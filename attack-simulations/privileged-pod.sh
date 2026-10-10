#!/bin/bash
# ============================================================================
# Attack Simulation: Privileged Pod Creation
# MITRE ATT&CK: T1610 - Deploy Container
# Stratus technique: k8s.privilege-escalation.privileged-pod
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/privileged-pod.kql   (table: AKSAuditAdmin)
# ============================================================================
#
# TACTIC: Privilege Escalation (TA0004) / Deploy Container (T1610). A pod with
# `securityContext.privileged: true` runs with essentially all Linux capabilities and
# access to host devices — the easiest path to escaping onto the node. Attackers who
# can create pods deploy a privileged one as a launchpad for host takeover.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAuditAdmin `create pods` whose spec sets
# securityContext.privileged=true. Admission policy (Pod Security / Gatekeeper) should
# ideally block this outright.

# Abort on first error.
set -e
# Unique per-run pod name for easy identification and cleanup.
POD="adversary-lab-priv-$(date +%s)"

echo "[*] Creating privileged pod: $POD (namespace: victim)"
# Apply an inline Pod manifest into the "victim" namespace.
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: victim
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1610" }
spec:
  containers:
    - name: priv
      image: busybox:1.36                 # tiny, ubiquitous image; just needs to run
      command: ["sleep", "3600"]          # idle for an hour so the pod stays Running
      securityContext:
        privileged: true          # <-- the signal the detection matches
EOF

echo ""
# Operator-facing hints plus manual cleanup (script does not self-delete the pod).
echo "[*] Expected detection: T1610 - Privileged Pod Creation"
echo "[*] Expected log table: AKSAuditAdmin"
echo "[!] Cleanup: kubectl delete pod $POD -n victim"
