#!/bin/bash
# ============================================================================
# Attack Simulation: ClusterRole Granting nodes/proxy (Kubelet API Access)
# MITRE ATT&CK: T1611 - Escape to Host
# Stratus technique: k8s.privilege-escalation.nodes-proxy
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/nodes-proxy-grant.kql   (table: AKSAuditAdmin)
# ============================================================================
#
# The nodes/proxy API call itself goes straight to the kubelet and is INVISIBLE
# to the apiserver audit log. So the detectable, durable signal is the RBAC GRANT
# that enables it — which is what this script creates.

set -e
ROLE="adversary-lab-nodesproxy-$(date +%s)"

echo "[*] Creating ClusterRole granting nodes/proxy: $ROLE"
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $ROLE
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1611" }
rules:
  - apiGroups: [""]
    resources: ["nodes/proxy"]     # <-- the rule the detection matches
    verbs: ["get", "create"]
EOF

echo ""
echo "[*] Expected detection: T1611 - ClusterRole Granting nodes/proxy"
echo "[*] Expected log table: AKSAuditAdmin  (Verb=create, resource=clusterroles)"
echo "[!] Cleanup: kubectl delete clusterrole $ROLE"
