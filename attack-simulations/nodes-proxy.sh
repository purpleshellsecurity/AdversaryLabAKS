#!/bin/bash
# ============================================================================
# Attack Simulation: ClusterRole Granting nodes/proxy (Kubelet API Access)
# MITRE ATT&CK: T1611 - Escape to Host
# Stratus technique: k8s.privilege-escalation.nodes-proxy
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/nodes-proxy-grant.kql   (table: AKSAuditAdmin)
# ============================================================================
#
# TACTIC: Privilege Escalation (TA0004) / Escape to Host (T1611). The `nodes/proxy`
# permission lets a principal talk directly to the kubelet API on every node, which
# can be abused to run commands in any pod on that node and effectively break out of
# the cluster's RBAC boundary toward the host.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# The nodes/proxy API call itself goes straight to the kubelet and is INVISIBLE
# to the apiserver audit log. So the detectable, durable signal is the RBAC GRANT
# that enables it — which is what this script creates.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAuditAdmin record of a `create clusterroles`
# whose rules include the resource `nodes/proxy`. That grant is rare in normal ops.

# `set -e` aborts the script on the first command that fails, so a partial/broken
# apply doesn't silently continue.
set -e
# Build a unique ClusterRole name using the epoch seconds, so repeated runs don't
# collide and each is easy to find and clean up.
ROLE="adversary-lab-nodesproxy-$(date +%s)"

echo "[*] Creating ClusterRole granting nodes/proxy: $ROLE"
# Pipe an inline (heredoc) manifest into `kubectl apply` to create the ClusterRole.
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $ROLE
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1611" }
rules:
  # The core namespace (apiGroup "") plus the nodes/proxy subresource is exactly
  # the kubelet-reaching grant an attacker wants; get+create verbs allow proxied
  # reads and command execution through the kubelet.
  - apiGroups: [""]
    resources: ["nodes/proxy"]     # <-- the rule the detection matches
    verbs: ["get", "create"]
EOF

echo ""
# Operator-facing hints plus a manual cleanup command (this script does NOT self-clean).
echo "[*] Expected detection: T1611 - ClusterRole Granting nodes/proxy"
echo "[*] Expected log table: AKSAuditAdmin  (Verb=create, resource=clusterroles)"
echo "[!] Cleanup: kubectl delete clusterrole $ROLE"
