#!/bin/bash
# ============================================================================
# Attack Simulation: Pod Contacted Azure IMDS (Managed-Identity Pivot)
# MITRE ATT&CK: T1552.005 - Cloud Instance Metadata API
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/imds-access.yaml   (Falco, CRITICAL)
# ============================================================================
#
# 169.254.169.254 is the Azure Instance Metadata Service. A container reaching it
# is trying to steal the NODE's managed identity and pivot into the subscription.
# This only reads metadata (no credential is exfiltrated) — the connection itself
# is the detected signal.

echo "[*] Connecting to Azure IMDS (169.254.169.254)..."
curl -s --max-time 5 -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1 \
  && echo "[*] IMDS responded." \
  || echo "[*] IMDS request sent (response ignored) — the outbound connection is the signal."

echo ""
echo "[*] Expected detection: Falco 'Pod Contacted Cloud Instance Metadata Service' (T1552.005, CRITICAL)"
echo "[*] Matched on: outbound and fd.sip = 169.254.169.254"
