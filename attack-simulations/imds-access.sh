#!/bin/bash
# ============================================================================
# Attack Simulation: Pod Contacted Azure IMDS (Managed-Identity Pivot)
# MITRE ATT&CK: T1552.005 - Cloud Instance Metadata API
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/imds-access.yaml   (Falco, CRITICAL)
# ============================================================================
#
# TACTIC: Credential Access (TA0006). This is the cloud-native pivot from Kubernetes to
# the underlying Azure subscription: the IMDS endpoint will hand out access tokens for
# the NODE's managed identity to anything that can reach it. A container that queries
# IMDS is almost always trying to escalate out of the cluster into cloud resources.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# 169.254.169.254 is the Azure Instance Metadata Service. A container reaching it
# is trying to steal the NODE's managed identity and pivot into the subscription.
# This only reads metadata (no credential is exfiltrated) — the connection itself
# is the detected signal.
#
# WHAT A DEFENDER SHOULD SEE: a Falco CRITICAL alert for an outbound connection from a
# pod to 169.254.169.254. (Best practice is to block pod egress to IMDS entirely.)

echo "[*] Connecting to Azure IMDS (169.254.169.254)..."
# Query the IMDS instance-metadata endpoint. Notes on the flags:
#   -s              -> silent (no progress meter)
#   --max-time 5    -> give up after 5s so the script can't hang
#   -H "Metadata:true" -> the required header IMDS demands (anti-SSRF guard)
#   the /metadata/instance path here reads only benign VM metadata (not a token)
#   >/dev/null 2>&1 -> discard the body; we only care that the request went out
# Whether IMDS replies or not, the OUTBOUND CONNECTION to 169.254.169.254 is the
# telemetry the detection fires on.
curl -s --max-time 5 -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1 \
  && echo "[*] IMDS responded." \
  || echo "[*] IMDS request sent (response ignored) — the outbound connection is the signal."

echo ""
# Operator-facing hints on the runtime detection and the exact field it matches.
echo "[*] Expected detection: Falco 'Pod Contacted Cloud Instance Metadata Service' (T1552.005, CRITICAL)"
echo "[*] Matched on: outbound and fd.sip = 169.254.169.254"
