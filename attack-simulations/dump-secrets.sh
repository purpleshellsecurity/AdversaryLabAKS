#!/bin/bash
# ============================================================================
# Attack Simulation: Cluster-Wide Secret Dump
# MITRE ATT&CK: T1552.007 - Unsecured Credentials: Container API
# Stratus technique: k8s.credential-access.dump-secrets
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/dump-secrets.kql   (table: AKSAudit — reads!)
# ============================================================================

echo "[*] Listing secrets across ALL namespaces (cluster-wide LIST /api/v1/secrets)..."
kubectl get secrets --all-namespaces        # <-- the cluster-scoped URI is the tell

echo ""
echo "[*] Expected detection: T1552.007 - Cluster-Wide Secret Dump"
echo "[*] Expected log table: AKSAudit  (reads live only in the full audit table)"
echo "[*] Note: a namespaced read (kubectl get secrets -n victim) does NOT fire this —"
echo "    the detection keys on the cluster-wide URI, not the count of secrets read."
