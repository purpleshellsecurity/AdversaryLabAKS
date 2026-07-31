#!/bin/bash
# ============================================================================
# Attack Simulation: Cluster-Wide Secret Dump
# MITRE ATT&CK: T1552.007 - Unsecured Credentials: Container API
# Stratus technique: k8s.credential-access.dump-secrets
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh
# Fires detection: detections/kql/dump-secrets.kql   (table: AKSAudit — reads!)
# ============================================================================
#
# TACTIC: Credential Access (TA0006). Kubernetes Secrets hold DB passwords, API keys,
# TLS private keys, and cloud credentials. An attacker who can LIST secrets across all
# namespaces harvests the keys to the whole environment in a single request.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# WHAT A DEFENDER SHOULD SEE: an AKSAudit entry for a `list` on secrets at the
# CLUSTER scope (URI /api/v1/secrets, no namespace). Note reads are only recorded in
# the full AKSAudit table, not the admin-only AKSAuditAdmin table.

echo "[*] Listing secrets across ALL namespaces (cluster-wide LIST /api/v1/secrets)..."
# `--all-namespaces` makes this a cluster-scoped LIST against /api/v1/secrets rather
# than a single namespace. That cluster-wide URI — not the number of secrets returned —
# is what the detection keys on.
kubectl get secrets --all-namespaces        # <-- the cluster-scoped URI is the tell

echo ""
# Operator-facing hints, including why a namespaced read would NOT trip this rule.
echo "[*] Expected detection: T1552.007 - Cluster-Wide Secret Dump"
echo "[*] Expected log table: AKSAudit  (reads live only in the full audit table)"
echo "[*] Note: a namespaced read (kubectl get secrets -n victim) does NOT fire this —"
echo "    the detection keys on the cluster-wide URI, not the count of secrets read."
