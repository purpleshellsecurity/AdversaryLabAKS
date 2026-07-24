#!/bin/bash
# ============================================================================
# Attack Simulation: Cryptocurrency Mining
# MITRE ATT&CK: T1496.001 - Compute Hijacking
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/crypto-mining.yaml   (Falco, CRITICAL)
#                  detections/kql/crypto-mining.kql       (log-string backstop)
# ============================================================================
#
# SAFE BY DESIGN: no actual mining happens. We copy a harmless binary (sleep) to
# the name `xmrig` and run it briefly — that makes proc.name match the Falco rule.
# We also emit a pool string so the ContainerLogV2 log-string KQL has something to
# catch. Zero CPU abuse, zero network mining.

WORK="/tmp/adversary-lab-miner"
mkdir -p "$WORK"

echo "[*] Simulating a miner process named 'xmrig' (harmless sleep, no mining)..."
cp "$(command -v sleep)" "$WORK/xmrig" 2>/dev/null && "$WORK/xmrig" 5 &   # <-- proc.name=xmrig

echo "[*] Emitting a mining-pool string for the log-string detection..."
echo "connecting to stratum+tcp://pool.minexmr.com:4444 (SIMULATED)"       # <-- log-string tell

wait
rm -rf "$WORK"

echo ""
echo "[*] Expected detection: Falco 'Crypto Mining Process Detected' (T1496.001, CRITICAL)"
echo "[*] Also: KQL crypto-mining.kql via ContainerLogV2 (weaker, evadable backstop)."
