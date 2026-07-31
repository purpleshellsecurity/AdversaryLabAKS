#!/bin/bash
# ============================================================================
# Attack Simulation: Cryptocurrency Mining
# MITRE ATT&CK: T1496.001 - Compute Hijacking
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/crypto-mining.yaml   (Falco, CRITICAL)
#                  detections/kql/crypto-mining.kql       (log-string backstop)
# ============================================================================
#
# TACTIC: Impact (TA0040). Crypto-jacking is one of the most common goals of an
# opportunistic container compromise: the attacker uses YOUR stolen CPU/GPU (and your
# cloud bill) to mine cryptocurrency into their wallet. `xmrig` is the best-known
# Monero miner and its process name is a strong indicator of compromise.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# SAFE BY DESIGN: no actual mining happens. We copy a harmless binary (sleep) to
# the name `xmrig` and run it briefly — that makes proc.name match the Falco rule.
# We also emit a pool string so the ContainerLogV2 log-string KQL has something to
# catch. Zero CPU abuse, zero network mining.
#
# WHAT A DEFENDER SHOULD SEE: a Falco CRITICAL alert on a process named `xmrig`, plus
# (optionally) a KQL log-search hit on a mining-pool URL in container stdout.

# Scratch directory to hold the renamed binary. Kept out of the app's real paths.
WORK="/tmp/adversary-lab-miner"
mkdir -p "$WORK"

echo "[*] Simulating a miner process named 'xmrig' (harmless sleep, no mining)..."
# Copy the innocuous `sleep` binary to the filename `xmrig`, then launch it in the
# background (`&`) for 5 seconds. Falco keys on the PROCESS NAME (proc.name=xmrig),
# not the binary contents — so a renamed `sleep` is enough to fire the rule safely.
cp "$(command -v sleep)" "$WORK/xmrig" 2>/dev/null && "$WORK/xmrig" 5 &   # <-- proc.name=xmrig

echo "[*] Emitting a mining-pool string for the log-string detection..."
# Print a fake Stratum mining-pool connection string to stdout. Real miners phone home
# to a pool over the stratum protocol; this line gives the log-search (KQL) detection a
# recognizable substring to match in ContainerLogV2. Note the "(SIMULATED)" marker.
echo "connecting to stratum+tcp://pool.minexmr.com:4444 (SIMULATED)"       # <-- log-string tell

# Block until the backgrounded fake miner finishes, then delete the scratch dir so we
# leave no artifacts behind.
wait
rm -rf "$WORK"

echo ""
# Operator-facing hints on which detections should light up.
echo "[*] Expected detection: Falco 'Crypto Mining Process Detected' (T1496.001, CRITICAL)"
echo "[*] Also: KQL crypto-mining.kql via ContainerLogV2 (weaker, evadable backstop)."
