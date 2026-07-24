#!/bin/bash
# ============================================================================
# Attack Simulation: Shell Spawned in Container
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/shell-in-container.yaml   (Falco, WARNING)
# ============================================================================
#
# Spawns a shell binary inside the container. In a real intrusion the PARENT of
# this shell would be the app process (a webshell); here the parent is this script.

echo "[*] Spawning a shell inside the container..."
bash -c 'echo "shell spawned by $(whoami), parent=$PPID"'   # <-- proc.name in (shell_binaries)

echo ""
echo "[*] Expected detection: Falco 'Shell Spawned in Container' (T1059, WARNING)"
echo "[*] Look for parent=%proc.pname in the alert — app-as-parent = likely webshell."
