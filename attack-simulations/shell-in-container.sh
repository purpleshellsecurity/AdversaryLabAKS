#!/bin/bash
# ============================================================================
# Attack Simulation: Shell Spawned in Container
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/shell-in-container.yaml   (Falco, WARNING)
# ============================================================================
#
# TACTIC: Execution (TA0002). Application containers normally run one long-lived
# process and never spawn an interactive shell. When a shell binary suddenly appears —
# especially as a child of the web/app process — it usually means someone achieved code
# execution (e.g. via a webshell) and is now typing commands.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# Spawns a shell binary inside the container. In a real intrusion the PARENT of
# this shell would be the app process (a webshell); here the parent is this script.
#
# WHAT A DEFENDER SHOULD SEE: a Falco WARNING for a shell process (bash/sh/etc.)
# starting in a container. The parent process name is the key triage field — an app
# server as the parent strongly suggests a webshell.

echo "[*] Spawning a shell inside the container..."
# Launch bash to run a trivial command. The command output is cosmetic; the DETECTION
# is simply that a shell binary (proc.name in the shell_binaries set) executed. It also
# echoes the current user and parent PID to illustrate the parent-process triage angle.
bash -c 'echo "shell spawned by $(whoami), parent=$PPID"'   # <-- proc.name in (shell_binaries)

echo ""
# Operator-facing hints, including which alert field distinguishes benign vs. webshell.
echo "[*] Expected detection: Falco 'Shell Spawned in Container' (T1059, WARNING)"
echo "[*] Look for parent=%proc.pname in the alert — app-as-parent = likely webshell."
