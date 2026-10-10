#!/bin/bash
# ============================================================================
# Attack Simulation: Container Escape via nsenter
# MITRE ATT&CK: T1611 - Escape to Host
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/container-escape.yaml   (Falco, CRITICAL)
# ============================================================================
#
# TACTIC: Privilege Escalation (TA0004) / Escape to Host (T1611). A container is just
# a set of Linux namespaces around a process. `nsenter` re-enters another process's
# namespaces; entering PID 1's namespaces means leaving the container and running
# with the HOST's view of the world — the definition of a container escape.
#
# THIS IS AN INTENTIONAL ATTACK SIMULATION for detection testing.
#
# Runs nsenter to enter the host namespaces. Without privileged/CAP_SYS_ADMIN the
# escape FAILS — but the execve of `nsenter` still fires the Falco rule, which is
# the point: Falco sees the *attempt*.
#
# WHAT A DEFENDER SHOULD SEE: a Falco CRITICAL alert for an `nsenter` execution inside
# a container — regardless of whether the escape actually succeeded.
#
# COVERAGE NOTE (see docs/DETECTION-COVERAGE.md): the KQL sibling
# detections/kql/container-escape.kql greps ContainerLogV2 for the string
# "nsenter" and may NOT fire here, because a failed nsenter rarely prints its own
# name to container stdout. Trust the Falco rule; the KQL is a weak backstop.

echo "[*] Attempting host-namespace entry via nsenter (expected to fail without privileges)..."
# `nsenter --target 1` targets PID 1 (the host init). The flags enter all of that
# process's namespaces — mount/uts/ipc/net/pid — and then run `/bin/true` (a no-op)
# inside them. If successful, that command runs on the HOST. `2>/dev/null || ...`
# suppresses the permission error and prints a friendly note on failure. Either way,
# the execve of `nsenter` is what Falco detects.
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/true 2>/dev/null || \
  echo "[*] nsenter denied (as expected) — the execve still fired Falco."

echo ""
# Operator-facing hint on the expected runtime alert.
echo "[*] Expected detection: Falco 'Container Escape via nsenter' (T1611, CRITICAL)"
