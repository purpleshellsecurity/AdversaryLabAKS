#!/usr/bin/env python3
"""
Falco runtime detection tester (Tier 2 — live syscalls, no cloud).

Proves the Falco rules END TO END: a real trigger runs inside a container, Falco
(watching host syscalls via modern eBPF) observes it, and we assert the expected
rule name appears in Falco's JSON output.

Unlike the KQL Tier 1 harness (which runs queries against recorded fixtures), there
is no faithful offline Falco engine — a syscall rule can only be proven by
generating the syscalls. So this needs a running Falco and a Docker daemon; the CI
job `falco-runtime-test` in validate.yaml wires that up.

Each manifest (detections/falco/tests/<rule>/test.json) declares:
  - image       : container image to run the trigger in
  - cmd         : shell command that produces the syscall pattern
  - expect_rule : the exact `rule:` name that must fire in detections/falco/<rule>.yaml

The triggers are SAFE by design (no real backdoor, no real mining) — see each cmd.

Usage:
  python falco_test.py --tests-dir detections/falco/tests --events-file /tmp/falco/events.jsonl
  python falco_test.py --tests-dir detections/falco/tests --dry-run   # list triggers, run nothing
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def docker_run(image: str, cmd: str, timeout: int = 90) -> None:
    """Run a trigger in a throwaway container. Triggers often 'fail' by design
    (a refused reverse shell, a denied nsenter) — that's fine, the syscall is what
    Falco sees, so we ignore the exit code."""
    try:
        subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "sh", image, "-c", cmd],
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pass  # the reverse-shell trigger self-times-out; not an error


def _iter_event_lines(container: str, events_file: str):
    """Yield candidate JSON lines from `docker logs <container>` (preferred — no
    file-permission issues) or from a Falco file_output file as a fallback."""
    if container:
        out = subprocess.run(
            ["docker", "logs", container],
            capture_output=True, text=True, check=False,
        )
        yield from (out.stdout + "\n" + out.stderr).splitlines()
    elif events_file and Path(events_file).exists():
        yield from Path(events_file).read_text(errors="replace").splitlines()


def load_fired_rules(container: str, events_file: str) -> set:
    fired = set()
    for line in _iter_event_lines(container, events_file):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(evt, dict) and evt.get("rule"):
            fired.add(evt["rule"])
    return fired


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 2 Falco runtime tester")
    ap.add_argument("--tests-dir", default="detections/falco/tests")
    ap.add_argument("--container", default="falco",
                    help="Falco container name to read JSON events from via `docker logs`")
    ap.add_argument("--events-file", default="",
                    help="fallback: read Falco file_output instead of docker logs")
    ap.add_argument("--settle-seconds", type=int, default=8,
                    help="pause after triggers so Falco flushes events")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    manifests = sorted(Path(args.tests_dir).glob("*/test.json"))
    if not manifests:
        print(f"ERROR: no Falco test manifests under {args.tests_dir}", file=sys.stderr)
        return 1
    cases = [(m.parent.name, json.loads(m.read_text())) for m in manifests]

    if args.dry_run:
        for name, c in cases:
            print(f"{name}: expect '{c['expect_rule']}'  <-  [{c['image']}] {c['cmd']}")
        return 0

    print(f"[*] firing {len(cases)} runtime triggers…")
    for name, c in cases:
        print(f"    - {name} ({c['image']})")
        docker_run(c["image"], c["cmd"])

    print(f"[*] waiting {args.settle_seconds}s for Falco to flush events…")
    time.sleep(args.settle_seconds)

    fired = load_fired_rules(args.container, args.events_file)
    passed = failed = 0
    for name, c in cases:
        ok = c["expect_rule"] in fired
        print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {c['expect_rule']}")
        passed += int(ok)
        failed += int(not ok)

    print(f"\nResults: {passed} passed, {failed} failed")
    if failed:
        print("\n--- Falco rules that DID fire (for debugging) ---")
        for r in sorted(x for x in fired if x):
            print(f"    {r}")
        if not fired:
            print("    (none — Falco may not have started or the driver failed to load)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
