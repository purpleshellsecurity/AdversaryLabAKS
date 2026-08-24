#!/usr/bin/env python3
"""
ARM parity check — proves infrastructure/main.json still matches main.bicep.

WHY THIS EXISTS
---------------
``infrastructure/main.json`` is the compiled ARM output of ``main.bicep``. It is
committed to the repo, but nothing produces or verifies it: CI never regenerates
it, and ``deploy.yaml`` deploys from ``main.bicep`` directly. So it is a DERIVED
file with no consumer and no guard — if someone edits the Bicep and forgets to
recompile, the committed JSON quietly describes infrastructure that no longer
exists, and nothing anywhere notices.

That is the same class of problem ``build-falco-rules.py`` solves for the Falco
rules. This is the equivalent gate for the ARM template.

NOTE: as of this writing the JSON was NOT drifting — it was consistent with its
source. This check exists to keep it that way, not to fix an active defect. If
you would rather not maintain a derived artifact that nothing consumes, deleting
``main.json`` and gitignoring it is a strictly simpler answer than this script.

WHY THE COMPILER VERSION IS PINNED
----------------------------------
Different Bicep versions emit different JSON for identical source. Comparing a
0.42.1-generated template against a 0.37.4 rebuild of the same unchanged source
produces differences in at least three places:

  * ``_generator`` metadata (version + templateHash) on every nested template,
  * the ``apiVersion`` chosen for nested deployment resources
    (0.37 emits 2022-09-01, 0.42 emits 2025-04-01),
  * how extension-resource ``scope`` is expressed
    (``format('Microsoft.KeyVault/vaults/{0}', ...)`` vs ``resourceId(...)``).

The first attempt at this check normalized away the first two and still reported
drift from the third — which is the lesson: the set of codegen differences is not
knowable in advance, so normalizing "the known ones" produces a check that looks
authoritative and silently is not.

So the version is PINNED in ``infrastructure/.bicep-version`` instead, and the
comparison is exact. If the local compiler does not match, this reports that it
CANNOT verify (exit 2) rather than guessing — a mismatch is never reported as
drift. The ``_generator`` block is still normalized away, since it carries the
version and content hash rather than anything about the infrastructure.

This pin governs only the generated artifact. The ``bicep-validate`` CI job still
lints with current Bicep, so new compiler warnings are not suppressed.

USAGE
-----
  python tools/check-arm-parity.py            # verify (what CI runs)
  python tools/check-arm-parity.py --write     # recompile and update main.json
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
BICEP_SOURCE = REPO_ROOT / "infrastructure" / "main.bicep"
ARM_TEMPLATE = REPO_ROOT / "infrastructure" / "main.json"

# Sections the template author controls. Everything outside these is either
# compiler bookkeeping or schema boilerplate.
COMPARED_SECTIONS = ("parameters", "variables", "resources", "outputs")

# The Bicep version main.json is generated with. Bump this and re-run --write
# together; never one without the other.
VERSION_PIN_FILE = REPO_ROOT / "infrastructure" / ".bicep-version"

# Exit code meaning "could not verify" — distinct from 1, which means real drift.
EXIT_CANNOT_VERIFY = 2


def pinned_version() -> str:
    """Read the Bicep version main.json is generated with.

    Returns:
        str: The pinned version, e.g. "0.42.1".

    Raises:
        SystemExit: If the pin file is missing — without it the comparison has no
        defined meaning, and guessing would defeat the point of the check.
    """
    if not VERSION_PIN_FILE.exists():
        sys.exit(f"ERROR: no version pin at {VERSION_PIN_FILE}")
    return VERSION_PIN_FILE.read_text(encoding="utf-8").strip()


def bicep_candidates() -> list:
    """Enumerate every Bicep compiler reachable on this machine.

    A host commonly has more than one, at different versions — a GitHub runner
    ships a standalone `bicep` on PATH AND an az-managed one under
    ~/.azure/bin/bicep that `az bicep install --version` writes to. Picking the
    first one found is what made this check fail in CI: the runner's PATH bicep
    (0.46.1) shadowed the pinned 0.42.1 that the install step had just placed.

    Returns:
        list: (kind, executable) pairs, where kind is "standalone" or "az".
    """
    found = []
    on_path = shutil.which("bicep")
    if on_path:
        found.append(("standalone", on_path))

    # The az CLI keeps its own copy here, which is what `az bicep install
    # --version vX` updates. It is deliberately NOT on PATH.
    az_managed = Path.home() / ".azure" / "bin" / "bicep"
    if az_managed.is_file() and str(az_managed) != on_path:
        found.append(("standalone", str(az_managed)))

    if shutil.which("az"):
        found.append(("az", "az"))
    return found


def bicep_version(kind: str, exe: str) -> Optional[str]:
    """Read the version of one Bicep compiler.

    Args:
        kind: "standalone" or "az".
        exe: Executable path, or "az".

    Returns:
        Optional[str]: Dotted version, or None if it could not be determined.
    """
    cmd = [exe, "--version"] if kind == "standalone" else [exe, "bicep", "version"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    match = re.search(r"(\d+\.\d+\.\d+)", result.stdout + result.stderr)
    return match.group(1) if match else None


def select_compiler(pinned: str):
    """Find a reachable compiler whose version matches the pin.

    Searching every candidate rather than taking the first means the check works
    both locally (standalone bicep on PATH) and in CI (az-managed bicep), without
    either environment needing to arrange its PATH just so.

    Args:
        pinned: The required version, e.g. "0.42.1".

    Returns:
        tuple: ((kind, exe), discovered) where the first element is the matching
        compiler or None, and `discovered` lists every (label, version) seen —
        used to explain the failure when nothing matches.
    """
    discovered = []
    match = None
    for kind, exe in bicep_candidates():
        version = bicep_version(kind, exe)
        label = "az bicep" if kind == "az" else exe
        discovered.append((label, version or "unknown"))
        if version == pinned and match is None:
            match = (kind, exe)
    return match, discovered


def compile_bicep(compiler, source: Path, out_path: Path) -> None:
    """Compile a .bicep file to ARM JSON with a specific compiler.

    Args:
        compiler: (kind, exe) pair from select_compiler().
        source: Path to the .bicep file.
        out_path: Where to write the compiled JSON.

    Raises:
        SystemExit: If compilation fails.
    """
    kind, exe = compiler
    if kind == "standalone":
        cmd = [exe, "build", str(source), "--outfile", str(out_path)]
    else:
        cmd = [exe, "bicep", "build", "--file", str(source), "--outfile", str(out_path)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"ERROR: bicep build failed:\n{result.stderr.strip()[:2000]}")


def normalize(node):
    """Strip the ``_generator`` metadata block from a template and its nested ones.

    That block carries the compiler version and a content hash — bookkeeping, not
    infrastructure. Everything else is compared exactly, which is only sound
    because the compiler version is pinned (see the module docstring).

    Args:
        node: Any node of the parsed template.

    Returns:
        The same structure with ``_generator`` blocks removed.
    """
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "metadata" and isinstance(value, dict) and "_generator" in value:
                trimmed = {k: v for k, v in value.items() if k != "_generator"}
                if not trimmed:
                    continue
                value = trimmed
            out[key] = normalize(value)
        return out

    if isinstance(node, list):
        return [normalize(item) for item in node]

    return node


def sections(template: dict) -> dict:
    """Extract and normalize the author-controlled sections of a template.

    Args:
        template: A parsed ARM template.

    Returns:
        dict: Normalized {section_name: content} for the compared sections.
    """
    return {name: normalize(template.get(name)) for name in COMPARED_SECTIONS}


def main() -> int:
    """Recompile the Bicep and compare (or rewrite) the committed ARM template.

    Returns:
        int: 0 when the committed JSON matches its source, 1 on drift, or
        EXIT_CANNOT_VERIFY (2) when the local compiler is not the pinned version.
    """
    parser = argparse.ArgumentParser(description="Verify main.json matches main.bicep")
    parser.add_argument(
        "--write",
        action="store_true",
        help="recompile and overwrite main.json instead of just checking",
    )
    args = parser.parse_args()

    if not BICEP_SOURCE.exists():
        sys.exit(f"ERROR: {BICEP_SOURCE} not found")

    # The comparison is exact, so it is only meaningful when the compiler that
    # rebuilds matches the one that produced the committed file. A mismatch is
    # reported as "cannot verify" — never as drift, which is the mistake this
    # check exists to avoid making.
    pinned = pinned_version()
    compiler, discovered = select_compiler(pinned)
    if compiler is None:
        print(f"::warning::No Bicep {pinned} found — cannot verify main.json.")
        print(f"::warning::This is NOT a drift failure.")
        if discovered:
            print("Compilers found:")
            for label, version in discovered:
                print(f"  {version:<10} {label}")
        else:
            print("No Bicep compiler found at all.")
        print(f"Install the pinned version:  az bicep install --version v{pinned}")
        return EXIT_CANNOT_VERIFY

    if args.write:
        compile_bicep(compiler, BICEP_SOURCE, ARM_TEMPLATE)
        print(f"Recompiled {ARM_TEMPLATE.relative_to(REPO_ROOT)} from {BICEP_SOURCE.name} "
              f"using Bicep {pinned}.")
        return 0

    if not ARM_TEMPLATE.exists():
        sys.exit(f"ERROR: {ARM_TEMPLATE} not found — run with --write to generate it")

    with tempfile.TemporaryDirectory() as tmp:
        rebuilt_path = Path(tmp) / "rebuilt.json"
        compile_bicep(compiler, BICEP_SOURCE, rebuilt_path)
        rebuilt = json.loads(rebuilt_path.read_text(encoding="utf-8"))

    committed = json.loads(ARM_TEMPLATE.read_text(encoding="utf-8"))

    committed_sections = sections(committed)
    rebuilt_sections = sections(rebuilt)

    drifted = [
        name for name in COMPARED_SECTIONS
        if json.dumps(committed_sections[name], sort_keys=True)
        != json.dumps(rebuilt_sections[name], sort_keys=True)
    ]

    print(f"Verified against Bicep {pinned} (pinned in {VERSION_PIN_FILE.name}).")

    if not drifted:
        print("OK — main.json matches main.bicep.")
        return 0

    print()
    for name in drifted:
        print(f"::error::main.json is stale — '{name}' does not match main.bicep")
        # Name the specific keys that differ, which is usually enough to see what
        # was changed in the Bicep without recompiling by hand.
        before, after = committed_sections[name], rebuilt_sections[name]
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) ^ set(after)):
                side = "only in committed JSON" if key in before else "only in rebuilt"
                print(f"::error::  {name}.{key} — {side}")

    print()
    print("infrastructure/main.json is a GENERATED file and is now out of date.")
    print("Regenerate it with:  python tools/check-arm-parity.py --write")
    return 1


if __name__ == "__main__":
    sys.exit(main())
