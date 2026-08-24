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


def local_bicep_version() -> Optional[str]:
    """Detect the version of the Bicep compiler on PATH.

    Returns:
        Optional[str]: Dotted version (e.g. "0.42.1"), or None if no compiler was
        found or its version could not be parsed.
    """
    for cmd in (["bicep", "--version"], ["az", "bicep", "version"]):
        if not shutil.which(cmd[0]):
            continue
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    return None


def compile_bicep(source: Path, out_path: Path) -> None:
    """Compile a .bicep file to ARM JSON, preferring `bicep` then `az bicep`.

    Args:
        source: Path to the .bicep file.
        out_path: Where to write the compiled JSON.

    Raises:
        SystemExit: If no Bicep compiler is available, or compilation fails.
    """
    if shutil.which("bicep"):
        cmd = ["bicep", "build", str(source), "--outfile", str(out_path)]
    elif shutil.which("az"):
        # `az bicep build` has no --outfile, so compile in place and move.
        cmd = ["az", "bicep", "build", "--file", str(source), "--outfile", str(out_path)]
    else:
        sys.exit("ERROR: neither `bicep` nor `az` is on PATH — cannot verify parity")

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
    local = local_bicep_version()
    if local is None:
        print(f"::warning::no Bicep compiler on PATH — cannot verify main.json (need {pinned})")
        return EXIT_CANNOT_VERIFY
    if local != pinned:
        print(f"::warning::Bicep {local} is installed but main.json is generated with {pinned}.")
        print(f"::warning::Cannot verify parity — this is NOT a drift failure.")
        print(f"Install the pinned version:  az bicep install --version v{pinned}")
        return EXIT_CANNOT_VERIFY

    if args.write:
        compile_bicep(BICEP_SOURCE, ARM_TEMPLATE)
        print(f"Recompiled {ARM_TEMPLATE.relative_to(REPO_ROOT)} from {BICEP_SOURCE.name} "
              f"using Bicep {pinned}.")
        return 0

    if not ARM_TEMPLATE.exists():
        sys.exit(f"ERROR: {ARM_TEMPLATE} not found — run with --write to generate it")

    with tempfile.TemporaryDirectory() as tmp:
        rebuilt_path = Path(tmp) / "rebuilt.json"
        compile_bicep(BICEP_SOURCE, rebuilt_path)
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
