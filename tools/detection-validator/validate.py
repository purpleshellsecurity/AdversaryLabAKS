#!/usr/bin/env python3
"""
Detection Rule Validator
========================
AKS Adversary Lab - validates KQL and Falco detection rules
for required fields, MITRE ATT&CK mappings, and structural integrity.

WHY THIS EXISTS
---------------
A detection library is only trustworthy if every rule is *complete*: it maps to
a MITRE ATT&CK technique, references the fields an analyst needs, and (for Falco)
is structurally well-formed. This validator is a cheap, fast, offline gate that
runs in CI and catches the boring-but-costly mistakes — a rule with no technique
ID, a Falco rule missing its ``condition``, an invalid ``priority`` — before they
ever ship. It does NOT test whether the detection logic actually *fires* on an
attack (that's the job of kql_test.py); it checks the rule's *shape*.

TWO RULE FLAVORS
----------------
  * KQL  (.kql) — Azure/Sentinel hunting queries. Validated as raw text because
    KQL has no lightweight Python parser; we grep for required substrings and a
    MITRE technique pattern.
  * Falco (.yaml) — runtime container detection rules. Validated as parsed YAML
    so we can check individual fields on each rule mapping.

ERRORS vs WARNINGS
------------------
Errors fail the file (and, via the exit code, the CI job). Warnings are advisory
nudges toward better rules and never fail the build. The distinction is
deliberate: a missing ``condition`` is broken (error); a short description is
merely sloppy (warning).

EXIT CODE
---------
main() returns 0 only if every file passed (zero errors across all files),
otherwise 1 — so CI blocks a merge that would ship a structurally broken rule.
"""

import os
import sys
import re
import yaml
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

# Matches a MITRE ATT&CK technique ID: a "T" followed by exactly 4 digits, with
# an optional ".NNN" sub-technique suffix. E.g. T1611 (Escape to Host) or
# T1078.004 (Valid Accounts: Cloud Accounts). Compiled once and reused.
MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

# Substrings that must literally appear somewhere in a KQL rule's text. We check
# text (not a parsed AST) because there's no lightweight KQL parser here; the
# presence of these tokens is a good-enough proxy that the rule is well-formed.
REQUIRED_KQL_FIELDS = [
    "TimeGenerated",   # every rule should scope on time (see the time-filter check below)
    "MitreTechnique",  # the ATT&CK mapping, surfaced as a projected column
]

# Keys every Falco rule mapping must define. Missing any of these is an ERROR —
# a Falco rule without a condition/output/priority is non-functional.
REQUIRED_FALCO_FIELDS = [
    "rule",       # the rule's unique name
    "desc",       # human description of what it detects
    "condition",  # the boolean expression that triggers the rule
    "output",     # the alert message template (uses %field interpolation)
    "priority",   # severity — must be one of VALID_FALCO_PRIORITIES below
    "tags",       # classification labels, expected to include a MITRE technique
]

# Falco's fixed set of syslog-style severity levels. Anything outside this set is
# rejected as an error. Stored as a set for O(1) membership tests.
VALID_FALCO_PRIORITIES = {
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
    "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"
}

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """The outcome of validating a single detection file.

    Bundling the result in a dataclass (instead of returning loose tuples) keeps
    the runner's bookkeeping readable and gives us a nice ``__str__`` for the
    report. ``passed`` is derived from "zero errors"; warnings never flip it.

    Attributes:
        file: Path to the validated file (as a string, for display).
        rule_type: "KQL" or "Falco".
        passed: True when there were no errors.
        errors: Blocking problems that fail the file.
        warnings: Advisory problems that do not fail the file.
    """
    file: str
    rule_type: str
    passed: bool
    errors: list
    warnings: list

    def __str__(self):
        # Render a compact per-file block: a PASS/FAIL header followed by any
        # errors and warnings, one per indented line.
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] {self.file}"]
        for e in self.errors:
            lines.append(f"       ERROR: {e}")
        for w in self.warnings:
            lines.append(f"       WARN:  {w}")
        return "\n".join(lines)


# ── KQL Validators ───────────────────────────────────────────────────────────

def validate_kql_file(path: Path) -> ValidationResult:
    """Validate a KQL detection rule file (text-based checks).

    KQL has no lightweight parser available here, so validation is deliberately
    substring/regex based: we confirm the file is non-empty, carries a MITRE
    technique ID, references its required fields, opens with a comment header,
    and scopes on time. Only a truly empty file or a missing MITRE ID is treated
    as an ERROR; the rest are advisory WARNINGS.

    Args:
        path: Path to the .kql file.

    Returns:
        ValidationResult: passed=False if the file is unreadable/empty or has no
        MITRE technique ID; otherwise passed=True (possibly with warnings).
    """
    errors = []
    warnings = []

    # Read the whole file as text. An OS-level read failure is an immediate,
    # terminal error — we can't validate what we can't read.
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        return ValidationResult(
            file=str(path), rule_type="KQL",
            passed=False, errors=[f"Cannot read file: {e}"], warnings=[]
        )

    # An empty (or whitespace-only) file can't be a valid rule — fail fast and
    # skip the remaining checks, which would all be noise.
    if not content.strip():
        errors.append("File is empty")
        return ValidationResult(
            file=str(path), rule_type="KQL",
            passed=False, errors=errors, warnings=warnings
        )

    # Every rule must map to at least one ATT&CK technique. ``findall`` returns
    # all matches; an empty list means the mapping is missing entirely (error).
    mitre_matches = MITRE_PATTERN.findall(content)
    if not mitre_matches:
        errors.append("No MITRE ATT&CK technique ID found (e.g. T1611)")
    else:
        log.debug("Found MITRE techniques: %s", mitre_matches)

    # Confirm each required token appears somewhere in the query text. Note the
    # asymmetry: a missing MitreTechnique *column* is only a warning (the ID may
    # still be present in a comment, caught above), whereas a missing
    # TimeGenerated reference is an error because unscoped queries are dangerous.
    for field in REQUIRED_KQL_FIELDS:
        if field not in content:
            if field == "MitreTechnique":
                warnings.append(f"Missing field: {field} — add 'extend MitreTechnique = \"TXXXX\"'")
            else:
                errors.append(f"Missing required field reference: {field}")

    # Convention: rules should open with a ``//`` comment header documenting
    # description, MITRE mapping, and data source. Advisory only.
    if not content.startswith("//"):
        warnings.append("Missing header comment block — add description, MITRE, and source")

    # If the rule references TimeGenerated but never calls ago(), it's probably
    # scanning all of history — usually a mistake in a hunting query. Warn so the
    # author adds a bounded time window.
    if "ago(" not in content and "TimeGenerated" in content:
        warnings.append("No time filter found — consider adding 'where TimeGenerated > ago(1h)'")

    # A file passes iff it accumulated no errors (warnings don't count).
    passed = len(errors) == 0
    return ValidationResult(
        file=str(path), rule_type="KQL",
        passed=passed, errors=errors, warnings=warnings
    )


# ── Falco Validators ─────────────────────────────────────────────────────────

def validate_falco_file(path: Path) -> ValidationResult:
    """Validate a Falco rule YAML file (structure-based checks).

    Unlike KQL, Falco rules are YAML, so we parse them and inspect each rule as a
    mapping. A Falco file is expected to be a top-level *list* of rule objects.
    For each rule we enforce required fields and a valid priority (errors), and
    nudge on MITRE tagging, description length, and useful output (warnings).

    Args:
        path: Path to the Falco .yaml file.

    Returns:
        ValidationResult: passed=False on read/parse failure, an empty file, a
        non-list top level, or any per-rule error; otherwise passed=True.
    """
    errors = []
    warnings = []

    # Read + parse in one guarded block. Two distinct failure modes get distinct
    # messages: an OS read error vs. malformed YAML that ``safe_load`` rejects.
    try:
        content = path.read_text(encoding="utf-8")
        rules = yaml.safe_load(content)
    except OSError as e:
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=[f"Cannot read file: {e}"], warnings=[]
        )
    except yaml.YAMLError as e:
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=[f"Invalid YAML: {e}"], warnings=[]
        )

    # ``safe_load`` returns None for an empty document — treat as no rules.
    if not rules:
        errors.append("File is empty or contains no rules")
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=errors, warnings=warnings
        )

    # Falco rule files are a YAML sequence at the top level. Anything else (a
    # bare mapping, a scalar) is structurally wrong — bail before iterating.
    if not isinstance(rules, list):
        errors.append("Expected a list of rules at the top level")
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=errors, warnings=warnings
        )

    # Validate each rule independently so one bad rule doesn't mask the others.
    # ``enumerate`` gives us an index to name unnamed/malformed entries.
    for i, rule in enumerate(rules):
        # Falco files may also contain ``list:``/``macro:`` entries, but any item
        # that isn't a mapping at all can't be validated as a rule — flag it.
        if not isinstance(rule, dict):
            errors.append(f"Rule {i}: expected a mapping, got {type(rule).__name__}")
            continue

        # Falco rule files legitimately contain `list:` and `macro:` entries
        # alongside rules. They are reusable fragments referenced from a rule's
        # condition (e.g. an allowlist of platform images), NOT detections, so
        # the rule-shaped checks below do not apply. Validate their own required
        # key and move on — treating them as malformed rules produced four
        # spurious errors per list and blocked a legitimate tuning change.
        if "list" in rule:
            if "items" not in rule:
                errors.append(f"List '{rule['list']}': missing required field 'items'")
            elif not isinstance(rule["items"], list):
                errors.append(f"List '{rule['list']}': 'items' must be a list")
            continue
        if "macro" in rule:
            if "condition" not in rule:
                errors.append(f"Macro '{rule['macro']}': missing required field 'condition'")
            continue

        # Prefer the rule's own name in messages; fall back to a positional label.
        rule_name = rule.get("rule", f"<unnamed rule {i}>")

        # Every required key must be present. Absence of any is a blocking error.
        for field in REQUIRED_FALCO_FIELDS:
            if field not in rule:
                errors.append(f"Rule '{rule_name}': missing required field '{field}'")

        # Priority must be one of Falco's known severities. ``.upper()`` makes the
        # check case-insensitive; the empty-string default skips rules with no
        # priority here (already reported missing by the required-fields loop).
        priority = rule.get("priority", "").upper()
        if priority and priority not in VALID_FALCO_PRIORITIES:
            errors.append(
                f"Rule '{rule_name}': invalid priority '{priority}' — "
                f"must be one of {sorted(VALID_FALCO_PRIORITIES)}"
            )

        # Encourage an ATT&CK mapping in the tags list. ``MITRE_PATTERN.match``
        # only anchors at the start of each tag, which is fine since technique
        # tags are written as bare IDs like "T1611". Non-list tags get their own
        # warning (Falco expects a sequence here).
        tags = rule.get("tags", [])
        if isinstance(tags, list):
            mitre_tags = [t for t in tags if MITRE_PATTERN.match(str(t))]
            if not mitre_tags:
                warnings.append(
                    f"Rule '{rule_name}': no MITRE technique tag found — "
                    "add e.g. T1611 to tags list"
                )
        else:
            warnings.append(f"Rule '{rule_name}': tags should be a list")

        # A one-word description is technically valid but unhelpful to an analyst.
        # 20 chars is an arbitrary "did you actually explain it?" threshold.
        desc = rule.get("desc", "")
        if desc and len(desc) < 20:
            warnings.append(
                f"Rule '{rule_name}': description is very short — "
                "add more context about what the rule detects"
            )

        # For container detections, the alert is far more actionable if it names
        # the offending pod. Nudge authors to interpolate %k8s.pod.name in output.
        # (The "%%" in the message is a literal percent for %-style formatting.)
        output = rule.get("output", "")
        if output and "%k8s.pod.name" not in output:
            warnings.append(
                f"Rule '{rule_name}': output missing %%k8s.pod.name — "
                "pod name is essential for container detections"
            )

    # Passed iff no rule produced an error.
    passed = len(errors) == 0
    return ValidationResult(
        file=str(path), rule_type="Falco",
        passed=passed, errors=errors, warnings=warnings
    )


# ── Runner ───────────────────────────────────────────────────────────────────

def run_validation(detections_dir: str) -> tuple[int, int]:
    """
    Validate every detection rule under ``detections_dir`` and print a report.

    Discovers KQL and Falco rule files by convention (see the globs below),
    validates each, prints a formatted summary block, and returns the tallies.

    Args:
        detections_dir: Root directory to scan (e.g. "detections").

    Returns:
        tuple[int, int]: (passed_count, failed_count). Returns (0, 1) as a
        sentinel "nothing to validate is itself a failure" when no files match —
        so an empty/misconfigured detections dir fails CI rather than passing
        vacuously.
    """
    base = Path(detections_dir)
    results = []

    # Validate KQL files: the kql/ library AND deployed technique-folder query.kql
    # (test.kql helper queries are intentionally excluded). The two globs are
    # concatenated so both layouts in this repo are covered in one pass.
    kql_files = sorted(base.glob("kql/*.kql")) + sorted(base.glob("*/query.kql"))
    if kql_files:
        for kql_file in kql_files:
            results.append(validate_kql_file(kql_file))
    else:
        log.warning("No .kql files found under %s", detections_dir)

    # Validate Falco files — all *.yaml directly under detections/falco/.
    falco_dir = base / "falco"
    if falco_dir.exists():
        for falco_file in sorted(falco_dir.glob("*.yaml")):
            results.append(validate_falco_file(falco_file))
    else:
        log.warning("No falco/ directory found under %s", detections_dir)

    # No files at all almost certainly means a wrong --detections-dir or a broken
    # checkout; surface it as a failure so it can't slip through silently.
    if not results:
        log.error("No detection files found under %s", detections_dir)
        return 0, 1

    # Tally pass/fail across every result for the summary line and return value.
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    print()
    print("=" * 60)
    print(" Detection Rule Validation Results")
    print("=" * 60)
    for result in results:
        print(result)
    print()
    print(f"Results: {passed} passed, {failed} failed, {len(results)} total")
    print("=" * 60)

    return passed, failed


# ── Entry Point ──────────────────────────────────────────────────────────────

def main() -> int:
    """Parse CLI args, run validation, and translate the result to an exit code.

    Returns:
        int: 0 when every file passed, 1 when any file failed. This return value
        becomes the process exit code and is what CI keys off of.
    """
    parser = argparse.ArgumentParser(
        description="Validate KQL and Falco detection rules"
    )
    parser.add_argument(
        "--detections-dir",
        default="detections",
        help="Path to detections directory (default: detections/)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    args = parser.parse_args()

    # --verbose drops the root logger to DEBUG so the "Found MITRE techniques"
    # debug lines (and any others) become visible.
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    passed, failed = run_validation(args.detections_dir)

    # Any failure -> non-zero exit so the CI step goes red.
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    # Hand main()'s return value to the OS as the process exit code.
    sys.exit(main())
