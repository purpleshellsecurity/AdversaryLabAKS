#!/usr/bin/env python3
"""
Detection Rule Validator
AKS Adversary Lab - validates KQL and Falco detection rules
for required fields, MITRE ATT&CK mappings, and structural integrity.
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

MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

REQUIRED_KQL_FIELDS = [
    "TimeGenerated",
    "MitreTechnique",
]

REQUIRED_FALCO_FIELDS = [
    "rule",
    "desc",
    "condition",
    "output",
    "priority",
    "tags",
]

VALID_FALCO_PRIORITIES = {
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
    "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"
}

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    file: str
    rule_type: str
    passed: bool
    errors: list
    warnings: list

    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] {self.file}"]
        for e in self.errors:
            lines.append(f"       ERROR: {e}")
        for w in self.warnings:
            lines.append(f"       WARN:  {w}")
        return "\n".join(lines)


# ── KQL Validators ───────────────────────────────────────────────────────────

def validate_kql_file(path: Path) -> ValidationResult:
    """Validate a KQL detection rule file."""
    errors = []
    warnings = []

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        return ValidationResult(
            file=str(path), rule_type="KQL",
            passed=False, errors=[f"Cannot read file: {e}"], warnings=[]
        )

    # Check file has content
    if not content.strip():
        errors.append("File is empty")
        return ValidationResult(
            file=str(path), rule_type="KQL",
            passed=False, errors=errors, warnings=warnings
        )

    # Check for MITRE technique mapping
    mitre_matches = MITRE_PATTERN.findall(content)
    if not mitre_matches:
        errors.append("No MITRE ATT&CK technique ID found (e.g. T1611)")
    else:
        log.debug("Found MITRE techniques: %s", mitre_matches)

    # Check for required fields
    for field in REQUIRED_KQL_FIELDS:
        if field not in content:
            if field == "MitreTechnique":
                warnings.append(f"Missing field: {field} — add 'extend MitreTechnique = \"TXXXX\"'")
            else:
                errors.append(f"Missing required field reference: {field}")

    # Check for header comment block
    if not content.startswith("//"):
        warnings.append("Missing header comment block — add description, MITRE, and source")

    # Check for time filter
    if "ago(" not in content and "TimeGenerated" in content:
        warnings.append("No time filter found — consider adding 'where TimeGenerated > ago(1h)'")

    passed = len(errors) == 0
    return ValidationResult(
        file=str(path), rule_type="KQL",
        passed=passed, errors=errors, warnings=warnings
    )


# ── Falco Validators ─────────────────────────────────────────────────────────

def validate_falco_file(path: Path) -> ValidationResult:
    """Validate a Falco rule YAML file."""
    errors = []
    warnings = []

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

    if not rules:
        errors.append("File is empty or contains no rules")
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=errors, warnings=warnings
        )

    if not isinstance(rules, list):
        errors.append("Expected a list of rules at the top level")
        return ValidationResult(
            file=str(path), rule_type="Falco",
            passed=False, errors=errors, warnings=warnings
        )

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"Rule {i}: expected a mapping, got {type(rule).__name__}")
            continue

        rule_name = rule.get("rule", f"<unnamed rule {i}>")

        # Check required fields
        for field in REQUIRED_FALCO_FIELDS:
            if field not in rule:
                errors.append(f"Rule '{rule_name}': missing required field '{field}'")

        # Validate priority
        priority = rule.get("priority", "").upper()
        if priority and priority not in VALID_FALCO_PRIORITIES:
            errors.append(
                f"Rule '{rule_name}': invalid priority '{priority}' — "
                f"must be one of {sorted(VALID_FALCO_PRIORITIES)}"
            )

        # Check for MITRE mapping in tags
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

        # Check description length
        desc = rule.get("desc", "")
        if desc and len(desc) < 20:
            warnings.append(
                f"Rule '{rule_name}': description is very short — "
                "add more context about what the rule detects"
            )

        # Check output has useful fields
        output = rule.get("output", "")
        if output and "%k8s.pod.name" not in output:
            warnings.append(
                f"Rule '{rule_name}': output missing %%k8s.pod.name — "
                "pod name is essential for container detections"
            )

    passed = len(errors) == 0
    return ValidationResult(
        file=str(path), rule_type="Falco",
        passed=passed, errors=errors, warnings=warnings
    )


# ── Runner ───────────────────────────────────────────────────────────────────

def run_validation(detections_dir: str) -> tuple[int, int]:
    """
    Validate all detection rules under detections_dir.
    Returns (passed_count, failed_count).
    """
    base = Path(detections_dir)
    results = []

    # Validate KQL files
    kql_dir = base / "kql"
    if kql_dir.exists():
        for kql_file in sorted(kql_dir.glob("*.kql")):
            results.append(validate_kql_file(kql_file))
    else:
        log.warning("No kql/ directory found under %s", detections_dir)

    # Validate Falco files
    falco_dir = base / "falco"
    if falco_dir.exists():
        for falco_file in sorted(falco_dir.glob("*.yaml")):
            results.append(validate_falco_file(falco_file))
    else:
        log.warning("No falco/ directory found under %s", detections_dir)

    if not results:
        log.error("No detection files found under %s", detections_dir)
        return 0, 1

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

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    passed, failed = run_validation(args.detections_dir)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
