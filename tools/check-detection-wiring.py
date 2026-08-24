#!/usr/bin/env python3
"""
Detection wiring check — proves every rule is actually reachable by a deployment.

WHY THIS EXISTS
---------------
``validate.py`` answers "is this rule authored correctly?" and ``kql_test.py``
answers "does this rule fire on the attack?". Neither answers the question that
went unnoticed for the whole ``detections/kql/`` library: **is this rule wired up
to deploy at all?**

Ten rules were structurally valid, seven were proven against fixtures in a real
Kusto engine, and none of them were ever deployed as Sentinel analytics rules —
because only one detection had a Bicep wrapper. The rules passed every gate and
still alerted on nothing.

``infrastructure/modules/aks_detections.bicep`` now deploys the library, but it
has to spell out each file path one by one: Bicep's ``loadTextContent`` and
``loadJsonContent`` require compile-time constant paths, so the module cannot
discover new detections on its own. That makes "author a rule and forget to wire
it" the natural next version of the same mistake. This check closes it.

WHAT IT ENFORCES
----------------
  1. Every ``.kql`` has a ``.metadata.json`` sidecar, and vice versa.
  2. Every detection is referenced by the Bicep module (so it can deploy).
  3. Metadata is complete and its values are ones Sentinel accepts.
  4. Rule names are unique — a collision would silently overwrite a live rule.
  5. Entity mappings reference columns the query actually projects.

Check 5 is the one worth dwelling on. Sentinel entity mappings promote query
columns into Account/IP entities, which is what drives correlation and the
investigation graph. The shared rule module used to hardcode ``Username`` and
``SourceIp`` — columns that, verifiably, only ONE of the eleven detections
projects (T1098.006). Nine project neither; lateral-movement projects Username
but no SourceIp.

What Sentinel does with a mapping to a column the query never returns is NOT
verified here: depending on the API version it either rejects the rule at
creation ("the given column does not exist") or accepts it and the entity never
populates. Either way the mapping is wrong, so this check refuses to ship it —
but the check is justified by the column mismatch itself, not by an assumed
failure mode.

EXIT CODE
---------
0 when every detection is complete and wired; 1 otherwise, so CI blocks a merge
that would ship an unreachable or misconfigured rule.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KQL_DIR = REPO_ROOT / "detections" / "kql"
WIRING_BICEP = REPO_ROOT / "infrastructure" / "modules" / "aks_detections.bicep"

# Fields every sidecar must define. Anything missing would either fail the Bicep
# compile or silently fall back to a default the author never chose.
REQUIRED_FIELDS = (
    "ruleName", "displayName", "description", "severity", "tactics", "techniques",
    "queryFrequency", "queryPeriod", "triggerThreshold", "enabled", "deploy",
    "groupingMatchingMethod", "entityMappings", "maturity",
)

# Constrained by the Microsoft.SecurityInsights/alertRules schema.
VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_GROUPING = {"AllEntities", "AnyAlert", "Selected"}

# Sentinel takes the PARENT technique only — "T1552", never "T1552.007".
PARENT_TECHNIQUE = re.compile(r"^T\d{4}$")

# ISO-8601 duration, the subset Sentinel accepts for schedules (e.g. PT15M, PT1H, P1D).
ISO_DURATION = re.compile(r"^P(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?)?$")


def load_wired_slugs() -> set[str]:
    """Extract the detection slugs the Bicep module actually references.

    Returns:
        set[str]: Slugs found in ``loadTextContent('../../detections/kql/<slug>.kql')``
        calls — i.e. the detections that can actually reach a deployment.

    Raises:
        SystemExit: If the wiring module is missing; without it nothing deploys
        and every other check would report misleading results.
    """
    if not WIRING_BICEP.exists():
        sys.exit(f"ERROR: wiring module not found at {WIRING_BICEP}")
    text = WIRING_BICEP.read_text(encoding="utf-8")
    return set(re.findall(r"loadTextContent\('\.\./\.\./detections/kql/([^']+)\.kql'\)", text))


def projected_columns(query_text: str) -> set[str]:
    """Collect column names a KQL query plausibly returns.

    This is a deliberately GENEROUS approximation, not a KQL parser. It gathers
    every identifier that appears as an assignment target or bare column in the
    query's ``project``, ``extend``, and ``summarize`` clauses. Being generous is
    the right bias: the check exists to catch an entity mapping naming a column
    that appears nowhere in the query, and a false failure here would be far more
    annoying than a missed edge case.

    Args:
        query_text: Full text of the .kql file.

    Returns:
        set[str]: Identifiers the query appears to produce.
    """
    # Strip // comments so commented-out clauses don't contribute phantom columns.
    body = "\n".join(re.sub(r"//.*$", "", line) for line in query_text.splitlines())

    columns: set[str] = set()
    # Assignment form: `User = tostring(...)`, `Flows = count()`.
    columns.update(re.findall(r"(\w+)\s*=", body))
    # Bare column lists after project/summarize/extend, e.g. `| project A, B, C`.
    for clause in re.findall(r"\|\s*(?:project|extend|summarize|project-keep)\b([^|]*)", body):
        columns.update(re.findall(r"\b([A-Za-z_]\w*)\b", clause))
    return columns


def check_detection(slug: str, wired: set[str], seen_rule_names: dict) -> list[str]:
    """Validate one detection's metadata, wiring, and entity mappings.

    Args:
        slug: Detection filename stem (e.g. "privileged-pod").
        wired: Slugs referenced by the Bicep module.
        seen_rule_names: Accumulator mapping ruleName -> slug, for collision detection.

    Returns:
        list[str]: Problem descriptions; empty when the detection is sound.
    """
    problems: list[str] = []
    kql_path = KQL_DIR / f"{slug}.kql"
    meta_path = KQL_DIR / f"{slug}.metadata.json"

    if not kql_path.exists():
        return [f"{slug}: has metadata but no {slug}.kql"]
    if not meta_path.exists():
        return [
            f"{slug}: has no {slug}.metadata.json — it cannot deploy. "
            f"Add the sidecar and reference it in {WIRING_BICEP.name}."
        ]

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"{slug}: metadata is not valid JSON: {e}"]

    for field in REQUIRED_FIELDS:
        if field not in meta:
            problems.append(f"{slug}: metadata missing required field '{field}'")
    if problems:
        # Later checks index into these fields; reporting them missing is enough.
        return problems

    # ── Wiring: present in the Bicep module at all? ──────────────────────────
    if slug not in wired:
        problems.append(
            f"{slug}: not referenced in {WIRING_BICEP.name} — the rule would never "
            f"deploy. Add a union(loadJsonContent(...), {{ query: loadTextContent(...) }}) entry."
        )

    # ── Value validity ──────────────────────────────────────────────────────
    if meta["severity"] not in VALID_SEVERITIES:
        problems.append(f"{slug}: severity '{meta['severity']}' not one of {sorted(VALID_SEVERITIES)}")

    if meta["groupingMatchingMethod"] not in VALID_GROUPING:
        problems.append(
            f"{slug}: groupingMatchingMethod '{meta['groupingMatchingMethod']}' "
            f"not one of {sorted(VALID_GROUPING)}"
        )

    for duration_field in ("queryFrequency", "queryPeriod"):
        if not ISO_DURATION.match(str(meta[duration_field])):
            problems.append(
                f"{slug}: {duration_field} '{meta[duration_field]}' is not an ISO-8601 "
                "duration (e.g. PT15M, PT1H)"
            )

    for technique in meta["techniques"]:
        if not PARENT_TECHNIQUE.match(str(technique)):
            problems.append(
                f"{slug}: technique '{technique}' must be the PARENT technique with no "
                "sub-technique suffix (Sentinel rejects e.g. T1552.007 — use T1552)"
            )

    # ── Rule name uniqueness ────────────────────────────────────────────────
    rule_name = meta["ruleName"]
    if rule_name in seen_rule_names:
        problems.append(
            f"{slug}: ruleName '{rule_name}' already used by "
            f"'{seen_rule_names[rule_name]}' — the second deployment would overwrite the first"
        )
    else:
        seen_rule_names[rule_name] = slug

    # ── Grouping strategy has to match whether entities exist ───────────────
    mappings = meta["entityMappings"]
    if not mappings and meta["groupingMatchingMethod"] == "AllEntities":
        problems.append(
            f"{slug}: groupingMatchingMethod is 'AllEntities' but the rule maps no "
            "entities, so alerts cannot group — use 'AnyAlert'"
        )

    # ── Entity mappings must name columns the query returns ─────────────────
    columns = projected_columns(kql_path.read_text(encoding="utf-8"))
    for mapping in mappings:
        for field_mapping in mapping.get("fieldMappings", []):
            column = field_mapping.get("columnName")
            if column and column not in columns:
                problems.append(
                    f"{slug}: entity mapping references column '{column}', which the "
                    f"query never projects — the {mapping.get('entityType')} entity "
                    "cannot resolve (Sentinel may reject the rule outright, or "
                    "deploy it with an entity that never populates)"
                )

    return problems


def main() -> int:
    """Check every detection and print a report.

    Returns:
        int: 0 when all detections are complete and wired, 1 otherwise.
    """
    if not KQL_DIR.is_dir():
        sys.exit(f"ERROR: no detections directory at {KQL_DIR}")

    slugs = sorted(
        {p.stem for p in KQL_DIR.glob("*.kql")}
        | {p.name.removesuffix(".metadata.json") for p in KQL_DIR.glob("*.metadata.json")}
    )
    if not slugs:
        sys.exit(f"ERROR: no detections found under {KQL_DIR}")

    wired = load_wired_slugs()
    seen_rule_names: dict[str, str] = {}
    all_problems: list[str] = []
    deployed = disabled = 0

    for slug in slugs:
        problems = check_detection(slug, wired, seen_rule_names)
        all_problems.extend(problems)

        meta_path = KQL_DIR / f"{slug}.metadata.json"
        if not problems and meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta["deploy"]:
                deployed += 1
                if not meta["enabled"]:
                    disabled += 1
                    # Deploying disabled is a legitimate choice for a rule that is
                    # known-noisy; surface it so it stays a conscious one.
                    print(f"::notice::{slug} deploys DISABLED (maturity: {meta['maturity']})")
            else:
                print(f"::notice::{slug} is NOT deployed (maturity: {meta['maturity']})")

    # Flag anything wired in Bicep with no detection behind it — a stale path
    # would fail the Bicep compile, but a renamed slug is worth naming here.
    for slug in sorted(wired - set(slugs)):
        all_problems.append(f"{slug}: referenced in {WIRING_BICEP.name} but no such detection exists")

    print()
    print("=" * 62)
    print(" Detection Wiring Check")
    print("=" * 62)
    print(f" detections found : {len(slugs)}")
    print(f" wired to deploy  : {deployed} ({disabled} deploying disabled)")
    print(f" not deployed     : {len(slugs) - deployed}")
    print("=" * 62)

    if all_problems:
        print()
        for problem in all_problems:
            print(f"::error::{problem}")
        print(f"\n{len(all_problems)} problem(s) found.")
        return 1

    print(" OK — every detection has metadata and is wired to a deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
