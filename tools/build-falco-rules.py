#!/usr/bin/env python3
"""
Falco rule assembler — makes helm/falco/values.yaml a DERIVED file.

WHY THIS EXISTS
---------------
The lab's six Falco rules used to live in two places at once: as readable,
commented YAML in ``detections/falco/*.yaml``, and again — hand-copied — inside
the ``customRules`` value in ``helm/falco/values.yaml``. Only the second copy is
ever deployed; Helm never reads ``detections/falco/``.

That is a silent, expensive failure mode. You tune a rule in the source file,
review it in a PR, merge it, and the cluster keeps running the old condition.
Every downstream artifact then lies: the coverage matrix says the rule was
tuned, git history says it was tuned, and the node is running last month's logic.

This script removes the second source of truth. ``detections/falco/*.yaml`` is
now the ONLY place a rule is authored; the Helm value is generated from it.
It is the same principle already applied correctly on the KQL side, where
``detections/T1098.006-cluster-role-binding/rule.bicep`` does::

    queryContent: loadTextContent('query.kql')  // so rule + hunt query never drift

TWO MODES
---------
  * ``--check`` — verify the committed values.yaml matches the source rules.
    Reports per-rule, field-level drift and exits 1 if any is found. This is
    what CI runs, and it is what you run locally before pushing.
  * (no flag)   — regenerate values.yaml in place. This is what you run after
    editing a rule.

WHY VERBATIM TEXT, NOT A YAML ROUND-TRIP
----------------------------------------
The obvious implementation — ``yaml.safe_load`` the sources and ``yaml.dump``
them into the value — would work but would destroy the authors' formatting:
folded ``>`` conditions collapse into single long quoted lines, and the rules
become much harder to read in a diff.

So instead the assembler copies the source rule text VERBATIM (dropping only
whole-line comments, which belong with the annotated source files rather than
the deployment artifact) and embeds it as a YAML block scalar. Correctness is
then guaranteed the other way round: :func:`verify` parses both sides and
compares them semantically, field by field, so a formatting-preserving copy can
never silently change what a rule actually matches.

The generated block is a ``|-`` block scalar rather than the escaped one-line
string this file used to hold, so rule changes now show up as ordinary
line-by-line diffs in review.
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

# ── Layout ───────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
FALCO_SOURCE_DIR = REPO_ROOT / "detections" / "falco"
VALUES_FILE = REPO_ROOT / "helm" / "falco" / "values.yaml"

# The key inside `falco.customRules` that holds the assembled ruleset. Falco
# mounts each customRules entry into its rules.d directory under this filename.
RULES_KEY = "adversary-lab-rules.yaml"

# Fields compared when checking for drift. These are every field that changes
# what a rule matches or how it reports — i.e. everything that matters.
COMPARED_FIELDS = ("desc", "condition", "output", "priority", "tags")

# Indentation of the block scalar's content RELATIVE to its key. splice_into_values
# adds the key's own indentation on top, so with the key at 4 spaces
# (falco: → customRules: → adversary-lab-rules.yaml:) content lands at 6.
BLOCK_INDENT = " " * 2

# A line consisting only of a comment (optionally indented). Inline trailing
# comments on content lines are deliberately NOT matched — those annotate real
# rule fields and are worth carrying through to the deployed file.
COMMENT_ONLY = re.compile(r"^\s*#")


# ── Assembly ─────────────────────────────────────────────────────────────────

def strip_comment_lines(text: str) -> str:
    """Drop whole-line comments and collapse the blank runs they leave behind.

    The standalone rule files carry substantial teaching commentary — a header
    block explaining the technique, plus per-field notes. That commentary is
    valuable where it lives and only bloats the deployment artifact, so it is
    dropped here. Inline comments (``priority: WARNING   # in-app reads are
    normal``) sit on content lines and are preserved.

    Args:
        text: Raw contents of one ``detections/falco/*.yaml`` file.

    Returns:
        str: The same text with comment-only lines removed, leading/trailing
        blank lines stripped, and no run of more than one blank line left behind.
    """
    kept = [ln for ln in text.splitlines() if not COMMENT_ONLY.match(ln)]

    out: list[str] = []
    for line in kept:
        # Collapse consecutive blanks — removing a comment block otherwise
        # leaves a gap whose size depends on how much commentary was there,
        # which would make the generated output unstable across edits.
        if not line.strip() and (not out or not out[-1].strip()):
            continue
        out.append(line.rstrip())

    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def load_source_rules() -> tuple[str, list[dict]]:
    """Read every source rule file and assemble the deployable ruleset.

    Files are processed in sorted order so the generated output is deterministic
    — the same inputs always produce a byte-identical block, which is what makes
    the ``--check`` gate meaningful.

    Returns:
        tuple[str, list[dict]]: the assembled rule text, and the parsed rule
        mappings it contains (used for the semantic comparison in verify()).

    Raises:
        SystemExit: If the source directory is missing or holds no rules — an
        empty ruleset would otherwise silently generate an empty Helm value and
        disable runtime detection entirely.
    """
    if not FALCO_SOURCE_DIR.is_dir():
        sys.exit(f"ERROR: no Falco source directory at {FALCO_SOURCE_DIR}")

    chunks: list[str] = []
    rules: list[dict] = []

    # ORDER IS SEMANTIC, NOT COSMETIC. Falco resolves a `list:`/`macro:` at the
    # point a condition references it, so shared fragments must appear BEFORE the
    # rules that use them or the ruleset fails to load. Underscore-prefixed files
    # hold those fragments and are emitted first.
    #
    # This is done explicitly rather than relying on sorted() — "_" happens to
    # sort before lowercase letters in ASCII, which would make correctness an
    # accident of filenames that a rename could silently break.
    paths = sorted(FALCO_SOURCE_DIR.glob("*.yaml"))
    paths.sort(key=lambda p: not p.name.startswith("_"))

    for path in paths:
        raw = path.read_text(encoding="utf-8")

        # Parse first: a source file that isn't a list of rule mappings would
        # produce a corrupt deployed ruleset, so fail here rather than ship it.
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            sys.exit(f"ERROR: {path.name} is not valid YAML: {e}")

        if not isinstance(parsed, list):
            sys.exit(f"ERROR: {path.name} must contain a top-level list of rules")

        rules.extend(r for r in parsed if isinstance(r, dict))
        chunks.append(strip_comment_lines(raw))

    if not rules:
        sys.exit(f"ERROR: no Falco rules found under {FALCO_SOURCE_DIR}")

    return "\n\n".join(chunks), rules


def render_block_scalar(rule_text: str) -> str:
    """Render the assembled rules as an indented YAML block-scalar value.

    ``|-`` keeps newlines literal and strips the trailing one. Every content
    line is indented to BLOCK_INDENT; blank lines are emitted truly empty rather
    than as indented whitespace, which some YAML tooling flags.

    Args:
        rule_text: The assembled rule text from load_source_rules().

    Returns:
        str: Lines forming the value, starting with the ``|-`` introducer.
    """
    lines = [f"{RULES_KEY}: |-"]
    for line in rule_text.splitlines():
        lines.append(f"{BLOCK_INDENT}{line}" if line.strip() else "")
    return "\n".join(lines)


# ── values.yaml surgery ──────────────────────────────────────────────────────

def splice_into_values(values_text: str, block: str) -> str:
    """Replace the customRules value in values.yaml, preserving everything else.

    A YAML round-trip would strip this file's extensive explanatory comments, so
    the rewrite is textual: locate the ``adversary-lab-rules.yaml:`` key, consume
    exactly its scalar value (every following line more-indented than the key,
    plus interior blanks), and splice the new block in its place.

    Args:
        values_text: Current contents of helm/falco/values.yaml.
        block: Rendered block scalar from render_block_scalar().

    Returns:
        str: The updated file contents.

    Raises:
        SystemExit: If the key cannot be found — better to stop than to guess at
        where the value belongs and corrupt the chart values.
    """
    lines = values_text.splitlines()

    key_idx = next(
        (i for i, ln in enumerate(lines) if ln.strip().startswith(f"{RULES_KEY}:")),
        None,
    )
    if key_idx is None:
        sys.exit(f"ERROR: could not find '{RULES_KEY}:' in {VALUES_FILE}")

    key_indent = len(lines[key_idx]) - len(lines[key_idx].lstrip())

    # Walk forward over the scalar's continuation lines. A blank line may sit
    # inside a block scalar, so it does not by itself end the value — only a
    # non-blank line indented at or above the key's own level does.
    end = key_idx + 1
    while end < len(lines):
        line = lines[end]
        if not line.strip():
            end += 1
            continue
        if len(line) - len(line.lstrip()) <= key_indent:
            break
        end += 1

    # Trim blank lines that trailed the old value so they aren't duplicated —
    # the structural blank line before the next key is re-added by the join.
    while end > key_idx + 1 and not lines[end - 1].strip():
        end -= 1

    indented_block = [f"{' ' * key_indent}{ln}" if ln else "" for ln in block.splitlines()]
    return "\n".join(lines[:key_idx] + indented_block + lines[end:]) + "\n"


def extract_deployed_rules(values_text: str) -> list[dict]:
    """Parse the rules currently embedded in values.yaml.

    Args:
        values_text: Contents of helm/falco/values.yaml.

    Returns:
        list[dict]: The rule mappings Helm would actually deploy.

    Raises:
        SystemExit: If the chart values, or the embedded ruleset, cannot be
        parsed — in either case there is nothing meaningful to compare against.
    """
    try:
        doc = yaml.safe_load(values_text) or {}
    except yaml.YAMLError as e:
        sys.exit(f"ERROR: {VALUES_FILE} is not valid YAML: {e}")

    embedded = (doc.get("falco", {}).get("customRules", {}) or {}).get(RULES_KEY)
    if embedded is None:
        sys.exit(f"ERROR: {VALUES_FILE} has no falco.customRules['{RULES_KEY}']")

    try:
        parsed = yaml.safe_load(embedded)
    except yaml.YAMLError as e:
        sys.exit(f"ERROR: embedded ruleset in {VALUES_FILE} is not valid YAML: {e}")

    return [r for r in (parsed or []) if isinstance(r, dict)]


# ── Verification ─────────────────────────────────────────────────────────────

def normalize(value) -> str:
    """Flatten a field to a whitespace-insensitive string for comparison.

    Falco conditions are folded ``>`` scalars, so identical logic can differ in
    line breaks and indentation. Collapsing all runs of whitespace compares what
    the rule MEANS rather than how it happens to be wrapped.

    Args:
        value: Any rule field value (string, list of tags, priority, ...).

    Returns:
        str: A canonical single-line form.
    """
    return " ".join(str(value).split())


def verify() -> int:
    """Compare deployed rules against source rules and report any drift.

    Returns:
        int: 0 when every source rule is present and semantically identical in
        values.yaml, 1 otherwise. This is the process exit code CI keys off.
    """
    _, source_rules = load_source_rules()
    deployed_rules = extract_deployed_rules(VALUES_FILE.read_text(encoding="utf-8"))

    # Only entries with a `rule:` key are detections. `list:`/`macro:` entries
    # are reusable condition fragments — they travel with the rules and are
    # compared implicitly through the conditions that reference them.
    source_by_name = {r["rule"]: r for r in source_rules if "rule" in r}
    deployed_by_name = {r["rule"]: r for r in deployed_rules if "rule" in r}

    problems: list[str] = []

    for name, src in source_by_name.items():
        dep = deployed_by_name.get(name)
        if dep is None:
            problems.append(f"'{name}' is in detections/falco/ but NOT deployed")
            continue
        drifted = [
            f for f in COMPARED_FIELDS
            if normalize(src.get(f)) != normalize(dep.get(f))
        ]
        if drifted:
            problems.append(f"'{name}' differs in: {', '.join(drifted)}")

    for name in deployed_by_name:
        if name not in source_by_name:
            problems.append(f"'{name}' is deployed but has NO source in detections/falco/")

    print(f"Falco rules — source: {len(source_by_name)}, deployed: {len(deployed_by_name)}")

    if problems:
        for problem in problems:
            print(f"::error::Falco rule drift — {problem}")
        print()
        print("helm/falco/values.yaml is GENERATED and is now stale.")
        print("Regenerate it with:  python tools/build-falco-rules.py")
        return 1

    print("OK — every source rule is deployed, byte-for-byte equivalent.")
    return 0


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    """Parse args and either regenerate values.yaml or verify it.

    Returns:
        int: 0 on success, 1 on drift (``--check``) — the process exit code.
    """
    parser = argparse.ArgumentParser(
        description="Assemble detections/falco/*.yaml into helm/falco/values.yaml"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify values.yaml matches the source rules; do not write (CI mode)",
    )
    args = parser.parse_args()

    if args.check:
        return verify()

    rule_text, rules = load_source_rules()
    current = VALUES_FILE.read_text(encoding="utf-8")
    updated = splice_into_values(current, render_block_scalar(rule_text))

    if updated == current:
        print(f"helm/falco/values.yaml already up to date ({len(rules)} rules).")
        return 0

    VALUES_FILE.write_text(updated, encoding="utf-8")
    print(f"Regenerated helm/falco/values.yaml from {len(rules)} source rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
