#!/usr/bin/env python3
"""Warn (non-blocking) on expired security exceptions.

WHAT THIS SCRIPT IS FOR
-----------------------
Real projects accumulate deliberate, documented deviations from a security
baseline — "we know this control is off, here's why, and here's when we'll
revisit it." In this lab those live in ``docs/security-exceptions.yaml``. Some
are time-boxed (they carry an ``expiration_date``); some are permanent,
knowingly accepted risks (``expiration_date: none``).

This tool reads that file and, for every time-boxed exception whose expiry has
passed, prints a GitHub Actions ``::warning::`` annotation. Those annotations
surface as yellow warnings in the CI run's "Annotations" panel and inline on
changed files — a gentle nudge to re-review or renew the exception.

WHY IT ALWAYS EXITS 0 (NON-BLOCKING BY DESIGN)
----------------------------------------------
This is a learning lab, not a production gate. An expired exception should
prompt a human to look, not hard-fail the pipeline and block everything else.
So every code path returns 0 — even "couldn't read the file" — and the script
communicates purely through warnings. If you wanted this to *enforce* expiry in
a real pipeline, you'd return a non-zero exit code here instead.

PERMANENT EXCEPTIONS ARE SKIPPED
--------------------------------
Entries with ``expiration_date: none`` (or a literal ``None`` in YAML) are
by-design accepted risks with no review deadline, so they never warn.
"""
# Standard library only — no third-party install needed except PyYAML.
import datetime
import sys
import yaml  # PyYAML: parses the exceptions file into native Python objects.

# Path is relative to the repo root, which is where CI invokes this script from.
EXCEPTIONS_FILE = "docs/security-exceptions.yaml"


def main() -> int:
    """Scan the exceptions file and warn on any that have expired.

    Returns:
        int: Always 0 (non-blocking). The return value feeds ``sys.exit`` so the
        process exit code is likewise always success, regardless of findings.
    """
    # Load the YAML. ``safe_load`` refuses to construct arbitrary Python objects
    # (unlike full ``load``), which is the right default for untrusted-ish input.
    # ``or {}`` guards against an empty file, where ``safe_load`` returns None.
    try:
        doc = yaml.safe_load(open(EXCEPTIONS_FILE)) or {}
    except OSError as e:
        # File missing/unreadable. We warn but still succeed — see module docstring.
        print(f"::warning::Could not read {EXCEPTIONS_FILE}: {e}")
        return 0

    today = datetime.date.today()
    expired = 0  # Running count of expired entries, reported in the summary line.

    # ``doc.get("exceptions") or []`` tolerates both a missing key and an explicit
    # ``exceptions:`` with no list under it — either way we iterate nothing.
    for entry in (doc.get("exceptions") or []):
        exp = entry.get("expiration_date")

        # Permanent exception: no expiry, or the literal string "none" in any
        # casing. These are accepted risks with no deadline, so skip them.
        if exp is None or str(exp).lower() == "none":
            continue

        # Normalize the expiry into a datetime.date so we can compare it to today.
        # PyYAML may already parse an ISO date (YYYY-MM-DD) into a datetime.date,
        # in which case we use it as-is; otherwise we parse the string ourselves.
        try:
            due = exp if isinstance(exp, datetime.date) else datetime.date.fromisoformat(str(exp))
        except ValueError:
            # A malformed date (e.g. "soon") shouldn't crash the run — warn and
            # move on so the remaining entries are still checked.
            print(f"::warning::Exception {entry.get('id')} has an unparseable expiration_date: {exp}")
            continue

        # Strictly-past dates are expired. An exception expiring *today* is still
        # considered valid (not < today).
        if due < today:
            expired += 1
            print(f"::warning::Security exception {entry.get('id')} expired on {exp} — review or renew it")

    # Final human-readable summary; also visible in plain CI logs, not just annotations.
    print(f"Checked security exceptions; {expired} expired (warnings only, non-blocking).")
    return 0


if __name__ == "__main__":
    # Propagate main()'s return value as the process exit code (always 0 here).
    sys.exit(main())
