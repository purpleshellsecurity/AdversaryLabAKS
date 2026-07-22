#!/usr/bin/env python3
"""Warn (non-blocking) on expired security exceptions.

Reads docs/security-exceptions.yaml and emits GitHub Actions ::warning::
annotations for any time-boxed exception past its expiration_date. Always exits
0 — this lab warns, it does not gate. Entries with expiration_date: none are
permanent, by-design accepted risks and are skipped.
"""
import datetime
import sys
import yaml

EXCEPTIONS_FILE = "docs/security-exceptions.yaml"


def main() -> int:
    try:
        doc = yaml.safe_load(open(EXCEPTIONS_FILE)) or {}
    except OSError as e:
        print(f"::warning::Could not read {EXCEPTIONS_FILE}: {e}")
        return 0

    today = datetime.date.today()
    expired = 0

    for entry in (doc.get("exceptions") or []):
        exp = entry.get("expiration_date")
        if exp is None or str(exp).lower() == "none":
            continue
        try:
            due = exp if isinstance(exp, datetime.date) else datetime.date.fromisoformat(str(exp))
        except ValueError:
            print(f"::warning::Exception {entry.get('id')} has an unparseable expiration_date: {exp}")
            continue
        if due < today:
            expired += 1
            print(f"::warning::Security exception {entry.get('id')} expired on {exp} — review or renew it")

    print(f"Checked security exceptions; {expired} expired (warnings only, non-blocking).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
