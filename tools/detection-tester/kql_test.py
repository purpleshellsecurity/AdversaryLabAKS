#!/usr/bin/env python3
"""
KQL detection logic tester (Tier 1 — offline, no cloud).

Runs a REAL detection .kql against RECORDED event fixtures inside a genuine Kusto
engine (the Kusto emulator, mcr.microsoft.com/azuredataexplorer/kustainer-linux),
and asserts it fires on the malicious sample and stays silent on the benign one.

How it works — no ingestion pipeline needed:
  We bind the audit table name to the fixture rows with a `let` datatable, inject
  a fresh TimeGenerated, then append the detection query verbatim and `| count`:

      let AKSAuditAdmin = datatable(...)[ ...fixture... ] | extend TimeGenerated = now();
      <contents of detections/kql/privileged-pod.kql>
      | count

  Because the `let` shadows the table name, the UNMODIFIED detection query runs
  against our fixture. That means we test the actual shipped logic, not a copy.

  This is the key trick, so it's worth stating plainly: in KQL a `let` binding
  that shares a name with a real table takes precedence within the query. The
  shipped rule starts with `AKSAuditAdmin | where ...`. Normally that reads the
  live cloud table; here, because we prepended `let AKSAuditAdmin = datatable(...)`,
  the very same rule text now reads our in-memory fixture rows instead — no
  ingestion, no cloud, no edits to the rule. We append `| count` so the whole
  thing collapses to a single number: >0 rows means "the detection fired".

A test manifest (detections/kql/tests/<rule>/test.json) declares the rule path,
the table name, the column schema, and the cases (fixture -> expected match/no_match).
A minimal manifest looks like:

    {
      "rule": "detections/kql/privileged-pod.kql",   # rule text to test, repo-relative
      "table": "AKSAuditAdmin",                        # table name the rule reads (shadowed)
      "schema": [{"name": "RequestUri", "type": "string"}, ...],
      "inject_timegenerated": true,                    # add a fresh TimeGenerated column?
      "cases": [
        {"name": "fires on privileged pod", "fixture": "malicious.json", "expect": "match"},
        {"name": "quiet on normal pod",     "fixture": "benign.json",    "expect": "no_match"}
      ]
    }

Usage:
  python kql_test.py --tests-dir detections/kql/tests               # run against $KUSTO_ENDPOINT
  python kql_test.py --tests-dir detections/kql/tests --dry-run     # print composed KQL, no engine
  KUSTO_ENDPOINT=http://localhost:8080 python kql_test.py ...
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    # requests is only used to POST queries at the live Kusto emulator. --dry-run
    # never touches the network, so we tolerate it being absent and only complain
    # (in run()) if a live run is actually attempted without it.
    import requests
except ImportError:
    requests = None  # only needed for live runs, not --dry-run


# ── KQL literal rendering ────────────────────────────────────────────────────

def kql_string(value: str) -> str:
    """Render a Python str as a safely-escaped KQL double-quoted string literal.

    We're building KQL source text by hand, so any backslashes or double quotes
    in the value must be escaped or they'd break out of the literal (and could,
    in principle, alter the query). Order matters: escape backslashes first, then
    quotes, otherwise the backslash we add for a quote would itself get doubled.

    Args:
        value: The raw value to embed (coerced to str).

    Returns:
        str: e.g. ``he said "hi"`` -> ``"he said \\"hi\\""``.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def kql_value(value, col_type: str) -> str:
    """Render one fixture cell as a KQL scalar literal, per its declared type.

    The manifest's schema tells us each column's KQL type; this maps a Python
    value to the correct literal syntax for that type.

    Args:
        value: The Python value from the fixture row (may be None).
        col_type: The KQL column type from the manifest schema.

    Returns:
        str: The value rendered as KQL source (a quoted string, a dynamic(...)
        literal, or a bare numeric/bool literal).

    Raises:
        ValueError: If col_type isn't one we know how to render.
    """
    if col_type == "string":
        # None becomes an empty string so the datatable stays rectangular.
        return kql_string("" if value is None else value)
    if col_type == "dynamic":
        # KQL's dynamic() takes a JSON-ish payload. json.dumps output *is* a valid
        # KQL dynamic literal; separators drop whitespace. When this query is sent
        # over the wire via requests(json=), the transport JSON-encodes the whole
        # csl string, re-escaping these inner quotes correctly end to end.
        return f"dynamic({json.dumps(value, separators=(',', ':'))})"
    if col_type in ("int", "long", "real", "bool", "boolean"):
        # Numbers and booleans render identically in JSON and KQL (1, 3.14, true),
        # so json.dumps is a convenient, correct serializer for these scalars.
        return json.dumps(value)
    raise ValueError(f"Unsupported column type: {col_type}")


def build_datatable(table: str, schema: list, rows: list, inject_time: bool) -> str:
    """Build the ``let <table> = datatable(...)[ ... ];`` fixture-binding statement.

    This is the heart of the shadowing trick (see module docstring): we emit a
    ``let`` that binds the *real* audit table's name to an inline ``datatable``
    holding our fixture rows. Any query that follows and reads ``<table>`` will
    read these rows instead of the cloud table.

    Args:
        table: The table name to shadow (must match what the rule reads).
        schema: List of {"name", "type"} column descriptors, in order.
        rows: List of dict fixture rows (missing keys render as empty/None).
        inject_time: If True, append ``| extend TimeGenerated = now()`` so rules
            that filter on ``ago(...)`` see the rows as "just happened". Fixtures
            therefore don't need to hard-code timestamps that would go stale.

    Returns:
        str: A complete, semicolon-terminated KQL ``let`` statement.
    """
    # Column header, e.g. "RequestUri:string, verb:string, requestObject:dynamic".
    header = ", ".join(f'{c["name"]}:{c["type"]}' for c in schema)
    rendered_rows = []
    for row in rows:
        # Render each cell in schema order; row.get tolerates a fixture that omits
        # a column (it'll render as the type's empty/None form).
        cells = [kql_value(row.get(c["name"]), c["type"]) for c in schema]
        rendered_rows.append("    " + ", ".join(cells))
    body = ",\n".join(rendered_rows)
    stmt = f"let {table} = datatable({header})\n[\n{body}\n]"
    if inject_time:
        # Give every fixture row a fresh "now" timestamp so time-window filters
        # in the rule (where TimeGenerated > ago(1h), etc.) don't exclude them.
        stmt += "\n| extend TimeGenerated = now()"
    return stmt + ";"


def compose_query(manifest: dict, rule_text: str, rows: list) -> str:
    """Assemble the full test query: fixture binding + rule + count.

    Layers three pieces into one KQL program:
      1. the ``let`` that shadows the table with fixture rows,
      2. the UNMODIFIED rule text (which begins by reading that table name), and
      3. ``| count`` to reduce the result to a single number of matches.

    Args:
        manifest: The parsed test.json (provides table/schema/inject flag).
        rule_text: The verbatim contents of the detection .kql file.
        rows: The fixture rows for the current case.

    Returns:
        str: A runnable KQL program whose sole output is a row count.
    """
    datatable = build_datatable(
        manifest["table"], manifest["schema"], rows,
        # Default to injecting TimeGenerated unless the manifest opts out.
        manifest.get("inject_timegenerated", True),
    )
    # rule_text already begins with the (now shadowed) table name, so we just
    # stack it after the let binding and pipe into count.
    return f"{datatable}\n{rule_text.strip()}\n| count"


# ── Kusto engine (emulator) ──────────────────────────────────────────────────

def run_count(endpoint: str, db: str, query: str, token: str | None) -> int:
    """POST a KQL query to the Kusto REST endpoint and return its single count.

    Assumes ``query`` ends in ``| count`` (or otherwise yields exactly one
    numeric cell), which is how compose_query builds it.

    Args:
        endpoint: Base URL of the Kusto engine (emulator or cloud).
        db: Database name to run against.
        query: The KQL text (the "csl" — Command/Statement Language — payload).
        token: Optional bearer token; the local emulator usually needs none.

    Returns:
        int: The value in the first cell of the first result table.

    Raises:
        RuntimeError: On a non-200 response or an unexpectedly shaped body.
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        # Only attach auth when a token is supplied — the local kustainer emulator
        # runs unauthenticated, so we don't force a header on it.
        headers["Authorization"] = f"Bearer {token}"
    # The v1 query REST contract: {"db": ..., "csl": <query text>}. rstrip("/")
    # avoids a doubled slash if the endpoint was given with a trailing one.
    resp = requests.post(
        f"{endpoint.rstrip('/')}/v1/rest/query",
        json={"db": db, "csl": query},
        headers=headers, timeout=60,
    )
    if resp.status_code != 200:
        # Truncate the body so a huge error page doesn't flood the console.
        raise RuntimeError(f"Kusto query failed ({resp.status_code}): {resp.text[:500]}")
    # Kusto v1 responses are {"Tables": [{"Columns": [...], "Rows": [[...]]}]}.
    # We want Tables[0].Rows[0][0] — the single count value.
    tables = resp.json().get("Tables")
    if not tables or not tables[0]["Rows"]:
        raise RuntimeError(f"Unexpected Kusto response: {resp.text[:500]}")
    return int(tables[0]["Rows"][0][0])


def wait_for_engine(endpoint: str, db: str, token: str, timeout_s: int) -> None:
    """Block until the Kusto engine answers a trivial query, or time out.

    The kustainer emulator (often started fresh in CI) takes a little while to
    accept queries. We poll a can't-fail query (``print n=1 | count`` -> 1) every
    few seconds until it succeeds or the deadline passes.

    Args:
        endpoint, db, token: Passed straight through to run_count.
        timeout_s: How long to keep polling before giving up.

    Raises:
        RuntimeError: If the engine never became ready in time (includes the last
            error seen, to aid debugging).
    """
    deadline = time.time() + timeout_s
    last = None  # Remember the most recent failure to report if we time out.
    while time.time() < deadline:
        try:
            # A ready engine returns exactly 1 for this probe.
            if run_count(endpoint, db, "print n=1 | count", token) == 1:
                print(f"[*] Kusto engine ready at {endpoint}")
                return
        except Exception as e:  # noqa: BLE001 — readiness poll, any error = not ready yet
            # During startup we expect connection refused / 5xx / parse hiccups;
            # swallow them all and just keep polling.
            last = e
        time.sleep(3)
    raise RuntimeError(f"Kusto engine not ready after {timeout_s}s: {last}")


# ── Runner ───────────────────────────────────────────────────────────────────

def run(tests_dir: Path, repo_root: Path, endpoint: str, db: str,
        token: str, dry_run: bool, wait_s: int) -> int:
    """Discover manifests, compose queries per case, and assert expected outcomes.

    For every ``*/test.json`` manifest, loads the referenced rule and, for each
    case, loads the fixture, composes the shadowed query, and (unless --dry-run)
    runs it. A case passes when the row count matches the expectation: >0 rows for
    ``expect: match``, exactly 0 for ``expect: no_match``.

    Args:
        tests_dir: Directory containing per-rule test folders.
        repo_root: Root used to resolve each manifest's ``rule`` path.
        endpoint, db, token: Kusto connection details.
        dry_run: If True, print the composed KQL and skip the engine entirely.
        wait_s: Seconds to wait for the engine before the first live query.

    Returns:
        int: 0 on all-pass (or any successful dry-run), 1 on any failure or if no
        manifests were found.
    """
    # Each rule under test lives in its own folder with a test.json manifest.
    manifests = sorted(tests_dir.glob("*/test.json"))
    if not manifests:
        print(f"ERROR: no test manifests found under {tests_dir}", file=sys.stderr)
        return 1

    if not dry_run:
        # Live run needs requests and a reachable, ready engine. --dry-run skips
        # both so it works with zero dependencies and no container.
        if requests is None:
            print("ERROR: `requests` is required for live runs (pip install requests)", file=sys.stderr)
            return 1
        wait_for_engine(endpoint, db, token, wait_s)

    passed = failed = 0
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text())
        # The rule path is repo-relative; the fixtures are relative to the manifest.
        rule_text = (repo_root / manifest["rule"]).read_text()
        for case in manifest["cases"]:
            rows = json.loads((manifest_path.parent / case["fixture"]).read_text())
            query = compose_query(manifest, rule_text, rows)
            # A readable label like "privileged-pod :: fires on privileged pod".
            label = f'{manifest_path.parent.name} :: {case["name"]}'

            if dry_run:
                # Show exactly what would run — invaluable for debugging a rule or
                # fixture without spinning up the emulator.
                print(f"\n===== {label} (expect {case['expect']}) =====\n{query}")
                continue

            count = run_count(endpoint, db, query, token)
            want_match = case["expect"] == "match"
            # match -> we need at least one hit; no_match -> we need zero hits.
            ok = (count > 0) if want_match else (count == 0)
            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {label} — expected {case['expect']}, got {count} row(s)")
            if ok:
                passed += 1
            else:
                failed += 1

    if dry_run:
        # Dry runs only print; there's nothing to pass/fail, so always succeed.
        return 0
    print(f"\nResults: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def main() -> int:
    """CLI entry point: parse args (with env-var defaults) and dispatch to run().

    Every connection option falls back to an environment variable so the same
    invocation works locally and in CI without repeating flags. Returns run()'s
    exit code.
    """
    ap = argparse.ArgumentParser(description="Tier 1 KQL detection logic tester")
    ap.add_argument("--tests-dir", default="detections/kql/tests")
    ap.add_argument("--repo-root", default=".")
    # Endpoint/db/token default from the environment, then to emulator-friendly
    # values, so `KUSTO_ENDPOINT=... python kql_test.py` just works.
    ap.add_argument("--endpoint", default=os.environ.get("KUSTO_ENDPOINT", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("KUSTO_DB", "NetDefaultDB"))
    ap.add_argument("--token", default=os.environ.get("KUSTO_TOKEN", ""))
    ap.add_argument("--dry-run", action="store_true", help="print composed KQL, do not contact an engine")
    ap.add_argument("--wait-seconds", type=int, default=120, help="how long to wait for the engine")
    args = ap.parse_args()
    return run(Path(args.tests_dir), Path(args.repo_root), args.endpoint,
               args.db, args.token, args.dry_run, args.wait_seconds)


if __name__ == "__main__":
    # Surface run()'s return value as the process exit code for CI.
    sys.exit(main())
