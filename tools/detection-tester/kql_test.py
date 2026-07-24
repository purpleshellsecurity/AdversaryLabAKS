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

A test manifest (detections/kql/tests/<rule>/test.json) declares the rule path,
the table name, the column schema, and the cases (fixture -> expected match/no_match).

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
    import requests
except ImportError:
    requests = None  # only needed for live runs, not --dry-run


# ── KQL literal rendering ────────────────────────────────────────────────────

def kql_string(value: str) -> str:
    """Render a Python str as a KQL double-quoted string literal."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def kql_value(value, col_type: str) -> str:
    """Render one fixture value as a KQL scalar literal for a datatable."""
    if col_type == "string":
        return kql_string("" if value is None else value)
    if col_type == "dynamic":
        # json.dumps output is a valid KQL dynamic literal; transport (requests
        # json=) re-escapes the inner quotes correctly over the wire.
        return f"dynamic({json.dumps(value, separators=(',', ':'))})"
    if col_type in ("int", "long", "real", "bool", "boolean"):
        return json.dumps(value)
    raise ValueError(f"Unsupported column type: {col_type}")


def build_datatable(table: str, schema: list, rows: list, inject_time: bool) -> str:
    """Build `let <table> = datatable(...)[ ... ] | extend TimeGenerated = now();`"""
    header = ", ".join(f'{c["name"]}:{c["type"]}' for c in schema)
    rendered_rows = []
    for row in rows:
        cells = [kql_value(row.get(c["name"]), c["type"]) for c in schema]
        rendered_rows.append("    " + ", ".join(cells))
    body = ",\n".join(rendered_rows)
    stmt = f"let {table} = datatable({header})\n[\n{body}\n]"
    if inject_time:
        stmt += "\n| extend TimeGenerated = now()"
    return stmt + ";"


def compose_query(manifest: dict, rule_text: str, rows: list) -> str:
    datatable = build_datatable(
        manifest["table"], manifest["schema"], rows,
        manifest.get("inject_timegenerated", True),
    )
    # rule_text already begins with the (now shadowed) table name.
    return f"{datatable}\n{rule_text.strip()}\n| count"


# ── Kusto engine (emulator) ──────────────────────────────────────────────────

def run_count(endpoint: str, db: str, query: str, token: str | None) -> int:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(
        f"{endpoint.rstrip('/')}/v1/rest/query",
        json={"db": db, "csl": query},
        headers=headers, timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Kusto query failed ({resp.status_code}): {resp.text[:500]}")
    tables = resp.json().get("Tables")
    if not tables or not tables[0]["Rows"]:
        raise RuntimeError(f"Unexpected Kusto response: {resp.text[:500]}")
    return int(tables[0]["Rows"][0][0])


def wait_for_engine(endpoint: str, db: str, token: str, timeout_s: int) -> None:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            if run_count(endpoint, db, "print n=1 | count", token) == 1:
                print(f"[*] Kusto engine ready at {endpoint}")
                return
        except Exception as e:  # noqa: BLE001 — readiness poll, any error = not ready yet
            last = e
        time.sleep(3)
    raise RuntimeError(f"Kusto engine not ready after {timeout_s}s: {last}")


# ── Runner ───────────────────────────────────────────────────────────────────

def run(tests_dir: Path, repo_root: Path, endpoint: str, db: str,
        token: str, dry_run: bool, wait_s: int) -> int:
    manifests = sorted(tests_dir.glob("*/test.json"))
    if not manifests:
        print(f"ERROR: no test manifests found under {tests_dir}", file=sys.stderr)
        return 1

    if not dry_run:
        if requests is None:
            print("ERROR: `requests` is required for live runs (pip install requests)", file=sys.stderr)
            return 1
        wait_for_engine(endpoint, db, token, wait_s)

    passed = failed = 0
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text())
        rule_text = (repo_root / manifest["rule"]).read_text()
        for case in manifest["cases"]:
            rows = json.loads((manifest_path.parent / case["fixture"]).read_text())
            query = compose_query(manifest, rule_text, rows)
            label = f'{manifest_path.parent.name} :: {case["name"]}'

            if dry_run:
                print(f"\n===== {label} (expect {case['expect']}) =====\n{query}")
                continue

            count = run_count(endpoint, db, query, token)
            want_match = case["expect"] == "match"
            ok = (count > 0) if want_match else (count == 0)
            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {label} — expected {case['expect']}, got {count} row(s)")
            if ok:
                passed += 1
            else:
                failed += 1

    if dry_run:
        return 0
    print(f"\nResults: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 1 KQL detection logic tester")
    ap.add_argument("--tests-dir", default="detections/kql/tests")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--endpoint", default=os.environ.get("KUSTO_ENDPOINT", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("KUSTO_DB", "NetDefaultDB"))
    ap.add_argument("--token", default=os.environ.get("KUSTO_TOKEN", ""))
    ap.add_argument("--dry-run", action="store_true", help="print composed KQL, do not contact an engine")
    ap.add_argument("--wait-seconds", type=int, default=120, help="how long to wait for the engine")
    args = ap.parse_args()
    return run(Path(args.tests_dir), Path(args.repo_root), args.endpoint,
               args.db, args.token, args.dry_run, args.wait_seconds)


if __name__ == "__main__":
    sys.exit(main())
