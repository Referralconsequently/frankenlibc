#!/usr/bin/env bash
# check_errno_edge_report.sh — Guard canonical errno + edge-case conformance artifact.
#
# Validates:
# 1. Canonical `tests/conformance/errno_edge_report.v1.json` exactly matches
#    harness-generated output from support_matrix + fixture packs + conformance matrix.
# 2. Structured JSONL logs are emitted with per-scenario errno triage fields.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPPORT_MATRIX="${ROOT}/support_matrix.json"
FIXTURE_DIR="${ROOT}/tests/conformance/fixtures"
CONFORMANCE_MATRIX="${ROOT}/tests/conformance/conformance_matrix.v1.json"
CANONICAL_REPORT="${ROOT}/tests/conformance/errno_edge_report.v1.json"
CURRENT_REPORT="${ROOT}/target/conformance/errno_edge_report.current.v1.json"
LOG_FILE="${ROOT}/target/conformance/errno_edge_report.log.jsonl"
TRACE_ID="bd-2tq.5-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${ROOT}/target/conformance"

for path in \
    "$SUPPORT_MATRIX" \
    "$CONFORMANCE_MATRIX" \
    "$CANONICAL_REPORT"
do
    if [[ ! -f "$path" ]]; then
        echo "ERROR: required file missing: $path" >&2
        exit 1
    fi
done

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo "ERROR: required fixture directory missing: $FIXTURE_DIR" >&2
    exit 1
fi

echo "=== Errno Edge Report Gate (bd-2tq.5) ==="
echo ""
echo "--- Step 1: generate current errno-edge report ---"
cargo run --quiet -p frankenlibc-harness --bin harness -- \
    errno-edge-report \
    --support-matrix "$SUPPORT_MATRIX" \
    --fixture "$FIXTURE_DIR" \
    --conformance-matrix "$CONFORMANCE_MATRIX" \
    --output "$CURRENT_REPORT"
echo "PASS: generated current errno-edge report at $CURRENT_REPORT"
echo ""

echo "--- Step 2: compare canonical artifact and emit errno triage log ---"
python3 - "$CANONICAL_REPORT" "$CURRENT_REPORT" "$LOG_FILE" "$TRACE_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone

canonical_path, current_path, log_path, trace_id = sys.argv[1:5]

with open(canonical_path, "r", encoding="utf-8") as fh:
    canonical = json.load(fh)
with open(current_path, "r", encoding="utf-8") as fh:
    current = json.load(fh)

if canonical != current:
    print("ERROR: canonical errno edge report drift detected")
    canon_summary = canonical.get("summary", {})
    current_summary = current.get("summary", {})
    for key in sorted(set(canon_summary) | set(current_summary)):
        if canon_summary.get(key) != current_summary.get(key):
            print(
                f"  summary.{key}: canonical={canon_summary.get(key)!r} current={current_summary.get(key)!r}"
            )
    if len(canonical.get("rows", [])) != len(current.get("rows", [])):
        print(
            f"  rows length: canonical={len(canonical.get('rows', []))} current={len(current.get('rows', []))}"
        )
    canonical_rows = canonical.get("rows", [])
    current_rows = current.get("rows", [])
    for idx, (canon_row, current_row) in enumerate(zip(canonical_rows, current_rows)):
        if canon_row != current_row:
            print(
                f"  first differing row[{idx}]:"
                f" canonical={canon_row.get('symbol')}::{canon_row.get('case_id')}::{canon_row.get('runtime_mode')}"
                f" current={current_row.get('symbol')}::{current_row.get('case_id')}::{current_row.get('runtime_mode')}"
            )
            break
    raise SystemExit(1)

events = []
timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
for row in current.get("rows", []):
    events.append(
        {
            "timestamp": timestamp,
            "trace_id": trace_id,
            "bead_id": "bd-2tq.5",
            "event": "errno_edge_case",
            "scenario_id": row["case_id"],
            "runtime_mode": row["runtime_mode"],
            "symbol": row["symbol"],
            "symbol_family": row["symbol_family"],
            "expected_errno": row["expected_errno"],
            "actual_errno": row.get("actual_errno"),
            "diff_ref": row["diff_ref"],
            "failure_kind": row["failure_kind"],
            "status": row["status"],
        }
    )

with open(log_path, "w", encoding="utf-8") as fh:
    for event in events:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")

summary = current.get("summary", {})
print("PASS: canonical errno edge artifact matches harness output")
print(
    "Summary:"
    f" tracked_symbols={summary.get('tracked_symbols')}"
    f" total_edge_cases={summary.get('total_edge_cases')}"
    f" errno_cases={summary.get('errno_cases')}"
    f" failing_edge_cases={summary.get('failing_edge_cases')}"
    f" execution_error_cases={summary.get('execution_error_cases')}"
)
print(f"Structured log written to: {log_path}")
PY

echo ""
echo "check_errno_edge_report: PASS"
