#!/usr/bin/env bash
# check_posix_obligation_matrix.sh — Guard canonical POSIX obligation traceability artifact.
#
# Validates:
# 1. Canonical `tests/conformance/posix_obligation_matrix.v1.json` exactly matches
#    harness-generated output from support_matrix + fixture packs + conformance matrix.
# 2. Structured JSONL logs are emitted with per-obligation and per-gap traceability fields.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPPORT_MATRIX="${ROOT}/support_matrix.json"
FIXTURE_DIR="${ROOT}/tests/conformance/fixtures"
CONFORMANCE_MATRIX="${ROOT}/tests/conformance/conformance_matrix.v1.json"
C_FIXTURE_SPEC="${ROOT}/tests/conformance/c_fixture_spec.json"
CANONICAL_REPORT="${ROOT}/tests/conformance/posix_obligation_matrix.v1.json"
CURRENT_REPORT="${ROOT}/target/conformance/posix_obligation_matrix.current.v1.json"
LOG_FILE="${ROOT}/target/conformance/posix_obligation_matrix.log.jsonl"
TRACE_ID="bd-2tq.4-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${ROOT}/target/conformance"

for path in \
    "$SUPPORT_MATRIX" \
    "$CONFORMANCE_MATRIX" \
    "$C_FIXTURE_SPEC" \
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

echo "=== POSIX Obligation Matrix Gate (bd-2tq.4) ==="
echo ""
echo "--- Step 1: generate current obligation report ---"
cargo run --quiet -p frankenlibc-harness --bin harness -- \
    posix-obligation-report \
    --support-matrix "$SUPPORT_MATRIX" \
    --fixture "$FIXTURE_DIR" \
    --conformance-matrix "$CONFORMANCE_MATRIX" \
    --c-fixture-spec "$C_FIXTURE_SPEC" \
    --output "$CURRENT_REPORT"
echo "PASS: generated current obligation report at $CURRENT_REPORT"
echo ""

echo "--- Step 2: compare canonical artifact and emit traceability log ---"
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
    print("ERROR: canonical POSIX obligation matrix drift detected")
    canon_summary = canonical.get("summary", {})
    current_summary = current.get("summary", {})
    for key in sorted(set(canon_summary) | set(current_summary)):
        if canon_summary.get(key) != current_summary.get(key):
            print(
                f"  summary.{key}: canonical={canon_summary.get(key)!r} current={current_summary.get(key)!r}"
            )
    if len(canonical.get("obligations", [])) != len(current.get("obligations", [])):
        print(
            f"  obligations length: canonical={len(canonical.get('obligations', []))} current={len(current.get('obligations', []))}"
        )
    if len(canonical.get("gaps", [])) != len(current.get("gaps", [])):
        print(
            f"  gaps length: canonical={len(canonical.get('gaps', []))} current={len(current.get('gaps', []))}"
        )
    raise SystemExit(1)

events = []
timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
for row in current.get("obligations", []):
    events.append(
        {
            "timestamp": timestamp,
            "trace_id": trace_id,
            "bead_id": "bd-2tq.4",
            "event": "posix_obligation",
            "posix_ref": row["posix_ref"],
            "symbol": row["symbol"],
            "symbol_family": row["symbol_family"],
            "coverage_state": row["coverage_state"],
            "test_refs": row["test_refs"],
            "artifact_refs": row["artifact_refs"],
            "obligation_kinds": row["obligation_kinds"],
        }
    )

for gap in current.get("gaps", []):
    events.append(
        {
            "timestamp": timestamp,
            "trace_id": trace_id,
            "bead_id": "bd-2tq.4",
            "event": "posix_gap",
            "posix_ref": gap.get("mapped_posix_refs", []),
            "symbol": gap["symbol"],
            "symbol_family": gap["symbol_family"],
            "coverage_state": "gap",
            "test_refs": gap["test_refs"],
            "artifact_refs": [canonical_path, current_path],
            "gap_reasons": gap["gap_reasons"],
        }
    )

with open(log_path, "w", encoding="utf-8") as fh:
    for event in events:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")

summary = current.get("summary", {})
print("PASS: canonical POSIX obligation artifact matches harness output")
print(
    "Summary:"
    f" tracked_symbols={summary.get('tracked_symbols')}"
    f" obligations={summary.get('total_obligations')}"
    f" covered={summary.get('covered_obligations')}"
    f" mapped_without_execution={summary.get('mapped_without_execution')}"
    f" execution_failures={summary.get('obligations_with_execution_failures')}"
)
print(f"Structured log written to: {log_path}")
PY

echo ""
echo "check_posix_obligation_matrix: PASS"
