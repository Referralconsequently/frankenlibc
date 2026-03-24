#!/usr/bin/env bash
# check_setjmp_semantics_contract.sh — CI/evidence gate for bd-2xp3
#
# Validates clean-room setjmp semantics contract artifact consistency against
# support/stub/waiver/fixture sources and emits structured evidence logs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPPORT="${ROOT}/support_matrix.json"
ARTIFACT="${ROOT}/tests/conformance/setjmp_semantics_contract.v1.json"
STUB_CENSUS="${ROOT}/tests/conformance/stub_census.json"
WAIVER_POLICY="${ROOT}/tests/conformance/stub_regression_waiver_policy.v1.json"
FIXTURE="${ROOT}/tests/conformance/fixtures/setjmp_ops.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/setjmp_semantics_contract.report.json"
LOG="${OUT_DIR}/setjmp_semantics_contract.log.jsonl"
CVE_DIR="${ROOT}/tests/cve_arena/results/bd-2xp3"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"
RUN_ID="setjmp-contract-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

for required in "${SUPPORT}" "${ARTIFACT}" "${STUB_CENSUS}" "${WAIVER_POLICY}" "${FIXTURE}"; do
  if [[ ! -f "${required}" ]]; then
    echo "FAIL: missing required input ${required}" >&2
    exit 1
  fi
done

python3 - "${ROOT}" "${SUPPORT}" "${ARTIFACT}" "${STUB_CENSUS}" "${WAIVER_POLICY}" "${FIXTURE}" "${REPORT}" "${LOG}" "${CVE_TRACE}" "${CVE_INDEX}" "${RUN_ID}" <<'PY'
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

(
    root_raw,
    support_raw,
    artifact_raw,
    stub_census_raw,
    waiver_policy_raw,
    fixture_raw,
    report_raw,
    log_raw,
    cve_trace_raw,
    cve_index_raw,
    run_id,
) = sys.argv[1:12]

root = Path(root_raw)
support_path = Path(support_raw)
artifact_path = Path(artifact_raw)
stub_census_path = Path(stub_census_raw)
waiver_policy_path = Path(waiver_policy_raw)
fixture_path = Path(fixture_raw)
report_path = Path(report_raw)
log_path = Path(log_raw)
cve_trace_path = Path(cve_trace_raw)
cve_index_path = Path(cve_index_raw)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        fail(f"unable to parse JSON {path}: {exc}")


support = load_json(support_path)
artifact = load_json(artifact_path)
stub_census = load_json(stub_census_path)
waiver_policy = load_json(waiver_policy_path)
fixture = load_json(fixture_path)

if artifact.get("schema_version") != "v1":
    fail("artifact schema_version must be v1")
if artifact.get("bead") != "bd-2xp3":
    fail("artifact bead must be bd-2xp3")

symbols = artifact.get("symbols", {})
if not isinstance(symbols, dict):
    fail("artifact symbols must be an object")

deferred_symbols = symbols.get("phase1_deferred", [])
phase2_symbols = symbols.get("phase2_target", [])
visible_now = symbols.get("support_matrix_visible_now", [])

if not isinstance(deferred_symbols, list):
    fail("symbols.phase1_deferred must be an array")
if len(deferred_symbols) != len(set(deferred_symbols)):
    fail("symbols.phase1_deferred contains duplicates")
if len(phase2_symbols) != len(set(phase2_symbols)):
    fail("symbols.phase2_target contains duplicates")
if len(visible_now) != len(set(visible_now)):
    fail("symbols.support_matrix_visible_now contains duplicates")

required_deferred = {"setjmp", "longjmp", "_setjmp", "_longjmp", "sigsetjmp", "siglongjmp"}
missing_required = sorted(required_deferred - (set(deferred_symbols) | set(visible_now)))
if missing_required:
    fail(f"setjmp symbol plan missing required symbols: {missing_required}")
overlap = sorted(set(deferred_symbols) & set(visible_now))
if overlap:
    fail(f"symbols.phase1_deferred and symbols.support_matrix_visible_now overlap: {overlap}")

matrix_rows = artifact.get("abi_semantics_matrix", [])
if not isinstance(matrix_rows, list) or not matrix_rows:
    fail("abi_semantics_matrix must be non-empty array")

matrix_symbols = []
for row in matrix_rows:
    if not isinstance(row, dict):
        fail("abi_semantics_matrix rows must be objects")
    symbol = str(row.get("symbol", "")).strip()
    if not symbol:
        fail("abi_semantics_matrix row missing symbol")
    matrix_symbols.append(symbol)
    expected_status = (
        "DeferredNotExported" if symbol in deferred_symbols else "ImplementedShadowDebt"
    )
    if str(row.get("support_matrix_status", "")) != expected_status:
        fail(
            f"abi_semantics_matrix.{symbol}.support_matrix_status must be {expected_status}"
        )
    for key in ["strict_semantics", "hardened_semantics", "signal_mask_semantics"]:
        if not str(row.get(key, "")).strip():
            fail(f"abi_semantics_matrix.{symbol}.{key} must be non-empty")

if len(matrix_symbols) != len(set(matrix_symbols)):
    fail("abi_semantics_matrix contains duplicate symbols")
expected_matrix_symbols = set(deferred_symbols) | set(visible_now)
if set(matrix_symbols) != expected_matrix_symbols:
    missing = sorted(expected_matrix_symbols - set(matrix_symbols))
    extra = sorted(set(matrix_symbols) - expected_matrix_symbols)
    fail(f"abi_semantics_matrix coverage mismatch missing={missing} extra={extra}")

signal_contract = artifact.get("signal_mask_contract", {})
if not isinstance(signal_contract, dict):
    fail("signal_mask_contract must be object")
rules = signal_contract.get("pairing_rules", [])
if not isinstance(rules, list) or len(rules) < 4:
    fail("signal_mask_contract.pairing_rules must contain >= 4 rules")
if not str(signal_contract.get("phase1_enforcement", "")).strip():
    fail("signal_mask_contract.phase1_enforcement must be non-empty")

notes = artifact.get("support_matrix_caveats", {}).get("user_visible_notes", [])
if not isinstance(notes, list) or len(notes) < 2:
    fail("support_matrix_caveats.user_visible_notes must contain >= 2 notes")

summary = artifact.get("summary", {})
if int(summary.get("total_symbols", -1)) != len(expected_matrix_symbols):
    fail("summary.total_symbols mismatch")
if int(summary.get("deferred_symbols", -1)) != len(deferred_symbols):
    fail("summary.deferred_symbols mismatch")
if int(summary.get("phase2_target_symbols", -1)) != len(phase2_symbols):
    fail("summary.phase2_target_symbols mismatch")
if int(summary.get("required_signal_mask_rules", -1)) != len(rules):
    fail("summary.required_signal_mask_rules mismatch")

support_symbols = {
    str(row.get("symbol"))
    for row in support.get("symbols", [])
    if isinstance(row, dict) and row.get("symbol") is not None
}
for symbol in deferred_symbols:
    if symbol in support_symbols:
        fail(f"deferred symbol unexpectedly present in support_matrix: {symbol}")
for symbol in visible_now:
    if symbol not in support_symbols:
        fail(f"support_matrix_visible_now symbol missing from support_matrix: {symbol}")

stub_rows = {
    str(row.get("symbol")): row
    for row in stub_census.get("stubs", [])
    if isinstance(row, dict)
}
for symbol in deferred_symbols:
    row = stub_rows.get(symbol)
    if row is None:
        fail(f"stub_census missing deferred symbol {symbol}")
    if row.get("call_family") != "setjmp":
        fail(f"stub_census {symbol} must have call_family=setjmp")
    if row.get("stub_type") != "todo!":
        fail(f"stub_census {symbol} must remain a todo! placeholder")

visible_stub_overlap = sorted(set(visible_now) & set(stub_rows))
if visible_stub_overlap:
    fail(
        "stub_census still lists phase-1 exported setjmp symbols: "
        f"{visible_stub_overlap}"
    )

waivers = waiver_policy.get("waivers", [])
if not isinstance(waivers, list):
    fail("waiver policy waivers must be an array")
forbidden_scopes = waiver_policy.get("policy", {}).get(
    "forbidden_without_waiver", {}
).get("source_debt_scopes", [])
if "exported_shadow_debt" not in forbidden_scopes:
    fail("waiver policy must recognize exported_shadow_debt scope")
matrix_statuses = waiver_policy.get("policy", {}).get(
    "forbidden_without_waiver", {}
).get("matrix_statuses", [])
if "Stub" not in matrix_statuses:
    fail("waiver policy must continue gating Stub matrix statuses")
owner_bead = artifact.get("support_matrix_caveats", {}).get("owner_bead")
if owner_bead != "bd-2ry":
    fail("support_matrix_caveats.owner_bead must be bd-2ry")
waiver_symbols = artifact.get("support_matrix_caveats", {}).get(
    "waiver_policy_symbols", []
)
for symbol in ["setjmp", "longjmp"]:
    if symbol not in waiver_symbols:
        fail(f"support_matrix_caveats.waiver_policy_symbols missing {symbol}")

cases = fixture.get("cases", [])
if not isinstance(cases, list) or not cases:
    fail("fixture cases must be non-empty")
case_functions = {str(case.get("function")) for case in cases if isinstance(case, dict)}
for symbol in ["setjmp", "longjmp", "_setjmp"]:
    if symbol not in case_functions:
        fail(f"fixture missing required function coverage: {symbol}")

modes = {str(case.get("mode")) for case in cases if isinstance(case, dict)}
if "strict" not in modes or "hardened" not in modes:
    fail("fixture must contain both strict and hardened cases")

has_savemask_case = any(
    isinstance(case, dict)
    and isinstance(case.get("inputs"), dict)
    and "savemask" in case["inputs"]
    for case in cases
)
if not has_savemask_case:
    fail("fixture must include at least one savemask case")

report = {
    "schema_version": "v1",
    "bead": "bd-2xp3",
    "checks": {
        "artifact_schema": "pass",
        "semantics_matrix": "pass",
        "signal_mask_contract": "pass",
        "support_matrix_alignment": "pass",
        "stub_and_waiver_alignment": "pass",
        "fixture_alignment": "pass",
        "summary_consistent": "pass",
    },
    "summary": {
        "deferred_symbol_count": len(deferred_symbols),
        "phase2_target_count": len(phase2_symbols),
        "matrix_row_count": len(matrix_rows),
        "signal_mask_rule_count": len(rules),
        "fixture_case_count": len(cases),
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

now = datetime.now(timezone.utc)
timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
trace_id = f"bd-2xp3::{run_id}::001"

event = {
    "timestamp": timestamp,
    "trace_id": trace_id,
    "level": "info",
    "event": "gate_result",
    "bead_id": "bd-2xp3",
    "stream": "conformance",
    "gate": "check_setjmp_semantics_contract",
    "mode": "strict",
    "api_family": "setjmp",
    "symbol": "setjmp_contract",
    "outcome": "pass",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [
        "tests/conformance/setjmp_semantics_contract.v1.json",
        "target/conformance/setjmp_semantics_contract.report.json",
        "target/conformance/setjmp_semantics_contract.log.jsonl",
    ],
    "details": {
        "deferred_symbols": deferred_symbols,
        "phase2_target": phase2_symbols,
        "required_signal_mask_rules": len(rules),
    },
}

encoded_event = json.dumps(event, separators=(",", ":"))
log_path.write_text(encoded_event + "\n", encoding="utf-8")
cve_trace_path.write_text(encoded_event + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def rel_path(path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()

artifacts = [artifact_path, report_path, log_path, cve_trace_path]
cve_index = {
    "index_version": 1,
    "bead_id": "bd-2xp3",
    "generated_utc": timestamp,
    "artifacts": [
        {
            "path": rel_path(path),
            "kind": "jsonl" if path.suffix == ".jsonl" else "json",
            "sha256": sha256(path),
        }
        for path in artifacts
    ],
}
cve_index_path.write_text(json.dumps(cve_index, indent=2) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2))
PY

echo "PASS: setjmp semantics contract gate"
