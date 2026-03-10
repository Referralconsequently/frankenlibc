#!/usr/bin/env bash
# check_runtime_math_hji_viability_proofs.sh — Prove the live discrete HJI artifact and runtime wiring.
#
# Bead: bd-249m.6
#
# This gate runs a dedicated harness subcommand which:
# - loads the checked-in HJI viability JSON artifact,
# - checks the checked-in convergence SVG against the live solver output,
# - verifies the runtime_math integration markers for HJI observe/snapshot wiring,
# - emits structured JSONL logs and a machine-readable JSON report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_hji_viability_proofs.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_hji_viability_proofs.report.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- runtime-math-hji-viability-proofs \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}"

echo "OK: runtime_math HJI viability proofs emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
