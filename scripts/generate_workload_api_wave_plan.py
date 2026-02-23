#!/usr/bin/env python3
"""Generate workload-ranked top-N API enablement wave plan (bd-3mam, bd-1x3.2 uplift)."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PRIORITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}

BASE_BEAD_ID = "bd-3mam"
UPLIFT_BEAD_ID = "bd-1x3.2"

SEVERITY_WEIGHTS = {
    "Stub": 3.0,
    "GlibcCallThrough:strict_hotpath": 2.0,
    "GlibcCallThrough:hardened_hotpath": 1.5,
    "GlibcCallThrough:coldpath": 1.0,
}

MODULE_BEAD_OVERRIDES = {
    "stdio_abi": ["bd-24ug"],
    "pthread_abi": ["bd-z84", "bd-yos", "bd-rth1", "bd-1f35", "bd-3hud"],
    "dlfcn_abi": ["bd-3rn", "bd-33zg"],
}

INTEGRATION_HOOKS = {
    "setjmp": ["bd-1gh"],
    "tls": ["bd-rth1", "bd-yos"],
    "threading": ["bd-z84", "bd-yos", "bd-3hud", "bd-1f35"],
    "hard_parts": ["bd-24ug", "bd-3rn", "bd-66s", "bd-3pe"],
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def as_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def severity_weight(status: str, perf_class: str) -> float:
    if status == "Stub":
        return SEVERITY_WEIGHTS["Stub"]
    return SEVERITY_WEIGHTS.get(f"{status}:{perf_class}", 1.0)


def collect_fixture_call_frequency(
    fixtures_dir: Path, candidate_symbols: set[str]
) -> Counter[str]:
    counter: Counter[str] = Counter()
    if not fixtures_dir.exists():
        return counter
    for fixture_path in sorted(fixtures_dir.glob("*.json")):
        fixture = load_json(fixture_path)
        if not isinstance(fixture, dict):
            continue
        for case in as_dict_list(fixture.get("cases", [])):
            symbol = str(case.get("function", ""))
            if symbol in candidate_symbols:
                counter[symbol] += 1
    return counter


def build_stub_debt_index(stub_debt_census: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in as_dict_list(stub_debt_census.get("risk_ranked_debt", [])):
        symbol = str(row.get("symbol", ""))
        if not symbol:
            continue
        index[symbol] = {
            "risk_score": parse_int(row.get("risk_score", 0)),
            "risk_tier": str(row.get("risk_tier", "low")),
            "debt_scope": str(row.get("debt_scope", "unknown")),
        }
    return index


def build_waiver_index(waiver_policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in as_dict_list(waiver_policy.get("waivers", [])):
        symbol = str(row.get("symbol", ""))
        if not symbol:
            continue
        index[symbol] = {
            "scope": str(row.get("scope", "")),
            "risk_tier": str(row.get("risk_tier", "")),
            "reason": str(row.get("reason", "")),
            "owner_bead": str(row.get("owner_bead", "")),
            "approved_by": str(row.get("approved_by", "")),
            "expires_utc": str(row.get("expires_utc", "")),
        }
    return index


def build_plan(
    workload_matrix: dict[str, Any],
    support_matrix: dict[str, Any],
    callthrough_census: dict[str, Any],
    stub_debt_census: dict[str, Any],
    waiver_policy: dict[str, Any],
    fixtures_dir: Path,
    top_n: int,
    input_manifest: dict[str, Any],
) -> dict[str, Any]:
    symbols = as_dict_list(support_matrix.get("symbols", []))
    symbol_module_lookup = {
        str(row.get("symbol", "")): str(row.get("module", ""))
        for row in symbols
        if str(row.get("symbol", "")) and str(row.get("module", ""))
    }
    candidates = [
        row
        for row in symbols
        if row.get("status") in {"GlibcCallThrough", "Stub"}
    ]
    candidate_symbols = {
        str(row.get("symbol", ""))
        for row in candidates
        if str(row.get("symbol", ""))
    }
    fixture_call_frequency = collect_fixture_call_frequency(fixtures_dir, candidate_symbols)
    debt_index = build_stub_debt_index(stub_debt_census)
    waiver_index = build_waiver_index(waiver_policy)

    workloads = as_dict_list(workload_matrix.get("workloads", []))
    module_workload_ids: dict[str, set[str]] = defaultdict(set)
    module_weighted_impact: dict[str, float] = defaultdict(float)
    module_critical_symbols: dict[str, Counter[str]] = defaultdict(Counter)

    for index, workload in enumerate(workloads, start=1):
        w_id = str(workload.get("id", "")).strip() or f"workload-{index}"
        weight = PRIORITY_WEIGHTS.get(str(workload.get("priority_impact", "medium")).lower(), 1.0)
        blocked_modules = list(dict.fromkeys(as_str_list(workload.get("blocked_by", []))))
        critical_symbols = list(
            dict.fromkeys(as_str_list(workload.get("critical_symbols", [])))
        )
        for module in blocked_modules:
            module_workload_ids[module].add(w_id)
            module_weighted_impact[module] += weight
            for symbol in critical_symbols:
                if symbol_module_lookup.get(symbol) == module:
                    module_critical_symbols[module][symbol] += 1

    wave_rows = as_dict_list(callthrough_census.get("decommission_waves", []))
    symbol_to_wave: dict[str, str] = {}
    for wave in wave_rows:
        wave_id = str(wave.get("wave_id"))
        if not wave_id:
            continue
        for symbol in as_str_list(wave.get("symbols", [])):
            symbol_to_wave[str(symbol)] = wave_id

    milestone_rows = as_dict_list(
        workload_matrix.get("milestone_mapping", {}).get("milestones", [])
    )
    module_to_beads: dict[str, list[str]] = defaultdict(list)
    for row in milestone_rows:
        bead = row.get("bead")
        if not bead:
            continue
        for module in as_str_list(row.get("unblocks_modules", [])):
            module_to_beads[str(module)].append(str(bead))

    for module, beads in MODULE_BEAD_OVERRIDES.items():
        merged = list(dict.fromkeys(module_to_beads.get(module, []) + beads))
        module_to_beads[module] = merged

    symbol_rows: list[dict[str, Any]] = []
    for row in candidates:
        symbol = str(row.get("symbol", "")).strip()
        module = str(row.get("module", "")).strip()
        if not symbol or not module:
            continue
        status = str(row.get("status", "")).strip()
        perf_class = str(row.get("perf_class", "")).strip()
        sev = severity_weight(status, perf_class)
        workload_weight = float(module_weighted_impact.get(module, 0.0))
        blocked_count = len(module_workload_ids.get(module, set()))
        critical_mentions = int(module_critical_symbols.get(module, Counter()).get(symbol, 0))
        fixture_calls = int(fixture_call_frequency.get(symbol, 0))
        call_frequency = fixture_calls + critical_mentions
        trace_weight = round(min(call_frequency, 50) / 10.0, 3)
        debt_row = debt_index.get(symbol, {})
        debt_risk_score = int(debt_row.get("risk_score", 0))
        debt_risk_weight = round(min(debt_risk_score, 200) / 50.0, 3)
        score = round(
            sev
            * (
                1.0
                + workload_weight
                + (0.5 * critical_mentions)
                + trace_weight
                + debt_risk_weight
            ),
            3,
        )
        waiver = waiver_index.get(symbol)

        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "status": status,
                "perf_class": perf_class,
                "severity_weight": sev,
                "blocked_workloads": blocked_count,
                "weighted_workload_impact": round(workload_weight, 3),
                "critical_symbol_mentions": critical_mentions,
                "fixture_call_frequency": fixture_calls,
                "call_frequency": call_frequency,
                "trace_weight": trace_weight,
                "stub_debt_risk_score": debt_risk_score,
                "stub_debt_risk_tier": str(debt_row.get("risk_tier", "low")),
                "debt_scope": str(debt_row.get("debt_scope", "unknown")),
                "debt_risk_weight": debt_risk_weight,
                "score": score,
                "wave_id": symbol_to_wave.get(symbol, "unplanned"),
                "recommended_beads": module_to_beads.get(module, []),
                "has_downgrade_waiver": waiver is not None,
                "downgrade_owner_bead": waiver.get("owner_bead") if waiver else None,
            }
        )

    symbol_rows.sort(key=lambda r: (-r["score"], r["module"], r["symbol"]))

    ranked_rows = []
    for rank, row in enumerate(symbol_rows, start=1):
        entry = dict(row)
        entry["rank"] = rank
        if entry["has_downgrade_waiver"]:
            entry["selected_wave"] = "downgrade-policy"
        elif rank <= 50:
            entry["selected_wave"] = "Top50"
        elif rank <= 200:
            entry["selected_wave"] = "Top200"
        else:
            entry["selected_wave"] = "Backlog"
        ranked_rows.append(entry)

    top_symbol_rows = ranked_rows[:top_n]
    effective_top_n = len(top_symbol_rows)

    module_scores: dict[str, dict[str, Any]] = {}
    for row in symbol_rows:
        module = row["module"]
        agg = module_scores.setdefault(
            module,
            {
                "module": module,
                "symbols_remaining": 0,
                "blocked_workloads": len(module_workload_ids.get(module, set())),
                "weighted_workload_impact": round(module_weighted_impact.get(module, 0.0), 3),
                "total_symbol_score": 0.0,
                "critical_symbol_hits": 0,
                "recommended_beads": module_to_beads.get(module, []),
            },
        )
        agg["symbols_remaining"] += 1
        agg["total_symbol_score"] = round(agg["total_symbol_score"] + row["score"], 3)
        agg["critical_symbol_hits"] += row["critical_symbol_mentions"]

    module_ranking = sorted(
        module_scores.values(),
        key=lambda r: (-r["total_symbol_score"], -r["blocked_workloads"], r["module"]),
    )
    for rank, row in enumerate(module_ranking, start=1):
        row["rank"] = rank

    wave_plan = []
    candidate_symbol_set = {r["symbol"] for r in symbol_rows}
    for wave in sorted(wave_rows, key=lambda w: parse_int(w.get("wave", 0), 0)):
        wave_id = str(wave.get("wave_id"))
        wave_symbols = [
            s for s in as_str_list(wave.get("symbols", [])) if s in candidate_symbol_set
        ]
        wave_symbol_set = set(wave_symbols)
        scored = [r for r in symbol_rows if r["symbol"] in wave_symbol_set]
        scored.sort(key=lambda r: (-r["score"], r["symbol"]))
        modules = sorted({r["module"] for r in scored})

        wave_plan.append(
            {
                "wave": int(wave.get("wave", 0)),
                "wave_id": wave_id,
                "title": wave.get("title"),
                "depends_on": sorted(as_str_list(wave.get("depends_on", []))),
                "modules": modules,
                "symbol_count": len(scored),
                "top_symbols": [r["symbol"] for r in scored[:10]],
                "avg_score": round(sum(r["score"] for r in scored) / max(len(scored), 1), 3),
                "max_score": round(max((r["score"] for r in scored), default=0.0), 3),
                "recommended_beads": sorted(
                    {
                        bead
                        for module in modules
                        for bead in module_to_beads.get(module, [])
                    }
                ),
                "success_criteria": [
                    "target module symbols no longer classified as GlibcCallThrough/Stub in support_matrix",
                    "replacement guard emits zero forbidden call-throughs for symbols in this wave",
                    "fixture/gate artifacts updated with deterministic logs",
                ],
            }
        )

    top_blocker = module_ranking[0]["module"] if module_ranking else None
    top50_rows = [row for row in ranked_rows if row["selected_wave"] == "Top50"]
    top200_rows = [
        row for row in ranked_rows if row["selected_wave"] in {"Top50", "Top200"}
    ]
    downgrade_rows = [
        {
            "symbol": row["symbol"],
            "module": row["module"],
            "status": row["status"],
            "rank": row["rank"],
            "reason": waiver_index[row["symbol"]]["reason"],
            "owner_bead": waiver_index[row["symbol"]]["owner_bead"],
            "approved_by": waiver_index[row["symbol"]]["approved_by"],
            "expires_utc": waiver_index[row["symbol"]]["expires_utc"],
            "risk_tier": waiver_index[row["symbol"]]["risk_tier"],
            "scope": waiver_index[row["symbol"]]["scope"],
        }
        for row in ranked_rows
        if row["symbol"] in waiver_index
    ]

    return {
        "schema_version": "v1",
        "bead": BASE_BEAD_ID,
        "uplift_bead": UPLIFT_BEAD_ID,
        "description": "Workload-ranked top-N API enablement wave plan from real workload blockers and support-matrix obligations.",
        "generated_utc": "2026-02-13T00:00:00Z",
        "inputs": input_manifest,
        "scoring": {
            "priority_weights": PRIORITY_WEIGHTS,
            "severity_weights": {
                "Stub": SEVERITY_WEIGHTS["Stub"],
                "GlibcCallThrough_strict_hotpath": SEVERITY_WEIGHTS["GlibcCallThrough:strict_hotpath"],
                "GlibcCallThrough_hardened_hotpath": SEVERITY_WEIGHTS["GlibcCallThrough:hardened_hotpath"],
                "GlibcCallThrough_coldpath": SEVERITY_WEIGHTS["GlibcCallThrough:coldpath"],
            },
            "formula": (
                "score = severity_weight * (1 + weighted_workload_impact + "
                "0.5 * critical_symbol_mentions + trace_weight + debt_risk_weight)"
            ),
        },
        "trace_weighting": {
            "call_frequency_sources": [
                "tests/conformance/fixtures/*.json cases[].function",
                "tests/conformance/workload_matrix.json workloads[].critical_symbols",
            ],
            "trace_weight_formula": "trace_weight = min(call_frequency, 50) / 10",
            "debt_risk_formula": "debt_risk_weight = min(stub_debt_risk_score, 200) / 50",
        },
        "module_ranking": module_ranking,
        "symbol_ranking_top_n": top_symbol_rows,
        "implementation_waves": {
            "top50": {
                "target_size": 50,
                "actual_size": len(top50_rows),
                "symbols": [row["symbol"] for row in top50_rows],
                "modules": sorted({row["module"] for row in top50_rows}),
                "recommended_beads": sorted(
                    {
                        bead
                        for row in top50_rows
                        for bead in row.get("recommended_beads", [])
                    }
                ),
            },
            "top200": {
                "target_size": 200,
                "actual_size": len(top200_rows),
                "symbols": [row["symbol"] for row in top200_rows],
                "modules": sorted({row["module"] for row in top200_rows}),
                "recommended_beads": sorted(
                    {
                        bead
                        for row in top200_rows
                        for bead in row.get("recommended_beads", [])
                    }
                ),
            },
        },
        "downgrade_policy": {
            "source_policy": "tests/conformance/stub_regression_waiver_policy.v1.json",
            "default_decision": str(
                waiver_policy.get("policy", {}).get("default_decision", "deny")
            ),
            "waived_symbols": downgrade_rows,
            "waived_symbol_count": len(downgrade_rows),
        },
        "wave_plan": wave_plan,
        "integration_hooks": INTEGRATION_HOOKS,
        "summary": {
            "top_n": effective_top_n,
            "candidate_symbols": len(symbol_rows),
            "module_count": len(module_ranking),
            "wave_count": len(wave_plan),
            "top_blocker_module": top_blocker,
            "top_symbol": top_symbol_rows[0]["symbol"] if top_symbol_rows else None,
            "baseline_unresolved_symbols": len(symbol_rows),
            "remaining_after_top_n": max(len(symbol_rows) - effective_top_n, 0),
            "top50_size": len(top50_rows),
            "top200_size": len(top200_rows),
            "downgrade_symbol_count": len(downgrade_rows),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workload-matrix",
        default="tests/conformance/workload_matrix.json",
        type=Path,
    )
    parser.add_argument("--support-matrix", default="support_matrix.json", type=Path)
    parser.add_argument(
        "--callthrough-census",
        default="tests/conformance/callthrough_census.v1.json",
        type=Path,
    )
    parser.add_argument(
        "--stub-debt-census",
        default="tests/conformance/stub_todo_debt_census.v1.json",
        type=Path,
    )
    parser.add_argument(
        "--waiver-policy",
        default="tests/conformance/stub_regression_waiver_policy.v1.json",
        type=Path,
    )
    parser.add_argument(
        "--fixtures-dir",
        default="tests/conformance/fixtures",
        type=Path,
    )
    parser.add_argument(
        "--output",
        default="tests/conformance/workload_api_wave_plan.v1.json",
        type=Path,
    )
    parser.add_argument("--top-n", default=200, type=int)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.top_n < 0:
        raise SystemExit("--top-n must be >= 0")

    workload_matrix = load_json(args.workload_matrix)
    support_matrix = load_json(args.support_matrix)
    callthrough_census = load_json(args.callthrough_census)
    stub_debt_census = load_json(args.stub_debt_census)
    waiver_policy = load_json(args.waiver_policy)
    fixtures_dir = args.fixtures_dir
    input_manifest = {
        "workload_matrix": {
            "path": str(args.workload_matrix),
            "sha256": sha256_file(args.workload_matrix),
        },
        "support_matrix": {
            "path": str(args.support_matrix),
            "sha256": sha256_file(args.support_matrix),
        },
        "callthrough_census": {
            "path": str(args.callthrough_census),
            "sha256": sha256_file(args.callthrough_census),
        },
        "stub_todo_debt_census": {
            "path": str(args.stub_debt_census),
            "sha256": sha256_file(args.stub_debt_census),
        },
        "stub_regression_waiver_policy": {
            "path": str(args.waiver_policy),
            "sha256": sha256_file(args.waiver_policy),
        },
        "trace_fixtures_dir": {
            "path": str(fixtures_dir),
            "fixture_count": len(list(sorted(fixtures_dir.glob("*.json")))),
        },
    }

    plan = build_plan(
        workload_matrix=workload_matrix,
        support_matrix=support_matrix,
        callthrough_census=callthrough_census,
        stub_debt_census=stub_debt_census,
        waiver_policy=waiver_policy,
        fixtures_dir=fixtures_dir,
        top_n=args.top_n,
        input_manifest=input_manifest,
    )

    rendered = json.dumps(plan, indent=2, sort_keys=False) + "\n"

    if args.check:
        if not args.output.exists():
            raise SystemExit(f"ERROR: output artifact missing for --check: {args.output}")
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            raise SystemExit(
                f"ERROR: workload API wave plan drift detected. regenerate with: {Path(__file__).name}"
            )
        print(
            "OK: workload API wave plan is up-to-date "
            f"(top_n={args.top_n}, candidates={plan['summary']['candidate_symbols']})"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(
        f"Wrote {args.output} "
        f"(top_n={args.top_n}, candidates={plan['summary']['candidate_symbols']}, waves={plan['summary']['wave_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
