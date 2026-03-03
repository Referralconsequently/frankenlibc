#!/usr/bin/env python3
"""Generate a Gentoo validation markdown report from available artifacts."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def find_latest_fast_summary(artifacts_dir: Path) -> Tuple[Optional[Path], Optional[Dict[str, Any]]]:
    root = artifacts_dir / "fast-validate"
    if not root.exists():
        return None, None
    candidates = sorted(root.glob("*/summary.json"))
    if not candidates:
        return None, None
    latest = candidates[-1]
    return latest, load_json(latest)


def format_percent(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}%"


def format_int(value: Any) -> str:
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value))
    return "n/a"


@dataclass
class Inputs:
    date: str
    franken_version: str
    gentoo_stage3: str
    mode: str
    data_dir: Path
    artifacts_dir: Path
    output: Path


def build_report(inputs: Inputs) -> str:
    perf_path = inputs.data_dir / "perf-results" / "perf_benchmark_results.v1.json"
    heal_path = inputs.data_dir / "healing-analysis" / "summary.json"
    quarantine_path = inputs.data_dir / "quarantine.json"
    regressions_path = inputs.data_dir / "regression_report.v1.json"

    fast_path, fast = find_latest_fast_summary(inputs.artifacts_dir)
    perf = load_json(perf_path)
    heal = load_json(heal_path)
    quarantine = load_json(quarantine_path)
    regressions = load_json(regressions_path)

    packages = int((fast or {}).get("total_packages", 0))
    passed = int((fast or {}).get("passed", 0))
    failed = int((fast or {}).get("failed", 0))
    skipped = int((fast or {}).get("skipped", 0))
    success_rate = (passed / packages * 100.0) if packages else 0.0
    test_pass_rate = ((passed + skipped) / packages * 100.0) if packages else 0.0

    avg_overhead = (perf or {}).get("avg_build_overhead_percent")
    median_overhead = (perf or {}).get("median_build_overhead_percent")
    total_heals = int((heal or {}).get("total_healing_actions", 0))
    heal_breakdown = (heal or {}).get("breakdown", {})
    by_package = (heal or {}).get("by_package", {})
    top_call_sites = (heal or {}).get("top_call_sites", [])
    quarantined = int(((quarantine or {}).get("statistics") or {}).get("total_quarantined", 0))

    regression_lines: List[str] = []
    if regressions:
        total_regressions = int(regressions.get("total_regressions", 0))
        if total_regressions == 0:
            regression_lines.append("- none reported")
        else:
            rows = regressions.get("regressions", [])
            for row in rows[:10]:
                package = row.get("package", "unknown")
                r_type = row.get("type", "unknown")
                severity = row.get("severity", "unknown")
                regression_lines.append(f"- {package}: {r_type} ({severity})")
    else:
        regression_lines.append("- no regression report artifact found")

    action_rows: List[str] = []
    if isinstance(heal_breakdown, dict) and heal_breakdown:
        for action, count in sorted(heal_breakdown.items(), key=lambda item: item[0]):
            c = int(count) if isinstance(count, (int, float)) else 0
            pct = (c / total_heals * 100.0) if total_heals else 0.0
            action_rows.append(f"| `{action}` | {c} | {pct:.2f}% |")
    else:
        action_rows.append("| n/a | 0 | 0.00% |")

    package_rows: List[str] = []
    perf_packages = (perf or {}).get("packages", [])
    if isinstance(perf_packages, list) and perf_packages:
        for row in perf_packages[:10]:
            atom = row.get("package", "unknown")
            overhead = row.get("build_overhead_percent")
            profile = row.get("latency_profile") or {}
            p50 = profile.get("p50_latency_ns", "n/a")
            p95 = profile.get("p95_latency_ns", "n/a")
            p99 = profile.get("p99_latency_ns", "n/a")
            verdict = "ok"
            if isinstance(p99, (int, float)) and p99 > 400:
                verdict = "warn"
            package_rows.append(
                f"| `{atom}` | {format_percent(float(overhead) if isinstance(overhead, (int, float)) else None)} "
                f"| {p50} | {p95} | {p99} | {verdict} |"
            )
    else:
        package_rows.append("| n/a | n/a | n/a | n/a | n/a | unknown |")

    call_site_rows: List[str] = []
    if isinstance(top_call_sites, list) and top_call_sites:
        for row in top_call_sites[:10]:
            call_site = row.get("call_site", "unknown")
            action = row.get("healing_action", "unknown")
            freq = row.get("frequency", 0)
            call_site_rows.append(f"| `{call_site}` | `{action}` | {format_int(freq)} |")
    else:
        call_site_rows.append("| `n/a` | `n/a` | 0 |")

    package_heal_rows: List[str] = []
    if isinstance(by_package, dict) and by_package:
        for package, payload in sorted(by_package.items(), key=lambda item: item[0]):
            count = int((payload or {}).get("total_healing_actions", 0))
            density = (payload or {}).get("actions_per_1000_calls", 0)
            package_heal_rows.append(f"| `{package}` | {count} | {density} |")
    else:
        package_heal_rows.append("| `n/a` | 0 | 0 |")

    artifact_rows = [
        f"- fast summary: `{fast_path}`" if fast_path else "- fast summary: `not found`",
        f"- performance report: `{perf_path}` ({'found' if perf else 'missing'})",
        f"- healing summary: `{heal_path}` ({'found' if heal else 'missing'})",
        f"- quarantine report: `{quarantine_path}` ({'found' if quarantine else 'missing'})",
        f"- regression report: `{regressions_path}` ({'found' if regressions else 'missing'})",
    ]

    lines = [
        "# FrankenLibC Gentoo Ecosystem Validation Report",
        "",
        f"**Date:** {inputs.date}",
        f"**FrankenLibC Version:** {inputs.franken_version}",
        f"**Gentoo Stage 3:** {inputs.gentoo_stage3}",
        f"**Mode:** {inputs.mode}",
        "",
        "## Executive Summary",
        "",
        f"- **Packages Tested:** {packages}",
        f"- **Build Success Rate:** {success_rate:.2f}%",
        f"- **Test Pass Rate:** {test_pass_rate:.2f}%",
        f"- **Average Build Overhead:** {format_percent(float(avg_overhead) if isinstance(avg_overhead, (int, float)) else None)}",
        f"- **Median Build Overhead:** {format_percent(float(median_overhead) if isinstance(median_overhead, (int, float)) else None)}",
        f"- **Total Healing Actions:** {total_heals}",
        f"- **Quarantined Tests:** {quarantined}",
        "",
        "## Results by Tier",
        "",
        "| Tier | Packages | Passed | Failed | Skipped | Notes |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        f"| Tier-1 Fast | {packages} | {passed} | {failed} | {skipped} | Derived from latest fast-validate summary |",
        "",
        "## Healing Action Summary",
        "",
        "| Action | Count | % of Total |",
        "| --- | ---: | ---: |",
        *action_rows,
        "",
        "### Top Call Sites",
        "",
        "| Call Site | Action | Frequency |",
        "| --- | --- | ---: |",
        *call_site_rows,
        "",
        "### By Package",
        "",
        "| Package | Total Actions | Actions per 1000 Calls |",
        "| --- | ---: | ---: |",
        *package_heal_rows,
        "",
        "## Regressions",
        "",
        *regression_lines,
        "",
        "## Performance Analysis",
        "",
        "| Package | Overhead % | p50 ns | p95 ns | p99 ns | Verdict |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        *package_rows,
        "",
        "## Artifact Index",
        "",
        *artifact_rows,
        "",
        "## Conclusions",
        "",
        "1. Validation artifacts are aggregated into one deterministic report surface.",
        "2. Healing and performance telemetry are linked directly to source artifact paths.",
        "3. Missing artifact classes are reported explicitly rather than silently omitted.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> Inputs:
    parser = argparse.ArgumentParser(description="Generate a Gentoo ecosystem validation markdown report.")
    parser.add_argument("--date", default=utc_today(), help="Report date (YYYY-MM-DD)")
    parser.add_argument("--franken-version", default="dev", help="FrankenLibC version label")
    parser.add_argument("--gentoo-stage3", default="unknown", help="Gentoo stage3 build date")
    parser.add_argument("--mode", default="hardened", help="Validation mode label")
    parser.add_argument("--data-dir", default="data/gentoo", help="Input data directory")
    parser.add_argument("--artifacts-dir", default="artifacts/gentoo-builds", help="Artifacts root directory")
    parser.add_argument(
        "--output",
        default="docs/gentoo/VALIDATION-REPORT.md",
        help="Output markdown path",
    )
    args = parser.parse_args()
    return Inputs(
        date=args.date,
        franken_version=args.franken_version,
        gentoo_stage3=args.gentoo_stage3,
        mode=args.mode,
        data_dir=Path(args.data_dir),
        artifacts_dir=Path(args.artifacts_dir),
        output=Path(args.output),
    )


def main() -> int:
    inputs = parse_args()
    report = build_report(inputs)
    inputs.output.parent.mkdir(parents=True, exist_ok=True)
    inputs.output.write_text(report + "\n", encoding="utf-8")
    print(f"Wrote report: {inputs.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
