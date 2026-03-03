# Gentoo Validation Operations Guide

This runbook is for maintainers operating Gentoo validation lanes day-to-day.

## Running Validation

## Preflight

```bash
# Repo root
python3 scripts/gentoo/validate-docs.py --strict
python3 scripts/gentoo/validate_cache.py --cache-dir /var/cache/binpkgs --strict
```

## Fast lane

```bash
scripts/gentoo/fast-validate.sh --hardened
```

## Full lane

```bash
python3 scripts/gentoo/build-runner.py --config configs/gentoo/build-config.toml
python3 scripts/gentoo/test-runner.py --package-file data/gentoo/build-order.txt
```

## Publish report

```bash
python3 scripts/gentoo/generate-report.py \
  --franken-version 0.1.0 \
  --gentoo-stage3 2026-02-01 \
  --output docs/gentoo/VALIDATION-REPORT.md
```

## Monitoring

Generate dashboard snapshots:

```bash
python3 scripts/gentoo/validation_dashboard.py --format both --output artifacts/gentoo-dashboard.json
```

Primary monitoring artifacts:

- `artifacts/gentoo-builds/fast-validate/<timestamp>/summary.json`
- `data/gentoo/perf-results/perf_benchmark_results.v1.json`
- `data/gentoo/healing-analysis/summary.json`
- `data/gentoo/quarantine.json`

## Incident Response

## Build failures spike

1. Identify first failing package atom and phase.
2. Compare baseline vs instrumented output.
3. Check hook JSONL for unexpected skip/enable transitions.
4. Re-run package in `strict` mode to isolate hardened-repair side effects.

## Performance regression

1. Inspect `avg_build_overhead_percent` and per-package overhead.
2. Compare p95/p99 latency metrics.
3. Check healing action inflation by package/call-site.
4. Raise regression report with exact artifact links.

## Logging gap

1. Confirm `FRANKENLIBC_LOG_DIR` and `FRANKENLIBC_PORTAGE_LOG`.
2. Verify writable directories in Docker/host context.
3. Re-run with minimal package and confirm JSONL emission.

## Maintenance

## Weekly

- review exclusion policy drift in `configs/gentoo/exclusions.json`,
- run cache validation and prune stale metadata,
- regenerate dashboard and report snapshots.

## Monthly

- refresh package prioritization (`top100`, tiering),
- evaluate stale open regressions and quarantine entries.

## Upgrades

When updating FrankenLibC version:

1. update reported version in generated report command,
2. run fast lane and full lane with new build,
3. regenerate validation report,
4. archive previous report and compare deltas.

## Related Docs

- [User Guide](./USER-GUIDE.md)
- [Technical Reference](./REFERENCE.md)
- [FAQ](./FAQ.md)
