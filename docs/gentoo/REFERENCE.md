# Gentoo Validation Technical Reference

This reference describes the architecture, config surface, data schemas, and CLI entry points for Gentoo ecosystem validation.

## Architecture

Validation data flow:

1. package selection/config inputs (`configs/gentoo/*`)
2. execution lane (`fast-validate.sh`, `build-runner.py`, `test-runner.py`)
3. logs + artifacts (`artifacts/gentoo-builds/*`, `data/gentoo/*`)
4. aggregation (`validation_dashboard.py`, `generate-report.py`)
5. publication (`docs/gentoo/VALIDATION-REPORT.md`)

Runtime interposition hook:

- `configs/gentoo/portage-bashrc` sources:
- `scripts/gentoo/frankenlibc-ebuild-hooks.sh`

The hook controls:

- preload activation by phase,
- package blocklists,
- mode selection,
- per-phase structured JSONL logs.

## Configuration Options

## Config Files

| File | Purpose |
| --- | --- |
| `configs/gentoo/build-config.toml` | Build-runner defaults (image, retries, timeout, paths) |
| `configs/gentoo/portage-bashrc` | Global Portage hook template |
| `configs/gentoo/exclusions.json` | Exclusion policy and stats |
| `configs/gentoo/tier1-mini.txt` | Fast validation package subset |
| `configs/gentoo/top100-packages.txt` | Broader package target set |

## Important Environment Variables

| Variable | Purpose |
| --- | --- |
| `FRANKENLIBC_MODE` | `strict` or `hardened` runtime policy |
| `FRANKENLIBC_PORTAGE_ENABLE` | Master enable switch for hook behavior |
| `FRANKENLIBC_PHASE_ALLOWLIST` | Which phases may enable preload |
| `FRANKENLIBC_PACKAGE_BLOCKLIST` | Atoms to skip for preload |
| `FRANKENLIBC_LIB` | Path to interposition `.so` |
| `FRANKENLIBC_LOG_DIR` | Per-package/per-phase log root |
| `FRANKENLIBC_PORTAGE_LOG` | Hook decision JSONL path |
| `FLC_CACHE_LOG` | Cache manager JSONL event path |

## Log Format

## Hook JSONL (`FRANKENLIBC_PORTAGE_LOG`)

Core fields emitted by `frankenlibc-ebuild-hooks.sh`:

- `timestamp`
- `event` (`enable`, `disable`, `skip`, `info`)
- `atom`, `category`, `pn`, `pf`
- `phase`
- `mode`
- `ld_preload`
- `log_file`
- `message`

## Cache JSONL (`FLC_CACHE_LOG`)

Events emitted by `cache_manager.py` include:

- `ts`
- `event` (`cache_lookup`, `cache_put`, `cache_validate`, `cache_invalidate`)
- `key`
- `hit_miss`
- `reason`
- `checksum`
- optional `age_days`

## Result Schemas

## Fast Validation Summary

Path: `artifacts/gentoo-builds/fast-validate/<timestamp>/summary.json`

Key fields:

- `schema_version`
- `bead`
- `mode`
- `total_packages`, `passed`, `failed`, `skipped`
- `results_dir`

## Performance Summary

Path: `data/gentoo/perf-results/perf_benchmark_results.v1.json`

Key fields:

- `avg_build_overhead_percent`
- `median_build_overhead_percent`
- `packages[]` with latency profile (`p50`, `p95`, `p99`, action counts)

## Healing Summary

Path: `data/gentoo/healing-analysis/summary.json`

Key fields:

- `total_healing_actions`
- `breakdown` by action
- `by_package`
- `top_call_sites`

## Dashboard Output

Produced by `scripts/gentoo/validation_dashboard.py`:

- JSON output (`schema_version`, `sections`, overall status)
- markdown output with per-section status and metrics

## CLI Reference

## Core runners

```bash
python3 scripts/gentoo/build-runner.py --help
python3 scripts/gentoo/test-runner.py --help
scripts/gentoo/fast-validate.sh --help
```

## Cache tooling

```bash
python3 scripts/gentoo/cache_manager.py --help
python3 scripts/gentoo/validate_cache.py --help
```

## Aggregation + reporting

```bash
python3 scripts/gentoo/validation_dashboard.py --help
python3 scripts/gentoo/generate-report.py --help
python3 scripts/gentoo/validate-docs.py --help
```

## Related Docs

- [User Guide](./USER-GUIDE.md)
- [Operations Guide](./OPERATIONS.md)
- [Contributing Guide](./CONTRIBUTING.md)
- [Validation Report Template](./VALIDATION-REPORT-TEMPLATE.md)
