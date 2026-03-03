# FrankenLibC Gentoo Ecosystem Validation Report

**Date:** 2026-03-03
**FrankenLibC Version:** 0.1.0
**Gentoo Stage 3:** 2026-02-01
**Mode:** hardened

## Executive Summary

- **Packages Tested:** 5
- **Build Success Rate:** 100.00%
- **Test Pass Rate:** 100.00%
- **Average Build Overhead:** 4.11%
- **Median Build Overhead:** 4.24%
- **Total Healing Actions:** 5
- **Quarantined Tests:** 0

## Results by Tier

| Tier | Packages | Passed | Failed | Skipped | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Tier-1 Fast | 5 | 5 | 0 | 0 | Derived from latest fast-validate summary |

## Healing Action Summary

| Action | Count | % of Total |
| --- | ---: | ---: |
| `ClampSize` | 2 | 40.00% |
| `IgnoreDoubleFree` | 1 | 20.00% |
| `ReallocAsMalloc` | 1 | 20.00% |
| `TruncateWithNull` | 1 | 20.00% |

### Top Call Sites

| Call Site | Action | Frequency |
| --- | --- | ---: |
| `redis/src/zmalloc.c:45` | `ClampSize` | 1 |
| `redis/src/sds.c:220` | `TruncateWithNull` | 1 |
| `curl/lib/url.c:98` | `IgnoreDoubleFree` | 1 |
| `curl/lib/memdebug.c:71` | `ClampSize` | 1 |
| `coreutils/src/xmalloc.c:31` | `ReallocAsMalloc` | 1 |

### By Package

| Package | Total Actions | Actions per 1000 Calls |
| --- | ---: | ---: |
| `dev-db/redis` | 2 | 1000.0 |
| `net-misc/curl` | 2 | 1000.0 |
| `sys-apps/coreutils` | 1 | 1000.0 |

## Regressions

- no regression report artifact found

## Performance Analysis

| Package | Overhead % | p50 ns | p95 ns | p99 ns | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `sys-apps/coreutils` | 5.55% | 205 | 386 | 394 | ok |
| `dev-libs/json-c` | 5.20% | 189 | 364 | 393 | ok |
| `app-arch/gzip` | 2.99% | 205 | 387 | 398 | ok |
| `sys-apps/grep` | 4.24% | 213 | 382 | 396 | ok |
| `net-misc/curl` | 2.56% | 213 | 383 | 397 | ok |

## Artifact Index

- fast summary: `artifacts/gentoo-builds/fast-validate/20260213T082508Z/summary.json`
- performance report: `data/gentoo/perf-results/perf_benchmark_results.v1.json` (found)
- healing summary: `data/gentoo/healing-analysis/summary.json` (found)
- quarantine report: `data/gentoo/quarantine.json` (found)
- regression report: `data/gentoo/regression_report.v1.json` (missing)

## Conclusions

1. Validation artifacts are aggregated into one deterministic report surface.
2. Healing and performance telemetry are linked directly to source artifact paths.
3. Missing artifact classes are reported explicitly rather than silently omitted.

