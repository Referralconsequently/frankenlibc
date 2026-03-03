# FrankenLibC Gentoo Ecosystem Validation Report

**Date:** `<YYYY-MM-DD>`
**FrankenLibC Version:** `<version>`
**Gentoo Stage 3:** `<stage3-date>`
**Mode:** `<strict|hardened>`

## Executive Summary

- **Packages Tested:** `<count>`
- **Build Success Rate:** `<percent>`
- **Test Pass Rate:** `<percent>`
- **Average Build Overhead:** `<percent>`
- **Median Build Overhead:** `<percent>`

## Results by Tier

| Tier | Packages | Passed | Failed | Skipped | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Tier-1 Fast | `<n>` | `<n>` | `<n>` | `<n>` | `<summary>` |
| Extended | `<n>` | `<n>` | `<n>` | `<n>` | `<summary>` |

## Healing Action Summary

| Action | Count | % of Total |
| --- | ---: | ---: |
| `ClampSize` | `<n>` | `<pct>` |
| `TruncateWithNull` | `<n>` | `<pct>` |
| `IgnoreDoubleFree` | `<n>` | `<pct>` |
| `ReallocAsMalloc` | `<n>` | `<pct>` |
| `ReturnSafeDefault` | `<n>` | `<pct>` |

Top call sites:

| Call Site | Action | Frequency |
| --- | --- | ---: |
| `<file:line>` | `<action>` | `<n>` |

## Regressions

- `<none | list of regressions with package + failure signature>`

## Performance Analysis

## Global

- p50 target adherence: `<pass/fail + details>`
- p95 target adherence: `<pass/fail + details>`
- p99 target adherence: `<pass/fail + details>`

## Per-package highlights

| Package | Overhead % | p50 ns | p95 ns | p99 ns | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `<atom>` | `<pct>` | `<ns>` | `<ns>` | `<ns>` | `<ok/warn/fail>` |

## Artifact Index

- fast summary: `<path>`
- performance report: `<path>`
- healing summary: `<path>`
- dashboard report: `<path>`
- hook logs: `<path>`
- generated report command:

```bash
python3 scripts/gentoo/generate-report.py \
  --franken-version <version> \
  --gentoo-stage3 <stage3-date> \
  --output docs/gentoo/VALIDATION-REPORT.md
```

## Conclusions

1. `<key finding 1>`
2. `<key finding 2>`
3. `<key finding 3>`

## Follow-up Actions

1. `<action + owner + due>`
2. `<action + owner + due>`
