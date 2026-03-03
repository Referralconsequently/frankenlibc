# Gentoo Validation FAQ

## Do I need hardened mode for validation?

No. Both modes are useful:

- `strict` is best for parity triage.
- `hardened` is best for safety behavior and healing telemetry.

## Why are some packages excluded?

Exclusions are policy-driven for known preload-incompatible or high-risk contexts (for example setuid paths). See [`configs/gentoo/exclusions.json`](../../configs/gentoo/exclusions.json).

## Where are the main results written?

- Fast lane summaries: `artifacts/gentoo-builds/fast-validate/<timestamp>/summary.json`
- Perf: `data/gentoo/perf-results/perf_benchmark_results.v1.json`
- Healing: `data/gentoo/healing-analysis/summary.json`

## How do I generate a publication-ready markdown report?

```bash
python3 scripts/gentoo/generate-report.py \
  --franken-version 0.1.0 \
  --gentoo-stage3 2026-02-01 \
  --output docs/gentoo/VALIDATION-REPORT.md
```

## How do I verify Gentoo docs and links are valid?

```bash
python3 scripts/gentoo/validate-docs.py --strict
```

## Does this require modifying ebuilds?

Not for the default preload lane. Integration is hook-based via `/etc/portage/bashrc` and `frankenlibc-ebuild-hooks.sh`.

## What should I include when reporting a regression?

At minimum:

1. package atom + mode,
2. exact command,
3. fast summary path,
4. relevant hook/healing logs,
5. failing test/build log excerpt.

## Can I run validation without Docker?

Yes, partially:

```bash
scripts/gentoo/fast-validate.sh --local
```

This runs local LD_PRELOAD smoke checks and skips full containerized build lanes.
