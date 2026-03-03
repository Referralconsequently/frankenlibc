# Gentoo Validation Contributing Guide

This guide explains how to contribute to the Gentoo ecosystem-validation lane in FrankenLibC.

## Scope

This guide covers:

- adding or reprioritizing package atoms,
- reporting FrankenLibC validation regressions,
- proposing exclusion policy changes,
- extending validation scripts and docs.

## Adding Packages

Primary lists:

- [`configs/gentoo/top100-packages.txt`](../../configs/gentoo/top100-packages.txt)
- [`configs/gentoo/tier1-mini.txt`](../../configs/gentoo/tier1-mini.txt)
- [`configs/gentoo/package-tiers.json`](../../configs/gentoo/package-tiers.json)

Update workflows:

```bash
# Recompute package ordering/deps artifacts
python3 scripts/gentoo/extract-deps.py --help
python3 scripts/gentoo/update-package-list.py --help

# Validate exclusion policy after package-list changes
python3 scripts/gentoo/check-exclusions.py --help
```

Rules:

- Keep Tier-1 fast lane small and representative.
- Add high-impact/common packages first.
- Avoid setuid/static-only atoms in preload lane unless you also ship explicit handling evidence.

## Reporting Issues

When filing a bug/regression:

1. include package atom(s),
2. include runtime mode (`strict` vs `hardened`),
3. include exact command used,
4. include structured log and artifact paths.

Minimum artifact set:

- fast validation summary JSON
- relevant hook JSONL (`FRANKENLIBC_PORTAGE_LOG`)
- package build/test log excerpt
- generated markdown report (if available)

Recommended report command:

```bash
python3 scripts/gentoo/generate-report.py \
  --franken-version <version> \
  --gentoo-stage3 <stage3-date> \
  --output docs/gentoo/VALIDATION-REPORT.md
```

## Exclusion Requests

Exclusions live in [`configs/gentoo/exclusions.json`](../../configs/gentoo/exclusions.json).

Valid exclusion categories:

- `fundamental`
- `setuid`
- `static_binary`
- `frankenlibc_bug`
- `environmental_constraint`

Every exclusion request must include:

- package atom,
- type,
- concrete reason,
- workaround path,
- tracking bead/issue when applicable.

Do not add exclusions as a first resort. Try reproducing with strict mode and phase scoping first.

## Test Infrastructure Changes

Key scripts:

- `scripts/gentoo/fast-validate.sh`
- `scripts/gentoo/build-runner.py`
- `scripts/gentoo/test-runner.py`
- `scripts/gentoo/validation_dashboard.py`
- `scripts/gentoo/generate-report.py`
- `scripts/gentoo/validate-docs.py`

When changing infrastructure:

1. keep outputs deterministic (stable field names, explicit timestamps),
2. preserve JSON schema version tags,
3. do not silently change default paths.

## Documentation Updates

If behavior changes, update these docs in the same patch:

- [User Guide](./USER-GUIDE.md)
- [Operations Guide](./OPERATIONS.md)
- [Technical Reference](./REFERENCE.md)
- [FAQ](./FAQ.md)

Validate docs before submitting:

```bash
python3 scripts/gentoo/validate-docs.py --strict
```

## Code Style

- Prefer small deterministic scripts with explicit CLI flags.
- Fail with clear non-zero exit codes.
- Emit structured JSON artifacts where possible.
- Keep shell scripts POSIX-safe where practical and quote variables.
