# FrankenLibC

<div align="center">
  <img src="franken_libc_illustration.webp" alt="FrankenLibC illustration" width="720">
</div>

<div align="center">

![version](https://img.shields.io/badge/version-0.1.0-2f6feb)
![rust](https://img.shields.io/badge/rust-nightly-f74c00)
![platform](https://img.shields.io/badge/platform-linux-181717)
![license](https://img.shields.io/badge/license-MIT%20with%20rider-8a2be2)

</div>

**A clean-room Rust libc project that interposes on glibc today, applies a Transparent Safety Membrane at the ABI boundary, and incrementally replaces unsafe libc behavior with native Rust implementations and raw-syscall paths.**

There is no curl installer or package-manager release yet. The current fast path is:

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd FrankenLibC
cargo build -p frankenlibc-abi --release
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo "hello from FrankenLibC"
```

## TL;DR

### The Problem

glibc is enormous, security-critical, and written in a language that cannot enforce memory safety at the ABI boundary. Existing Linux software still expects glibc-compatible symbols, calling conventions, and process semantics.

### The Solution

FrankenLibC puts a **Transparent Safety Membrane (TSM)** behind a glibc-shaped ABI. Every libc entrypoint can validate, sanitize, repair, deny, and audit before handing control to safe Rust code, raw Linux syscalls, or, where the project is not done yet, a constrained host-glibc call-through.

### Why Use FrankenLibC?

Current source of truth: `tests/conformance/support_matrix_maintenance_report.v1.json`.

| Why it matters | Current state |
|---|---|
| Large classified ABI surface | `3980` exported symbols classified |
| Native ownership is already broad | `3441 Implemented` + `406 RawSyscall` = `96.7%` native coverage |
| No exported stubs right now | `0 Stub` |
| Interposition works today | `target/release/libfrankenlibc_abi.so` via `LD_PRELOAD` |
| Hardened mode exists now | `FRANKENLIBC_MODE=hardened` |
| Verification is first-class | harness CLI, conformance fixtures, maintenance gates, smoke scripts, perf scripts |
| Runtime math is live code | `frankenlibc-membrane/src/runtime_math/` contains active control kernels, not just design docs |

## Quick Example

```bash
# 1. Build the interpose artifact
cargo build -p frankenlibc-abi --release

# 2. Inspect the current symbol reality
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json

# 3. Run something small in strict mode
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo strict

# 4. Run the same idea in hardened mode
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo hardened

# 5. Run the membrane verification campaign
cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json

# 6. Check support-matrix maintenance drift
bash scripts/check_support_matrix_maintenance.sh

# 7. Run the preload smoke suite
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

## Concrete Case Studies

These are the kinds of situations FrankenLibC is designed to make tractable.

### Case study 1: unsafe legacy binary, no relink budget

You have a prebuilt C or C++ binary, you do not want to rebuild it, and you want a safer libc boundary for experiments:

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" \
./legacy_binary
```

Why this matters:

- no relink step
- no source-code rewrite requirement
- explicit artifact path
- membrane and verification tooling can be layered around the run

### Case study 2: documentation drift after a symbol promotion

You convert a symbol from `GlibcCallThrough` to `Implemented`, but you need to know whether reports still agree:

```bash
bash scripts/check_support_matrix_maintenance.sh
```

This catches a very real failure mode in replacement-library work: code and status claims quietly diverging.

### Case study 3: hardened-mode semantics as an engineering question

Instead of arguing abstractly about whether hardened mode "works," the repo has an explicit membrane verification path:

```bash
cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json
```

That is the right shape for this project: behavior as an artifact, not just a claim in prose.

## Design Philosophy

### 1. ABI first

This project is only interesting if existing binaries can talk to it. The ABI boundary is the contract: symbol names, calling conventions, version scripts, `errno`, mode semantics, and process-level behavior.

### 2. Safety at the edge

Unsafe C inputs are not trusted. The TSM sits at the libc boundary and classifies pointers, regions, fds, and contexts before anything meaningful happens.

### 3. Native replacement by pressure, not by vanity

The project does not pretend the whole world is already reimplemented. Each exported symbol is explicitly classified as `Implemented`, `RawSyscall`, or `GlibcCallThrough`, and the matrix is machine-checked.

### 4. Clean-room over translation

The codebase is not a line-by-line Rust port of glibc. Behavior is driven by contracts, fixtures, and verification artifacts rather than transliterating legacy C.

### 5. Evidence beats rhetoric

Support claims, mode semantics, fixture coverage, drift checks, smoke tests, and release gates all live in code and machine-generated artifacts. The README should summarize them, not replace them.

## Comparison

| Dimension | glibc | musl | Sanitizers around glibc | FrankenLibC |
|---|---|---|---|---|
| Production Linux compatibility target | Native | Requires relink / different libc target | Native glibc only | Interpose-first, replacement later |
| Memory-safe implementation goal | No | No | No | Yes for native paths |
| Runtime repair mode | No | No | No | Yes, `hardened` |
| Per-symbol implementation census | No | No | No | Yes, `support_matrix.json` |
| Host-glibc dependency today | N/A | No | Yes | Yes for remaining `GlibcCallThrough` paths |
| Raw syscall fallback paths | Internal | Internal | No | Explicit taxonomy |
| Auditable structured verification artifacts | Limited | Limited | Limited | Core workflow |

## Current State

Current source of truth: `tests/conformance/support_matrix_maintenance_report.v1.json`.

| Status | Count | Meaning |
|---|---:|---|
| `Implemented` | 3441 | Native ABI-backed Rust-owned behavior |
| `RawSyscall` | 406 | ABI path delegates directly to Linux syscalls |
| `GlibcCallThrough` | 133 | Still depends on host glibc for that symbol |
| `Stub` | 0 | No exported stubs in the current classified surface |

Total classified exports: **3980**.  
Current native coverage (`Implemented + RawSyscall`): **96.7%**.

What that means in practice:

- The current shipping artifact is the **interpose** shared library: `target/release/libfrankenlibc_abi.so`.
- The future **replace** artifact (`libfrankenlibc_replace.so`) is still planned, not done.
- Host glibc is still required today because `GlibcCallThrough` symbols remain.

## What We Have Actually Built

The project is no longer just an architecture sketch. Today’s repo contains:

| Area | What exists now |
|---|---|
| ABI boundary | A large `extern "C"` surface in `crates/frankenlibc-abi`, including native stdio, string, math, allocator, resolver, locale, and syscall-facing entrypoints |
| Safety membrane | Validation, healing, metrics, runtime policy, runtime math controllers, and pointer-safety infrastructure in `crates/frankenlibc-membrane` |
| Safe semantic kernels | Safe Rust implementations in `crates/frankenlibc-core` for string, stdio, math, ctype, malloc, locale, pthread, resolver, and more |
| Verification harness | A dedicated CLI in `crates/frankenlibc-harness` for fixture capture, verification, traceability, reality reports, membrane verification, evidence compliance, and runtime-math snapshots |
| Conformance assets | Fixture packs, maintenance reports, smoke tests, golden snapshots, release gates, and drift-check scripts under `tests/` and `scripts/` |
| Bench infrastructure | Criterion benches in `crates/frankenlibc-bench` plus perf scripts and baselines in `scripts/` |

It is useful to think of FrankenLibC as three things at once:

1. A libc interposition artifact you can run today.
2. A memory-safety and repair substrate at the libc ABI edge.
3. A verification-heavy engineering program for turning more of glibc into native Rust without hiding the unfinished parts.

## Why This Is Useful In Practice

FrankenLibC is useful anywhere the libc boundary is the last realistic place to impose safety or observability without rewriting the whole program.

| Scenario | Why FrankenLibC helps |
|---|---|
| Legacy C/C++ binaries | `LD_PRELOAD` lets you experiment without relinking the program |
| Security testing | `hardened` mode can expose and constrain unsafe behavior that would otherwise corrupt memory silently |
| Compatibility research | The support matrix and reality reports make it explicit which symbols are owned natively vs still delegated |
| Differential verification | The harness can compare FrankenLibC behavior against host glibc fixture packs |
| Replacement-library R&D | The taxonomy and gating model support gradual movement from interpose to standalone replace |
| Observability and evidence | Structured reports and maintenance artifacts make the project auditable instead of anecdotal |

Put differently: this is not just "another libc." It is an attempt to make libc replacement measurable, staged, and safety-oriented.

## Installation

### 1. Build from source

Requirements:

- Linux
- Rust nightly with `rustfmt` and `clippy`
- A normal Cargo toolchain; this repo is a Rust workspace, not a mixed package-manager project

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd FrankenLibC
rustup toolchain install nightly
cargo build -p frankenlibc-abi --release
```

Output:

```bash
target/release/libfrankenlibc_abi.so
```

### 2. Install into a local prefix

```bash
install -d "$HOME/.local/lib/frankenlibc"
install -m 755 target/release/libfrankenlibc_abi.so "$HOME/.local/lib/frankenlibc/"
LD_PRELOAD="$HOME/.local/lib/frankenlibc/libfrankenlibc_abi.so" /bin/echo hello
```

### 3. System-style install for experiments

```bash
sudo install -d /usr/lib/frankenlibc
sudo install -m 755 target/release/libfrankenlibc_abi.so /usr/lib/frankenlibc/
LD_PRELOAD=/usr/lib/frankenlibc/libfrankenlibc_abi.so /bin/echo hello
```

### What does not exist yet

- No curl installer
- No Homebrew formula
- No crates.io install path for the interpose library
- No distro packages

## Quick Start

### 1. Build the library

```bash
cargo build -p frankenlibc-abi --release
```

### 2. Build the harness and inspect the classified surface

```bash
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json
cat /tmp/frankenlibc-reality.json
```

### 3. Run strict mode

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### 4. Run hardened mode

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### 5. Run the default repo gates

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### 6. Run the conformance and smoke tooling

```bash
bash scripts/check_support_matrix_maintenance.sh
bash scripts/check_c_fixture_suite.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

## Common Commands

This repo is a workspace with a library artifact plus a verification harness. The most useful commands are:

| Workflow | Command | What it does |
|---|---|---|
| Build interpose library | `cargo build -p frankenlibc-abi --release` | Produces `libfrankenlibc_abi.so` |
| Workspace correctness gate | `cargo check --workspace --all-targets` | Compile validation |
| Lint gate | `cargo clippy --workspace --all-targets -- -D warnings` | Lint validation |
| Test gate | `cargo test --workspace` | Unit + integration coverage |
| Repo CI gate | `bash scripts/ci.sh` | Project-standard default gate |
| Support-matrix drift check | `bash scripts/check_support_matrix_maintenance.sh` | Regenerates and validates maintenance report |
| Preload smoke test | `bash scripts/ld_preload_smoke.sh` | Real program interposition smoke |
| C fixture suite | `bash scripts/check_c_fixture_suite.sh` | Integration-fixture validation |
| Reality report | `cargo run -p frankenlibc-harness --bin harness -- reality-report --support-matrix support_matrix.json --output /tmp/reality.json` | Machine-readable current-state summary |
| Fixture verification | `cargo run -p frankenlibc-harness --bin harness -- verify --fixture tests/conformance/fixtures --report /tmp/conformance.md` | Replays fixture packs |
| Membrane verification | `cargo run -p frankenlibc-harness --bin harness -- verify-membrane --mode both --output /tmp/healing.json` | Runs strict/hardened healing oracle |
| Benchmarking | `cargo bench -p frankenlibc-bench` | Benchmarks library hot paths |

## Configuration

The important runtime knob is `FRANKENLIBC_MODE`. The broader environment inventory is machine-generated in `tests/conformance/runtime_env_inventory.v1.json`.

Example operator shell setup:

```bash
# Runtime behavior
export FRANKENLIBC_MODE=hardened          # strict | hardened
export FRANKENLIBC_LOG=/tmp/franken.jsonl # optional structured runtime log

# Build / verification convenience
export FRANKENLIBC_LIB="$PWD/target/release/libfrankenlibc_abi.so"
export FRANKENLIBC_EXTENDED_GATES=0
export FRANKENLIBC_E2E_SEED=42
export FRANKENLIBC_E2E_STRESS_ITERS=5

# Example invocation
LD_PRELOAD="$FRANKENLIBC_LIB" /bin/echo configured
```

High-signal variables:

| Variable | Default | Notes |
|---|---|---|
| `FRANKENLIBC_MODE` | `strict` | Process-wide immutable mode selection |
| `FRANKENLIBC_LOG` | unset | Structured runtime log path |
| `FRANKENLIBC_LIB` | unset | Tooling override for the built interpose library |
| `FRANKENLIBC_EXTENDED_GATES` | `0` | Enables heavier CI / perf / snapshot gates |
| `FRANKENLIBC_E2E_SEED` | `42` | Deterministic seed for some E2E workflows |
| `FRANKENLIBC_E2E_STRESS_ITERS` | `5` | Stress iteration count for E2E scripts |

## Architecture

```text
      C process
         |
         v
+-------------------------------+
| glibc-shaped extern "C" ABI   |
| crates/frankenlibc-abi        |
+-------------------------------+
         |
         v
+-------------------------------+
| Transparent Safety Membrane   |
| crates/frankenlibc-membrane   |
|                               |
| null -> tls -> bloom -> arena |
|      -> fingerprint -> canary |
|      -> bounds -> policy      |
+-------------------------------+
         |
         +-----------------------------+
         |                             |
         v                             v
+----------------------+   +----------------------+
| Native Rust kernels  |   | Raw syscall veneers  |
| crates/frankenlibc-  |   | mostly unistd/io/... |
| core                 |   +----------------------+
+----------------------+
         |
         v
+-------------------------------+
| Verification and evidence     |
| crates/frankenlibc-harness    |
| tests/, scripts/, reports     |
+-------------------------------+
```

## How The Transparent Safety Membrane Works

The membrane is the main architectural idea in the project. Instead of trusting raw C pointers because the caller crossed an ABI boundary, FrankenLibC treats the ABI boundary as the place where unsafe information must be classified.

Typical validation path:

```text
incoming pointer / region / fd / mode / context
    ->
null check
    ->
thread-local cache
    ->
bloom filter ownership precheck
    ->
arena / metadata lookup
    ->
fingerprint and canary validation
    ->
bounds / state checks
    ->
Allow | Repair | Deny
```

That classification is what makes strict vs hardened meaningful:

| Mode | Membrane behavior |
|---|---|
| `strict` | preserve compatibility-oriented behavior for supported paths; no repair rewrites |
| `hardened` | apply deterministic repair or denial instead of allowing corruption to continue |

Examples of repair actions already modeled in the code:

- clamp a size to known allocation bounds
- truncate a string write with a guaranteed trailing NUL
- ignore a double-free instead of corrupting allocator state
- treat invalid realloc patterns as a safe malloc path
- switch to a safer semantic variant when policy demands it

## Algorithms And Design Choices

FrankenLibC is unusually explicit about the algorithms it uses. Some of the important ones are:

| Mechanism | Where it shows up | Why it exists |
|---|---|---|
| Safety-state lattice | `crates/frankenlibc-membrane/src/lattice.rs` | Gives a monotone way to reason about pointer/state degradation |
| Galois-connection modeling | `crates/frankenlibc-membrane/src/galois.rs` | Bridges flat C semantics and richer internal safety semantics |
| Generational arena | `arena.rs` | Temporal-safety tracking, especially UAF detection |
| Fingerprints + canaries | `fingerprint.rs` | Allocation-integrity checks with low-overhead metadata |
| Bloom filters | `bloom.rs` | Cheap pointer-ownership precheck before expensive validation |
| TLS validation cache | `tls_cache.rs` | Keeps common validation paths out of global contention |
| Runtime policy routing | `runtime_policy.rs` and membrane runtime math | Lets the boundary choose between fast/full/repair/deny styles of behavior |
| Fixture-driven conformance | harness + `tests/conformance/fixtures` | Lets behavior claims be compared against host libc concretely |

None of these are there for aesthetic reasons. Each one exists to solve a specific pressure point in libc replacement:

- compatibility pressure
- safety pressure
- performance pressure
- observability pressure
- staged-migration pressure

## Runtime Math: What It Is And Why It Exists

The `runtime_math/` tree is one of the most distinctive parts of the project. The point is not to make the codebase sound fancy. The point is to encode runtime decision logic for validation depth, risk handling, admissibility, and control under pressure.

Representative families already present in the repo:

| Family | Examples |
|---|---|
| Risk / sequential testing | `risk.rs`, `eprocess.rs`, `cvar.rs`, `conformal.rs`, `changepoint.rs` |
| Control / routing | `bandit.rs`, `control.rs`, `pareto.rs`, `design.rs`, `admm_budget.rs` |
| Consistency / coherence | `cohomology.rs`, `higher_topos.rs`, `grothendieck_glue.rs`, `hodge_decomposition.rs` |
| Statistical drift / anomaly detection | `kernel_mmd.rs`, `wasserstein_drift.rs`, `matrix_concentration.rs`, `transfer_entropy.rs` |
| Certified safety machinery | `hji_reachability.rs`, `sos_barrier.rs`, `sos_invariant.rs`, `mean_field_game.rs` |

The README-friendly summary is:

- offline proofs and synthesis can be heavyweight
- runtime behavior must stay compact and deterministic
- the codebase therefore ships controller kernels and evidence structures, not giant theorem provers in the hot path

## Replacement Strategy

FrankenLibC is deliberately staged.

| Stage | Meaning |
|---|---|
| Interpose now | Replace selected behavior behind `LD_PRELOAD`, while allowing explicit host call-throughs where still necessary |
| Expand native ownership | Convert more `GlibcCallThrough` symbols into `Implemented` or `RawSyscall` |
| Enforce artifact contracts | Use maintenance and replacement gates so interpose vs replace claims do not drift |
| Standalone replace later | Eliminate host-glibc dependencies for the replacement artifact |

This staged model is why the symbol taxonomy matters so much. Without a machine-readable map of what is native and what is still delegated, a project like this would quickly become impossible to reason about honestly.

### Workspace map

| Path | Purpose |
|---|---|
| `crates/frankenlibc-membrane` | TSM validation pipeline, healing policy, runtime math controllers |
| `crates/frankenlibc-core` | Safe Rust semantic implementations |
| `crates/frankenlibc-abi` | `extern "C"` boundary and the interpose shared library |
| `crates/frankenlibc-harness` | Fixture capture, verification, reporting, evidence tooling |
| `crates/frankenlibc-bench` | Criterion benches |
| `crates/frankenlibc-fixture-exec` | Helper for fixture execution |
| `tests/conformance` | Canonical reports, fixture packs, maintenance artifacts |
| `tests/integration` | Integration tests against produced artifacts |
| `tests/runtime_math` | Runtime math golden artifacts |
| `tests/gentoo` | Gentoo ecosystem validation assets |
| `scripts` | Drift gates, smoke tests, reports, release checks, perf tooling |

## Subsystem Tour

The repo is large enough that it helps to know where the major surfaces live.

| Subsystem | Where to look | What it covers |
|---|---|---|
| String and memory APIs | `crates/frankenlibc-core/src/string/` and `crates/frankenlibc-abi/src/string_abi.rs` | `mem*`, `str*`, and related bootstrap string surface |
| Stdio | `crates/frankenlibc-core/src/stdio/`, `crates/frankenlibc-abi/src/stdio_abi.rs`, `crates/frankenlibc-abi/src/io_internal_abi.rs` | file streams, buffered I/O, internal `_IO_*` bridges |
| Allocator and pointer safety | `malloc/` in core plus `arena.rs`, `fingerprint.rs`, `ptr_validator.rs` in membrane | allocator behavior, ownership tracking, corruption detection |
| Threading | `crates/frankenlibc-core/src/pthread/` and `crates/frankenlibc-abi/src/pthread_abi.rs` | pthread entrypoints, synchronization primitives, thread lifecycle |
| Resolver / networking | `resolv/`, `inet/`, `socket_abi.rs`, `resolv_abi.rs` | DNS/bootstrap resolver and network-facing ABI surface |
| Locale and iconv | `locale/`, `iconv/`, `locale_abi.rs`, `iconv_abi.rs` | locale setup, conversion, and early internationalization surface |
| Runtime math | `crates/frankenlibc-membrane/src/runtime_math/` | risk, control, anomaly detection, and runtime decision kernels |
| Verification harness | `crates/frankenlibc-harness/` | fixture verification, reports, evidence compliance, snapshots |

### If you only read four code areas

Read these first:

1. `crates/frankenlibc-abi/`
2. `crates/frankenlibc-membrane/`
3. `crates/frankenlibc-core/`
4. `crates/frankenlibc-harness/`

That is the runtime stack from ABI boundary to semantic implementation to verification.

### Runtime modes

| Mode | Purpose | Behavior |
|---|---|---|
| `strict` | Compatibility-first | No repair rewrites; prefer ABI-compatible failures |
| `hardened` | Safety-first | Repairs or denies unsafe patterns and emits evidence |

### Healing actions

`crates/frankenlibc-membrane/src/heal.rs` currently defines:

- `ClampSize`
- `TruncateWithNull`
- `IgnoreDoubleFree`
- `IgnoreForeignFree`
- `ReallocAsMalloc`
- `ReturnSafeDefault`
- `UpgradeToSafeVariant`

## Verification Model

FrankenLibC is not just "a library build." The project is organized around verification artifacts:

- `support_matrix.json`: per-symbol status taxonomy
- `tests/conformance/support_matrix_maintenance_report.v1.json`: canonical maintenance snapshot
- `tests/conformance/fixtures/`: host-libc fixture packs
- `tests/runtime_math/golden/`: runtime math snapshot goldens
- `scripts/check_*.sh`: drift, closure, smoke, and policy gates

That verification stack exists to answer different questions:

| Question | Artifact or gate |
|---|---|
| "What symbols are currently native?" | `support_matrix.json` |
| "Did documentation or status drift?" | `check_support_matrix_maintenance.sh` |
| "Does behavior still match captured expectations?" | fixture verification via harness and conformance scripts |
| "Does interposition still work on real binaries?" | `ld_preload_smoke.sh` and integration tests |
| "Did runtime-math behavior drift?" | snapshot goldens and linkage checks |
| "Are release claims internally coherent?" | closure / release gate scripts |

Representative verification flows:

```bash
# Support-matrix maintenance
bash scripts/check_support_matrix_maintenance.sh

# Fixture pipeline
bash scripts/check_conformance_fixture_pipeline.sh

# LD_PRELOAD smoke
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh

# Runtime math snapshots
bash scripts/snapshot_gate.sh

# Release / closure-oriented checks
bash scripts/check_closure_contract.sh
bash scripts/check_release_gate.sh
```

## Verification Artifact Catalog

One of the easiest ways to get lost in this repo is to see many reports without knowing which ones answer which questions. This table is the shortcut.

| Artifact | Role |
|---|---|
| `support_matrix.json` | Per-symbol source of truth for implementation taxonomy |
| `tests/conformance/support_matrix_maintenance_report.v1.json` | Canonical maintenance snapshot derived from the support matrix |
| `tests/conformance/fixtures/` | Host-libc fixture corpus used for differential verification |
| `tests/conformance/c_fixture_spec.json` | Integration-fixture coverage contract |
| `tests/conformance/runtime_env_inventory.v1.json` | Machine-generated inventory of documented `FRANKENLIBC_*` environment variables |
| `tests/runtime_math/golden/` | Golden snapshots for runtime-math behavior |
| `target/conformance/*.json` and `*.jsonl` | Generated local evidence from harness runs and maintenance gates |

There are really three categories of artifacts in this project:

- claims about what exists
- evidence about what happened
- gates that compare the two

That split is worth keeping in mind when reading the repo.

## Road To Standalone Replace

The README now makes the interpose-vs-replace distinction explicit, but it is worth spelling out the progression more concretely.

### Today

- interpose shared library exists
- host glibc still required for the remaining `GlibcCallThrough` surface
- support taxonomy is machine-checked
- hardened mode and verification flows are already live

### Next

- reduce remaining `GlibcCallThrough` symbols family by family
- keep maintenance artifacts synchronized as each promotion lands
- tighten replacement gates so "replace-ready" is mechanically enforced, not socially assumed

### End state

- standalone replacement artifact exists as a real product, not a README promise
- `Implemented` and `RawSyscall` are sufficient for the replacement artifact
- the project can make stronger deployment claims without hand-waving over unresolved host dependencies

This progression is one of the strongest things the README can emphasize, because it explains why the project has so many reports and gates: they are how a staged libc replacement stays honest.

## Suggested Reading Order

If you want to understand the project deeply instead of just using it, this order works well:

1. `README.md`
2. `AGENTS.md`
3. `support_matrix.json`
4. `crates/frankenlibc-abi/`
5. `crates/frankenlibc-membrane/`
6. `crates/frankenlibc-core/`
7. `crates/frankenlibc-harness/`
8. `tests/conformance/`
9. `scripts/check_*.sh`

That sequence mirrors how the project itself works:

- claimed surface
- actual ABI boundary
- safety substrate
- semantic kernels
- verification and drift control

## Troubleshooting

### `LD_PRELOAD` does nothing

Check that you built the ABI crate in release mode and are pointing at the actual `.so`:

```bash
test -f target/release/libfrankenlibc_abi.so
```

### `cargo` fails because the toolchain is wrong

This repo uses nightly Rust:

```bash
rustup toolchain install nightly
rustup override set nightly
```

### A README claim and a machine artifact disagree

Trust the machine artifact. The most useful current files are:

- `support_matrix.json`
- `tests/conformance/support_matrix_maintenance_report.v1.json`
- `tests/conformance/runtime_env_inventory.v1.json`

### Hardened mode does not appear to log anything

Set a log path explicitly:

```bash
FRANKENLIBC_LOG=/tmp/franken.jsonl \
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo test
```

### A drift gate fails after touching symbol classifications

You probably updated code or `support_matrix.json` without refreshing a canonical artifact. Start here:

```bash
bash scripts/check_support_matrix_maintenance.sh
```

## Limitations

- The current production artifact is the **interpose** shared library, not a full standalone libc replacement.
- Host glibc is still required for the remaining `GlibcCallThrough` symbols.
- The README can summarize current reality, but the canonical truth still lives in generated reports and gates.
- Linux is the real target. Multi-architecture and full replacement stories are still active work.
- Many verification scripts exist because this is an active research-heavy codebase, not a polished end-user product.

## Glossary

| Term | Meaning in this repo |
|---|---|
| TSM | Transparent Safety Membrane |
| `Implemented` | Symbol path is natively owned in FrankenLibC |
| `RawSyscall` | Symbol path goes directly to Linux syscalls rather than host glibc |
| `GlibcCallThrough` | Symbol still depends on host glibc for behavior |
| `strict` | Compatibility-first runtime mode |
| `hardened` | Repair/deny-capable runtime mode |
| reality report | Generated report summarizing current classified symbol state |
| maintenance report | Canonical artifact used to detect support-matrix drift |
| interpose artifact | `libfrankenlibc_abi.so`, used via `LD_PRELOAD` |
| replace artifact | Planned standalone libc artifact with no host-glibc call-throughs |

## FAQ

### Is FrankenLibC a drop-in replacement for glibc today?

Not fully. The practical artifact today is `libfrankenlibc_abi.so` used via `LD_PRELOAD`. Full standalone replacement remains planned.

### Does it already implement a lot of symbols natively?

Yes. The current classified surface is 3980 symbols, with 3441 `Implemented` and 406 `RawSyscall`.

### What does hardened mode actually do?

It allows the membrane to repair or deny unsafe patterns instead of just propagating failures, while recording evidence about what happened.

### Is this a clean-room reimplementation?

Yes. The architecture and implementation are spec-first and verification-driven rather than line-by-line glibc translation.

### Is runtime math real code or just naming theater?

Real code. The `frankenlibc-membrane/src/runtime_math/` tree is large and live, and the repo includes snapshot and linkage gates around it.

### Should I trust the README or the generated reports?

The generated reports. The README is a guide. The source of truth is the code plus the canonical artifacts under `tests/conformance/`.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

FrankenLibC is available under the terms in [LICENSE](LICENSE), currently `MIT License (with OpenAI/Anthropic Rider)`.
