# Memory Model Decisions (R12 Barrier Map)

This document records the cross-architecture memory-ordering decisions used by the generated BarrierMap audit (`memory_model_audit.json`).

## Scope

- Transparent Safety Membrane (TSM) atomic sites:
  - `crates/frankenlibc-membrane/src/ptr_validator.rs`
  - `crates/frankenlibc-membrane/src/arena.rs`
  - `crates/frankenlibc-membrane/src/tls_cache.rs`
  - `crates/frankenlibc-membrane/src/config.rs`
  - `crates/frankenlibc-membrane/src/metrics.rs`
- Futex/condvar atomic sites:
  - `crates/frankenlibc-core/src/pthread/cond.rs` (non-test region)

## Ordering Policy Table

| Ordering | Barrier Requirement | x86-64 (TSO) Interpretation | aarch64 Interpretation |
|---|---|---|---|
| `Relaxed` | none | Atomicity only; no extra fence required | Atomicity only; no extra fence required |
| `Acquire` | acquire | No explicit `mfence`; acquire semantics from atomic load | Requires acquire load semantics (`ldar` or equivalent) |
| `Release` | release | No explicit `mfence`; release semantics from atomic store | Requires release store semantics (`stlr` or equivalent) |
| `AcqRel` | acquire+release | RMW preserves acq/rel ordering | Requires acq/rel RMW semantics (`ldaxr/stlxr` or equivalent) |
| `SeqCst` | total-order fence discipline | Sequentially consistent atomics provide global order | Requires seq-cst ordering discipline (typically `dmb ish` around operations) |

## Drift Gate

BarrierMap generation enforces per-file expected atomic-site counts. If a new atomic site is added (or removed) without updating the reviewed source spec in `crates/frankenlibc-membrane/build.rs`, the build fails with a BarrierMap drift error. This is intentional and acts as a CI guard.

## Notes on herd7

The generated audit currently records `herd7_result: pending_external_herd7` for each site. That marks the architecture mapping as reviewed but indicates explicit litmus-run artifacts still need to be wired into the gate.
