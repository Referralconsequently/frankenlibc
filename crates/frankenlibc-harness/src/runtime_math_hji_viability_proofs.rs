//! Runtime-math HJI viability proof gate.
//!
//! Bead: `bd-249m.6`
//!
//! Goal:
//! - Prove the live discrete HJI controller artifact remains stable and
//!   traceable to checked-in proof evidence.
//! - Verify the runtime-math integration points still wire HJI observe/snapshot
//!   surfaces into the production decision kernel.
//!
//! This gate is intentionally explicit about scope:
//! - It proves the shipped `(risk, latency, adverse)` 4x4x4 discretization.
//! - It does not claim the future async-signal-safety state model described by
//!   R16 (`pc_region`, `lock_state`, `signal_pending`).

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use frankenlibc_membrane::hji_reachability::{HjiViabilityComputation, viability_proof_artifact};
use serde::Serialize;
use std::path::Path;

const BEAD_ID: &str = "bd-249m.6";
const GATE: &str = "runtime_math_hji_viability_proofs";
const RUN_ID: &str = "rtm-hji-viability-proofs";

#[derive(Debug, Serialize)]
pub struct HjiViabilityProofSummary {
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct HjiViabilityIntegrationReport {
    pub observe_hook_present: bool,
    pub state_cache_present: bool,
    pub snapshot_value_present: bool,
    pub snapshot_breach_present: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HjiViabilityProofReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: HjiViabilityProofSources,
    pub summary: HjiViabilityProofSummary,
    pub live_computation: HjiViabilityComputation,
    pub integration: HjiViabilityIntegrationReport,
}

#[derive(Debug, Serialize)]
pub struct HjiViabilityProofSources {
    pub computation_artifact: String,
    pub convergence_svg: String,
    pub hji_reachability_rs: String,
    pub runtime_math_mod_rs: String,
    pub log_path: String,
    pub report_path: String,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
) -> Result<HjiViabilityProofReport, Box<dyn std::error::Error>> {
    let computation_path = workspace_root.join("tests/runtime_math/hji_viability_computation.json");
    let svg_path = workspace_root.join("tests/runtime_math/viability_convergence.svg");
    let hji_path = workspace_root.join("crates/frankenlibc-membrane/src/hji_reachability.rs");
    let runtime_math_path =
        workspace_root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");

    std::fs::create_dir_all(
        log_path
            .parent()
            .ok_or_else(|| std::io::Error::other("log_path must have a parent directory"))?,
    )?;
    std::fs::create_dir_all(
        report_path
            .parent()
            .ok_or_else(|| std::io::Error::other("report_path must have a parent directory"))?,
    )?;

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Warn, "runtime_math.hji_viability.scope_boundary")
            .with_stream(StreamKind::Release)
            .with_gate(GATE)
            .with_outcome(Outcome::Pass)
            .with_controller_id("hji_scope")
            .with_details(serde_json::json!({
                "assumption": "proof surface is limited to the shipped 4x4x4 (risk, latency, adverse) discretization",
                "non_claim": "no claim is made yet for the future async-signal-safety state model",
                "decision_path": "proof->hji_viability->scope_boundary",
            })),
    )?;

    let expected: HjiViabilityComputation =
        serde_json::from_str(&std::fs::read_to_string(&computation_path)?)?;
    let live = viability_proof_artifact();
    let expected_svg = render_convergence_svg(&live);
    let actual_svg = std::fs::read_to_string(&svg_path)?;
    let runtime_math_src = std::fs::read_to_string(&runtime_math_path)?;

    let mut checks = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;

    let computation_match = expected == live;
    checks += 1;
    if computation_match {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new(
            "",
            LogLevel::Info,
            "runtime_math.hji_viability.computation_artifact",
        )
        .with_stream(StreamKind::Release)
        .with_gate(GATE)
        .with_outcome(if computation_match {
            Outcome::Pass
        } else {
            Outcome::Fail
        })
        .with_controller_id("hji_artifact")
        .with_details(serde_json::json!({
            "matches_checked_in_artifact": computation_match,
            "safe_kernel_volume": live.safe_kernel_volume,
            "non_viable_volume": live.non_viable_volume,
            "converged_iteration": live.converged_iteration,
            "decision_path": "proof->hji_viability->computation_artifact",
        })),
    )?;

    let svg_match = actual_svg == expected_svg;
    checks += 1;
    if svg_match {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new(
            "",
            LogLevel::Info,
            "runtime_math.hji_viability.convergence_svg",
        )
        .with_stream(StreamKind::Release)
        .with_gate(GATE)
        .with_outcome(if svg_match {
            Outcome::Pass
        } else {
            Outcome::Fail
        })
        .with_controller_id("hji_convergence_svg")
        .with_details(serde_json::json!({
            "matches_checked_in_svg": svg_match,
            "point_count": live.convergence.len(),
            "decision_path": "proof->hji_viability->convergence_svg",
        })),
    )?;

    let integration = inspect_runtime_math_integration(&runtime_math_src);
    for (event, ok) in [
        ("observe_hook", integration.observe_hook_present),
        ("state_cache", integration.state_cache_present),
        ("snapshot_value", integration.snapshot_value_present),
        ("snapshot_breach", integration.snapshot_breach_present),
    ] {
        checks += 1;
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
        emitter.emit_entry(
            LogEntry::new(
                "",
                LogLevel::Info,
                "runtime_math.hji_viability.integration_marker",
            )
            .with_stream(StreamKind::Release)
            .with_gate(GATE)
            .with_outcome(if ok { Outcome::Pass } else { Outcome::Fail })
            .with_controller_id(event)
            .with_details(serde_json::json!({
                "marker": event,
                "present": ok,
                "decision_path": "proof->hji_viability->integration_marker",
            })),
        )?;
    }

    emitter.flush()?;

    let report = HjiViabilityProofReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("", LogLevel::Info, "generated").timestamp,
        sources: HjiViabilityProofSources {
            computation_artifact: rel_path(workspace_root, &computation_path),
            convergence_svg: rel_path(workspace_root, &svg_path),
            hji_reachability_rs: rel_path(workspace_root, &hji_path),
            runtime_math_mod_rs: rel_path(workspace_root, &runtime_math_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
        },
        summary: HjiViabilityProofSummary {
            checks,
            passed,
            failed,
        },
        live_computation: live,
        integration,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

#[must_use]
pub fn render_convergence_svg(computation: &HjiViabilityComputation) -> String {
    let width = 640.0;
    let height = 240.0;
    let margin = 32.0;
    let plot_width = width - margin * 2.0;
    let plot_height = height - margin * 2.0;
    let max_iter = computation
        .convergence
        .last()
        .map_or(1.0, |point| point.iteration.max(1) as f64);
    let max_delta = computation
        .convergence
        .iter()
        .fold(0.0f64, |acc, point| acc.max(point.max_delta))
        .max(1.0);

    let points = computation
        .convergence
        .iter()
        .map(|point| {
            let x = if computation.convergence.len() <= 1 {
                margin
            } else {
                margin + ((point.iteration as f64 - 1.0) / (max_iter - 1.0)) * plot_width
            };
            let y = margin + plot_height - ((point.max_delta / max_delta) * plot_height);
            format!("{x:.2},{y:.2}")
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        concat!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"640\" height=\"240\" viewBox=\"0 0 640 240\" role=\"img\" aria-labelledby=\"title desc\">\n",
            "  <title id=\"title\">HJI Bellman Residual Convergence</title>\n",
            "  <desc id=\"desc\">Residual by value-iteration sweep for the live discrete HJI controller.</desc>\n",
            "  <rect width=\"640\" height=\"240\" fill=\"#fbfaf5\"/>\n",
            "  <path d=\"M 32 208 H 608\" stroke=\"#23211f\" stroke-width=\"1\" fill=\"none\"/>\n",
            "  <path d=\"M 32 32 V 208\" stroke=\"#23211f\" stroke-width=\"1\" fill=\"none\"/>\n",
            "  <polyline points=\"{points}\" fill=\"none\" stroke=\"#b53f24\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>\n",
            "  <text x=\"32\" y=\"20\" fill=\"#23211f\" font-family=\"monospace\" font-size=\"14\">Discrete HJI Bellman residual</text>\n",
            "  <text x=\"32\" y=\"228\" fill=\"#5a554d\" font-family=\"monospace\" font-size=\"11\">converged_iteration={converged_iteration} safe_kernel_volume={safe_kernel_volume}</text>\n",
            "  <text x=\"540\" y=\"28\" fill=\"#5a554d\" font-family=\"monospace\" font-size=\"11\">max_delta={max_delta:.6}</text>\n",
            "</svg>\n"
        ),
        points = points,
        converged_iteration = computation.converged_iteration,
        safe_kernel_volume = computation.safe_kernel_volume,
        max_delta = computation
            .convergence
            .first()
            .map_or(0.0, |point| point.max_delta),
    )
}

fn inspect_runtime_math_integration(runtime_math_src: &str) -> HjiViabilityIntegrationReport {
    let observe_hook_present =
        runtime_math_src.contains("hji.observe(risk_bound_ppm, estimated_cost_ns, adverse);");
    let state_cache_present =
        runtime_math_src.contains("self.cached_hji_state.store(hji_code, Ordering::Relaxed);");
    let snapshot_value_present = runtime_math_src.contains("hji_safety_value: hji_summary.value,");
    let snapshot_breach_present =
        runtime_math_src.contains("hji_breached: hji_summary.state == ReachState::Breached,");

    let mut failures = Vec::new();
    if !observe_hook_present {
        failures.push("runtime_math/mod.rs missing hji.observe(...) call".to_string());
    }
    if !state_cache_present {
        failures.push("runtime_math/mod.rs missing cached_hji_state publish".to_string());
    }
    if !snapshot_value_present {
        failures.push("runtime_math/mod.rs missing hji_safety_value snapshot field".to_string());
    }
    if !snapshot_breach_present {
        failures.push("runtime_math/mod.rs missing hji_breached snapshot field".to_string());
    }

    HjiViabilityIntegrationReport {
        observe_hook_present,
        state_cache_present,
        snapshot_value_present,
        snapshot_breach_present,
        failures,
    }
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
