//! Integration test: runtime_math HJI viability proofs (bd-249m.6)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs and a JSON report.
//! 4. The report indicates the checked-in HJI artifacts still match live code.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_hji_viability_proofs.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_hji_viability_proofs.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_hji_viability_proofs.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_hji_viability_proofs.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run HJI viability proofs gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_hji_viability_proofs.log.jsonl");
    let report_path = root.join("target/conformance/runtime_math_hji_viability_proofs.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 6,
        "expected multiple log lines (got {line_count})"
    );

    let log_body = std::fs::read_to_string(&log_path).expect("HJI proof log should be readable");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str()
                == Some("runtime_math.hji_viability.scope_boundary")),
        "HJI proof log should include scope boundary WARN event"
    );
    assert!(
        log_events.iter().any(|entry| {
            entry["event"].as_str() == Some("runtime_math.hji_viability.computation_artifact")
        }),
        "HJI proof log should include computation artifact event"
    );
    assert!(
        log_events.iter().any(|entry| {
            entry["event"].as_str() == Some("runtime_math.hji_viability.integration_marker")
        }),
        "HJI proof log should include integration marker events"
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-249m.6"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        report["live_computation"]["safe_kernel_volume"].as_u64(),
        Some(48)
    );
    assert_eq!(
        report["live_computation"]["non_viable_volume"].as_u64(),
        Some(16)
    );
    assert_eq!(
        report["live_computation"]["boundary_witnesses"]
            .as_array()
            .map(|rows| rows.len()),
        Some(5)
    );
    assert_eq!(
        report["integration"]["observe_hook_present"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["integration"]["snapshot_breach_present"].as_bool(),
        Some(true)
    );
}
