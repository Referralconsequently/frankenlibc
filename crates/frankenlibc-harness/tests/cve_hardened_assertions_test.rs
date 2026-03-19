// cve_hardened_assertions_test.rs — bd-1m5.6
// Integration tests for the hardened CVE prevention/healing assertion suite.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn run_generator(extra_args: &[&str]) -> std::process::Output {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let mut args = vec![
        root.join("scripts/generate_cve_hardened_assertions.py")
            .to_str()
            .unwrap()
            .to_string(),
        "-o".to_string(),
        report_path.to_str().unwrap().to_string(),
    ];
    args.extend(extra_args.iter().map(|value| value.to_string()));
    Command::new("python3")
        .args(args)
        .current_dir(&root)
        .output()
        .expect("failed to execute hardened assertions generator")
}

#[test]
fn hardened_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let output = run_generator(&[]);
    assert!(
        output.status.success(),
        "Hardened assertions generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn hardened_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.6"));

    let summary = &data["summary"];
    for field in &[
        "total_assertions",
        "no_crash_in_hardened",
        "with_healing_actions",
        "prevention_strategies",
        "unique_healing_actions",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["regression_detection"].is_object());
    assert!(data["assertion_matrix"].is_array());
    assert!(data["healing_expectation_map"].is_object());
}

#[test]
fn hardened_all_cves_no_crash() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let assertions = data["assertion_matrix"].as_array().unwrap();
    assert!(!assertions.is_empty(), "No hardened assertions");

    for a in assertions {
        let cve_id = a["cve_id"].as_str().unwrap_or("unknown");
        assert!(
            !a["hardened_expectations"]["crashes"].as_bool().unwrap(),
            "{} expected to crash in hardened mode",
            cve_id
        );
        assert!(
            a["hardened_expectations"]["no_uncontrolled_unsafety"]
                .as_bool()
                .unwrap(),
            "{} has uncontrolled memory unsafety",
            cve_id
        );
    }
}

#[test]
fn hardened_all_cves_have_healing_actions() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let assertions = data["assertion_matrix"].as_array().unwrap();
    for a in assertions {
        let cve_id = a["cve_id"].as_str().unwrap_or("unknown");
        let healing = a["hardened_expectations"]["healing_actions_required"]
            .as_array()
            .unwrap();
        assert!(
            !healing.is_empty(),
            "{} has no healing actions defined",
            cve_id
        );
    }
}

#[test]
fn hardened_multiple_prevention_strategies() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let strategies = data["summary"]["prevention_strategies"]
        .as_object()
        .unwrap();
    assert!(
        strategies.len() >= 2,
        "Only {} prevention strategies (need >= 2)",
        strategies.len()
    );
}

#[test]
fn hardened_no_validation_errors() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let val_errors = data["summary"]["validation_errors"].as_u64().unwrap();
    assert_eq!(val_errors, 0, "Validation errors found");
    assert_eq!(data["regression_detection"]["status"], "clean");
}

#[test]
fn hardened_healing_expectation_map_populated() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let map = data["healing_expectation_map"].as_object().unwrap();
    assert!(
        map.len() >= 4,
        "Only {} healing actions in map (need >= 4)",
        map.len()
    );

    for (action, info) in map {
        let count = info["count"].as_u64().unwrap();
        assert!(count > 0, "Healing action {} has count 0", action);
    }
}

#[test]
fn hardened_regression_detection_digest_present() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let digest = data["regression_detection"]["assertion_digest"]
        .as_str()
        .expect("assertion digest should be present");
    assert_eq!(digest.len(), 64, "assertion digest should be full sha256");
    assert!(
        data["regression_detection"]["all_no_crash"]
            .as_bool()
            .unwrap(),
        "all_no_crash should remain true"
    );
    assert!(
        data["regression_detection"]["all_with_healing_actions"]
            .as_bool()
            .unwrap(),
        "all_with_healing_actions should remain true"
    );
}

#[test]
fn hardened_log_emission_contains_required_fields() {
    let root = repo_root();
    let log_path = root.join("target/conformance/hardened_assertions.log.jsonl");
    let output = run_generator(&[
        "--timestamp",
        "2026-03-19T19:31:00Z",
        "--log",
        log_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "Hardened assertions generator with log failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {}", log_path.display(), e));
    let rows: Vec<serde_json::Value> = content
        .lines()
        .map(|line| serde_json::from_str(line).expect("log row should be valid json"))
        .collect();
    assert!(
        rows.len() >= 2,
        "expected assertion rows plus summary row in log"
    );

    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "bead_id",
            "scenario_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "event",
            "outcome",
        ] {
            assert!(row.get(field).is_some(), "missing log field {field}");
        }
        assert_eq!(row["bead_id"], "bd-1m5.6");
        assert_eq!(row["mode"], "hardened");
    }

    let summary = rows
        .iter()
        .find(|row| row["event"] == "cve_hardened_assertion_summary")
        .expect("summary row should be present");
    assert_eq!(summary["outcome"], "clean");
    assert_eq!(summary["validation_errors"], 0);
}
