// conformance_fixture_unit_tests_test.rs — bd-2hh.5
// Integration tests for conformance fixture verification and regression detection.

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
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let mut args = vec![
        root.join("scripts/generate_conformance_fixture_unit_tests.py")
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
        .expect("failed to execute fixture unit test generator")
}

#[test]
fn fixture_unit_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let output = run_generator(&[]);
    assert!(
        output.status.success(),
        "Fixture unit test generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn fixture_unit_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2hh.5"));

    let summary = &data["summary"];
    for field in &[
        "total_fixture_files",
        "valid_fixture_files",
        "invalid_fixture_files",
        "total_cases",
        "total_issues",
        "determinism_verified",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["regression_detection"].is_object());
    assert!(data["fixture_results"].is_array());
    assert!(data["regression_baseline"].is_object());
    assert!(data["fixture_hashes"].is_object());
}

#[test]
fn fixture_unit_invalid_fixture_is_reported_deterministically() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let results = data["fixture_results"].as_array().unwrap();
    assert!(!results.is_empty(), "No fixture results");
    assert_eq!(data["summary"]["invalid_fixture_files"], 1);
    assert_eq!(data["regression_detection"]["status"], "attention_required");
    assert_eq!(
        data["regression_detection"]["invalid_fixture_files"][0],
        "setjmp_nested_edges.json"
    );

    let invalid = results
        .iter()
        .find(|row| row["file"] == "setjmp_nested_edges.json")
        .expect("expected setjmp_nested_edges.json to be tracked");
    assert!(!invalid["valid"].as_bool().unwrap());
    assert!(
        invalid["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue == "Missing top-level field: version")
    );
    assert!(
        invalid["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue == "Missing top-level field: cases")
    );
}

#[test]
fn fixture_unit_determinism_verified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    assert!(
        data["summary"]["determinism_verified"].as_bool().unwrap(),
        "Fixture parsing not deterministic"
    );
}

#[test]
fn fixture_unit_regression_baseline_populated() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let baseline = &data["regression_baseline"];
    let symbol_count = baseline["symbol_count"].as_u64().unwrap();
    assert!(
        symbol_count >= 50,
        "Only {} symbols in baseline (need >= 50)",
        symbol_count
    );

    let symbols = baseline["symbols"].as_object().unwrap();
    for (sym, info) in symbols {
        let count = info["count"].as_u64().unwrap();
        assert!(count > 0, "Symbol {} has 0 cases in baseline", sym);
    }

    let digest = data["regression_detection"]["baseline_fixture_digest"]
        .as_str()
        .unwrap();
    assert_eq!(digest.len(), 64, "baseline digest should be full sha256");
}

#[test]
fn fixture_unit_all_have_hashes() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let hashes = data["fixture_hashes"].as_object().unwrap();
    let results = data["fixture_results"].as_array().unwrap();

    assert_eq!(
        hashes.len(),
        results.len(),
        "Hash count doesn't match fixture count"
    );

    for (file, hash) in hashes {
        let h = hash.as_str().unwrap();
        assert!(!h.is_empty(), "Empty hash for fixture {}", file);
    }
}

#[test]
fn fixture_unit_log_emission_contains_required_fields() {
    let root = repo_root();
    let log_path = root.join("target/conformance/fixture_unit_tests.log.jsonl");
    let output = run_generator(&[
        "--timestamp",
        "2026-03-19T17:47:00Z",
        "--log",
        log_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "Fixture unit test generator with log failed:\n{}",
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
        "expected per-fixture rows plus summary row in log"
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
        assert_eq!(row["bead_id"], "bd-2hh.5");
        assert_eq!(row["mode"], "fixture_validation");
    }

    let summary = rows
        .iter()
        .find(|row| row["event"] == "fixture_validation_summary")
        .expect("summary row should be present");
    assert_eq!(summary["outcome"], "attention_required");
    assert_eq!(summary["invalid_fixture_files"], 1);
}
