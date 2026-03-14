//! Integration tests for bd-2tq.4 POSIX obligation traceability artifacts.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn posix_obligation_report_generates_expected_schema() {
    let root = workspace_root();
    let root_prefix = format!("{}/", root.display());
    let out = root.join("target/conformance/posix_obligation_matrix.current.v1.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let output = Command::new(harness_bin)
        .current_dir(&root)
        .arg("posix-obligation-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output")
        .arg(&out)
        .output()
        .expect("run posix obligation report command");

    assert!(
        output.status.success(),
        "posix obligation report generation failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists(), "missing report output: {}", out.display());

    let report = load_json(&out);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-2tq.4"));

    let summary = report["summary"].as_object().expect("summary object");
    for required in [
        "total_exported",
        "tracked_symbols",
        "total_obligations",
        "covered_obligations",
        "mapped_without_execution",
        "obligations_with_execution_failures",
        "error_condition_obligations",
        "async_concurrency_obligations",
        "symbols_missing_any_mapping",
        "symbols_missing_execution_evidence",
        "symbols_missing_error_conditions",
        "symbols_missing_async_concurrency",
    ] {
        assert!(
            summary.contains_key(required),
            "missing summary field {required}"
        );
    }

    let obligations = report["obligations"]
        .as_array()
        .expect("obligations should be array");
    assert!(
        !obligations.is_empty(),
        "obligations array should contain at least one row"
    );
    for row in obligations {
        assert!(row["posix_ref"].is_string(), "posix_ref must be string");
        assert!(row["symbol"].is_string(), "symbol must be string");
        assert!(
            row["coverage_state"].is_string(),
            "coverage_state must be string"
        );
        assert!(row["test_refs"].is_array(), "test_refs must be array");
        assert!(
            !row["test_refs"].as_array().unwrap().is_empty(),
            "every obligation must map to at least one test ref"
        );
        assert!(
            row["artifact_refs"].is_array(),
            "artifact_refs must be array"
        );
        for artifact_ref in row["artifact_refs"].as_array().unwrap() {
            let artifact_ref = artifact_ref
                .as_str()
                .expect("artifact_refs entries must be strings");
            assert!(
                !artifact_ref.starts_with(&root_prefix),
                "artifact refs must stay repo-relative, found absolute path: {artifact_ref}"
            );
        }
    }

    let gaps = report["gaps"].as_array().expect("gaps should be array");
    for gap in gaps {
        assert!(gap["symbol"].is_string(), "gap.symbol must be string");
        assert!(
            gap["gap_reasons"].is_array(),
            "gap.gap_reasons must be an array"
        );
        assert!(
            !gap["gap_reasons"].as_array().unwrap().is_empty(),
            "gap.gap_reasons must not be empty"
        );
    }
}

#[test]
fn traceability_command_emits_non_empty_matrix() {
    let root = workspace_root();
    let markdown_out = root.join("target/conformance/traceability_matrix.current.md");
    let json_out = root.join("target/conformance/traceability_matrix.current.json");
    if let Some(parent) = markdown_out.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let output = Command::new(harness_bin)
        .current_dir(&root)
        .arg("traceability")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output-md")
        .arg(&markdown_out)
        .arg("--output-json")
        .arg(&json_out)
        .output()
        .expect("run traceability command");

    assert!(
        output.status.success(),
        "traceability command failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        markdown_out.exists() && json_out.exists(),
        "traceability outputs must exist"
    );

    let markdown = std::fs::read_to_string(&markdown_out).expect("markdown should be readable");
    assert!(
        markdown.contains("# Traceability Matrix"),
        "markdown should render heading"
    );

    let matrix = load_json(&json_out);
    let entries = matrix["entries"].as_array().expect("entries array");
    assert!(
        !entries.is_empty(),
        "traceability entries must not be empty"
    );
}

#[test]
fn posix_obligation_gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_posix_obligation_matrix.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_posix_obligation_matrix.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "posix obligation gate failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
