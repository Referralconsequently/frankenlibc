//! Integration test: POSIX conformance report generation (bd-18qq.7).

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
fn posix_conformance_report_generates_expected_schema() {
    let root = workspace_root();
    let out = root.join("target/conformance/posix_conformance_report.current.v1.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let output = Command::new(harness_bin)
        .current_dir(&root)
        .arg("posix-conformance-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(&out)
        .output()
        .expect("run posix conformance report command");

    assert!(
        output.status.success(),
        "posix report generation failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists(), "missing report output: {}", out.display());

    let report = load_json(&out);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-18qq.7"));

    let summary = report["summary"].as_object().expect("summary object");
    for required in [
        "total_exported",
        "eligible_symbols",
        "symbols_with_cases",
        "symbols_with_all_core_categories",
        "symbols_with_errno_case",
        "symbols_with_missing_spec_traceability",
        "symbols_with_execution_failures",
        "total_fixture_cases",
        "total_execution_cases",
    ] {
        assert!(
            summary.contains_key(required),
            "missing summary field {required}"
        );
    }

    let symbols = report["symbols"]
        .as_array()
        .expect("symbols should be array");
    assert!(
        !symbols.is_empty(),
        "symbols array should contain at least one eligible symbol"
    );

    let mut prev_symbol: Option<String> = None;
    for row in symbols {
        let symbol = row["symbol"].as_str().expect("symbol string").to_string();
        let case_count = row["case_count"].as_u64().expect("case_count u64");
        let categories = row["categories"].as_object().expect("categories object");
        let category_total = categories
            .values()
            .map(|value| value.as_u64().expect("category counts as u64"))
            .sum::<u64>();
        assert_eq!(
            case_count, category_total,
            "case_count must equal sum(categories) for {}",
            symbol
        );
        assert!(
            row["quality_flags"].is_array(),
            "quality_flags must be array for {}",
            symbol
        );
        if let Some(prev) = prev_symbol {
            assert!(prev <= symbol, "rows must be sorted by symbol asc");
        }
        prev_symbol = Some(symbol);
    }
}
