//! Report generation for conformance results.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::conformance_matrix::ConformanceMatrixReport;
use crate::verify::VerificationSummary;
use crate::{FixtureCase, FixtureSet};

/// A conformance report combining verification and traceability data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Report title.
    pub title: String,
    /// Runtime mode tested (strict or hardened).
    pub mode: String,
    /// Timestamp (UTC).
    pub timestamp: String,
    /// Verification summary.
    pub summary: VerificationSummary,
}

impl ConformanceReport {
    /// Render the report as markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n\n", self.title));
        out.push_str(&format!("- Mode: {}\n", self.mode));
        out.push_str(&format!("- Timestamp: {}\n", self.timestamp));
        out.push_str(&format!("- Total: {}\n", self.summary.total));
        out.push_str(&format!("- Passed: {}\n", self.summary.passed));
        out.push_str(&format!("- Failed: {}\n\n", self.summary.failed));

        out.push_str("| Trace | Family | Symbol | Mode | Case | Spec | Status |\n");
        out.push_str("|-------|--------|--------|------|------|------|--------|\n");
        for r in &self.summary.results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                r.trace_id, r.family, r.symbol, r.mode, r.case_name, r.spec_section, status
            ));
        }
        out
    }

    /// Render the report as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

/// Missing-link diagnostic for decision traceability aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionTraceFinding {
    pub trace_id: String,
    pub symbol: Option<String>,
    pub reason: String,
}

/// Aggregated explainability report over JSONL structured logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionTraceReport {
    pub total_events: usize,
    pub decision_events: usize,
    pub explainable_decision_events: usize,
    pub missing_explainability: usize,
    pub findings: Vec<DecisionTraceFinding>,
}

impl DecisionTraceReport {
    /// Build an explainability report from JSONL content.
    #[must_use]
    pub fn from_jsonl_str(jsonl: &str) -> Self {
        let mut report = Self {
            total_events: 0,
            decision_events: 0,
            explainable_decision_events: 0,
            missing_explainability: 0,
            findings: Vec::new(),
        };

        for (line_no, raw) in jsonl.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            report.total_events += 1;

            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(err) => {
                    report.missing_explainability += 1;
                    report.findings.push(DecisionTraceFinding {
                        trace_id: "<invalid-json>".to_string(),
                        symbol: None,
                        reason: format!("line {} invalid JSON: {}", line_no + 1, err),
                    });
                    continue;
                }
            };

            let Some(obj) = value.as_object() else {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id: "<invalid-object>".to_string(),
                    symbol: None,
                    reason: format!("line {} is not a JSON object", line_no + 1),
                });
                continue;
            };

            let is_runtime_decision_event = obj
                .get("event")
                .and_then(|v| v.as_str())
                .is_some_and(|e| e == "runtime_decision");
            if !is_runtime_decision_event {
                continue;
            }
            report.decision_events += 1;

            let trace_id = obj
                .get("trace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing-trace-id>")
                .to_string();
            let symbol = obj
                .get("symbol")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            if obj.get("decision").is_none() {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id,
                    symbol,
                    reason: "missing fields: decision".to_string(),
                });
                continue;
            }

            let mut missing = Vec::new();
            if obj
                .get("trace_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("trace_id");
            }
            if obj
                .get("symbol")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("symbol");
            }
            if obj
                .get("span_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("span_id");
            }
            if obj
                .get("controller_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("controller_id");
            }
            if obj
                .get("decision_action")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("decision_action");
            }
            if !obj
                .get("risk_inputs")
                .is_some_and(serde_json::Value::is_object)
            {
                missing.push("risk_inputs");
            }

            if missing.is_empty() {
                report.explainable_decision_events += 1;
            } else {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id,
                    symbol,
                    reason: format!("missing fields: {}", missing.join(", ")),
                });
            }
        }

        report
    }

    /// True when every decision event has complete explainability context.
    #[must_use]
    pub const fn fully_explainable(&self) -> bool {
        self.missing_explainability == 0
    }
}

/// Taxonomy count summary derived from support matrix symbols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityCounts {
    pub implemented: u64,
    pub raw_syscall: u64,
    pub glibc_call_through: u64,
    pub stub: u64,
}

/// Machine-readable single source-of-truth report for docs reality tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityReport {
    pub generated_at_utc: String,
    pub total_exported: u64,
    pub counts: RealityCounts,
    pub stubs: Vec<String>,
}

impl RealityReport {
    /// Build report from support_matrix JSON bytes.
    pub fn from_support_matrix_json_str(json: &str) -> Result<Self, String> {
        let matrix: serde_json::Value = serde_json::from_str(json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;

        let generated_at_utc = matrix["generated_at_utc"]
            .as_str()
            .ok_or("missing generated_at_utc in support matrix")?
            .to_string();
        let total_exported = matrix["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;

        let symbols = matrix["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;
        let symbol_count = u64::try_from(symbols.len())
            .map_err(|_| "support matrix symbols[] length does not fit u64".to_string())?;
        if symbol_count != total_exported {
            return Err(format!(
                "support matrix total_exported ({total_exported}) does not match symbols[] length ({symbol_count})"
            ));
        }

        let mut stubs = Vec::new();
        let mut implemented = 0u64;
        let mut raw_syscall = 0u64;
        let mut glibc_call_through = 0u64;
        let mut stub = 0u64;

        for sym in symbols {
            let status = sym["status"].as_str().ok_or("symbol missing status")?;
            let symbol_name = sym["symbol"].as_str().ok_or("symbol missing symbol name")?;
            match status {
                "Implemented" => implemented += 1,
                "RawSyscall" => raw_syscall += 1,
                "GlibcCallThrough" => glibc_call_through += 1,
                "Stub" => {
                    stub += 1;
                    stubs.push(symbol_name.to_string());
                }
                _ => {
                    return Err(format!(
                        "unknown support status '{status}' for symbol '{symbol_name}'"
                    ));
                }
            }
        }

        stubs.sort();

        let computed_total = implemented + raw_syscall + glibc_call_through + stub;
        if computed_total != total_exported {
            return Err(format!(
                "support matrix status totals ({computed_total}) do not match total_exported ({total_exported})"
            ));
        }

        Ok(Self {
            generated_at_utc,
            total_exported,
            counts: RealityCounts {
                implemented,
                raw_syscall,
                glibc_call_through,
                stub,
            },
            stubs,
        })
    }

    /// Build report from support_matrix file on disk.
    pub fn from_support_matrix_path(path: &Path) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|err| format!("failed reading support matrix '{}': {err}", path.display()))?;
        Self::from_support_matrix_json_str(&json)
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

/// Per-category fixture-case counts used for POSIX conformance coverage quality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PosixCaseCategoryCounts {
    pub normal: u64,
    pub boundary: u64,
    pub error: u64,
    pub other: u64,
}

impl PosixCaseCategoryCounts {
    #[must_use]
    pub const fn all_core_categories_present(&self) -> bool {
        self.normal > 0 && self.boundary > 0 && self.error > 0
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.normal + self.boundary + self.error + self.other
    }
}

/// Execution-status counts from conformance matrix rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PosixExecutionCounts {
    pub total: u64,
    pub pass: u64,
    pub fail: u64,
    pub error: u64,
    pub timeout: u64,
    pub crash: u64,
}

impl PosixExecutionCounts {
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.fail > 0 || self.error > 0 || self.timeout > 0 || self.crash > 0
    }
}

/// Per-symbol POSIX conformance coverage row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixSymbolCoverageRow {
    pub symbol: String,
    pub status: String,
    pub module: String,
    pub case_count: u64,
    pub strict_cases: u64,
    pub hardened_cases: u64,
    pub has_errno_case: bool,
    pub spec_sections: Vec<String>,
    pub categories: PosixCaseCategoryCounts,
    pub execution: PosixExecutionCounts,
    pub quality_flags: Vec<String>,
}

/// Summary section for POSIX conformance coverage report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixConformanceSummary {
    pub total_exported: u64,
    pub eligible_symbols: u64,
    pub symbols_with_cases: u64,
    pub symbols_with_all_core_categories: u64,
    pub symbols_with_errno_case: u64,
    pub symbols_with_missing_spec_traceability: u64,
    pub symbols_with_execution_failures: u64,
    pub total_fixture_cases: u64,
    pub total_execution_cases: u64,
}

/// Machine-readable report for bd-18qq.7 POSIX conformance campaign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixConformanceReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub summary: PosixConformanceSummary,
    pub symbols: Vec<PosixSymbolCoverageRow>,
}

#[derive(Debug, Default)]
struct FixtureSymbolAggregate {
    case_count: u64,
    strict_cases: u64,
    hardened_cases: u64,
    has_errno_case: bool,
    spec_sections: BTreeSet<String>,
    categories: PosixCaseCategoryCounts,
}

impl PosixConformanceReport {
    /// Build report from on-disk support matrix + fixture directory + conformance matrix.
    pub fn from_paths(
        support_matrix_path: &Path,
        fixture_dir: &Path,
        conformance_matrix_path: &Path,
    ) -> Result<Self, String> {
        let support_matrix_json = std::fs::read_to_string(support_matrix_path).map_err(|err| {
            format!(
                "failed reading support matrix '{}': {err}",
                support_matrix_path.display()
            )
        })?;
        let conformance_matrix_json =
            std::fs::read_to_string(conformance_matrix_path).map_err(|err| {
                format!(
                    "failed reading conformance matrix '{}': {err}",
                    conformance_matrix_path.display()
                )
            })?;
        let fixture_sets = load_fixture_sets_from_dir(fixture_dir)?;
        Self::from_inputs(
            &support_matrix_json,
            &fixture_sets,
            &conformance_matrix_json,
        )
    }

    /// Build report from parsed fixture sets and raw JSON blobs.
    pub fn from_inputs(
        support_matrix_json: &str,
        fixture_sets: &[FixtureSet],
        conformance_matrix_json: &str,
    ) -> Result<Self, String> {
        let support_value: serde_json::Value = serde_json::from_str(support_matrix_json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;
        let generated_at_utc = support_value["generated_at_utc"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let total_exported = support_value["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;
        let support_symbols = support_value["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;

        let mut eligible_symbols: Vec<(String, String, String)> = Vec::new();
        for symbol_row in support_symbols {
            let symbol = symbol_row["symbol"]
                .as_str()
                .ok_or("support matrix symbol row missing symbol")?;
            let status = symbol_row["status"]
                .as_str()
                .ok_or("support matrix symbol row missing status")?;
            let module = symbol_row["module"].as_str().unwrap_or("unknown");
            if status == "Implemented" || status == "RawSyscall" {
                eligible_symbols.push((symbol.to_string(), status.to_string(), module.to_string()));
            }
        }
        eligible_symbols.sort_by(|a, b| a.0.cmp(&b.0));

        let mut fixture_by_symbol: BTreeMap<String, FixtureSymbolAggregate> = BTreeMap::new();
        for fixture_set in fixture_sets {
            for case in &fixture_set.cases {
                let agg = fixture_by_symbol.entry(case.function.clone()).or_default();
                agg.case_count = agg.case_count.saturating_add(1);
                if case.mode.eq_ignore_ascii_case("strict")
                    || case.mode.eq_ignore_ascii_case("both")
                {
                    agg.strict_cases = agg.strict_cases.saturating_add(1);
                }
                if case.mode.eq_ignore_ascii_case("hardened")
                    || case.mode.eq_ignore_ascii_case("both")
                {
                    agg.hardened_cases = agg.hardened_cases.saturating_add(1);
                }
                if case.expected_errno != 0 {
                    agg.has_errno_case = true;
                }
                let spec_section = case.spec_section.trim();
                if !spec_section.is_empty() {
                    agg.spec_sections.insert(spec_section.to_string());
                }
                match classify_posix_case(case) {
                    PosixCaseClass::Normal => {
                        agg.categories.normal = agg.categories.normal.saturating_add(1)
                    }
                    PosixCaseClass::Boundary => {
                        agg.categories.boundary = agg.categories.boundary.saturating_add(1)
                    }
                    PosixCaseClass::Error => {
                        agg.categories.error = agg.categories.error.saturating_add(1)
                    }
                    PosixCaseClass::Other => {
                        agg.categories.other = agg.categories.other.saturating_add(1)
                    }
                }
            }
        }

        let matrix: ConformanceMatrixReport = serde_json::from_str(conformance_matrix_json)
            .map_err(|err| format!("invalid conformance matrix JSON: {err}"))?;
        let mut execution_by_symbol: BTreeMap<String, PosixExecutionCounts> = BTreeMap::new();
        for case in &matrix.cases {
            let counts = execution_by_symbol.entry(case.symbol.clone()).or_default();
            counts.total = counts.total.saturating_add(1);
            match case.status.as_str() {
                "pass" => counts.pass = counts.pass.saturating_add(1),
                "fail" => counts.fail = counts.fail.saturating_add(1),
                "error" => counts.error = counts.error.saturating_add(1),
                "timeout" => counts.timeout = counts.timeout.saturating_add(1),
                "crash" => counts.crash = counts.crash.saturating_add(1),
                _ => {}
            }
        }

        let mut rows = Vec::with_capacity(eligible_symbols.len());
        for (symbol, status, module) in eligible_symbols {
            let fixture = fixture_by_symbol.remove(&symbol).unwrap_or_default();
            let execution = execution_by_symbol.remove(&symbol).unwrap_or_default();
            let spec_sections: Vec<String> = fixture.spec_sections.into_iter().collect();

            let mut quality_flags = Vec::new();
            if fixture.case_count == 0 {
                quality_flags.push(String::from("missing_fixture_cases"));
            }
            if fixture.strict_cases == 0 {
                quality_flags.push(String::from("missing_strict_case"));
            }
            if fixture.hardened_cases == 0 {
                quality_flags.push(String::from("missing_hardened_case"));
            }
            if fixture.categories.normal == 0 {
                quality_flags.push(String::from("missing_normal_case"));
            }
            if fixture.categories.boundary == 0 {
                quality_flags.push(String::from("missing_boundary_case"));
            }
            if fixture.categories.error == 0 {
                quality_flags.push(String::from("missing_error_case"));
            }
            if !fixture.has_errno_case {
                quality_flags.push(String::from("missing_errno_case"));
            }
            if spec_sections.is_empty() {
                quality_flags.push(String::from("missing_spec_traceability"));
            }
            if execution.has_failures() {
                quality_flags.push(String::from("execution_failures_present"));
            }

            rows.push(PosixSymbolCoverageRow {
                symbol,
                status,
                module,
                case_count: fixture.case_count,
                strict_cases: fixture.strict_cases,
                hardened_cases: fixture.hardened_cases,
                has_errno_case: fixture.has_errno_case,
                spec_sections,
                categories: fixture.categories,
                execution,
                quality_flags,
            });
        }

        rows.sort_by(|a, b| a.symbol.cmp(&b.symbol));

        let eligible_symbols =
            u64::try_from(rows.len()).map_err(|_| "eligible symbol count overflow".to_string())?;
        let symbols_with_cases =
            u64::try_from(rows.iter().filter(|row| row.case_count > 0).count()).unwrap_or(0);
        let symbols_with_all_core_categories = u64::try_from(
            rows.iter()
                .filter(|row| row.categories.all_core_categories_present())
                .count(),
        )
        .unwrap_or(0);
        let symbols_with_errno_case =
            u64::try_from(rows.iter().filter(|row| row.has_errno_case).count()).unwrap_or(0);
        let symbols_with_missing_spec_traceability = u64::try_from(
            rows.iter()
                .filter(|row| row.spec_sections.is_empty())
                .count(),
        )
        .unwrap_or(0);
        let symbols_with_execution_failures = u64::try_from(
            rows.iter()
                .filter(|row| row.execution.has_failures())
                .count(),
        )
        .unwrap_or(0);
        let total_fixture_cases = rows
            .iter()
            .fold(0u64, |acc, row| acc.saturating_add(row.case_count));
        let total_execution_cases = rows
            .iter()
            .fold(0u64, |acc, row| acc.saturating_add(row.execution.total));

        Ok(Self {
            schema_version: "v1".to_string(),
            bead: "bd-18qq.7".to_string(),
            generated_at_utc,
            summary: PosixConformanceSummary {
                total_exported,
                eligible_symbols,
                symbols_with_cases,
                symbols_with_all_core_categories,
                symbols_with_errno_case,
                symbols_with_missing_spec_traceability,
                symbols_with_execution_failures,
                total_fixture_cases,
                total_execution_cases,
            },
            symbols: rows,
        })
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PosixCaseClass {
    Normal,
    Boundary,
    Error,
    Other,
}

fn classify_posix_case(case: &FixtureCase) -> PosixCaseClass {
    if case.expected_errno != 0 {
        return PosixCaseClass::Error;
    }

    let mut haystack = String::new();
    haystack.push_str(&case.name.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.spec_section.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.expected_output.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.inputs.to_string().to_ascii_lowercase());

    let has_boundary_marker = [
        "boundary",
        "bound",
        "limit",
        "max",
        "min",
        "overflow",
        "underflow",
        "size_max",
        "long_max",
        "int_max",
        "empty",
        "zero",
        "null",
        "eof",
    ]
    .iter()
    .any(|marker| haystack.contains(marker));
    if has_boundary_marker {
        return PosixCaseClass::Boundary;
    }

    let has_error_marker = [
        "invalid",
        "error",
        "errno",
        "efault",
        "einval",
        "failed",
        "denied",
        "uaf",
        "double_free",
    ]
    .iter()
    .any(|marker| haystack.contains(marker));
    if has_error_marker {
        return PosixCaseClass::Error;
    }

    if haystack.contains("normal") || haystack.contains("happy_path") || haystack.contains("basic")
    {
        return PosixCaseClass::Normal;
    }

    PosixCaseClass::Other
}

fn load_fixture_sets_from_dir(fixture_dir: &Path) -> Result<Vec<FixtureSet>, String> {
    let mut fixture_paths: Vec<_> = std::fs::read_dir(fixture_dir)
        .map_err(|err| {
            format!(
                "failed reading fixture dir '{}': {err}",
                fixture_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    fixture_paths.sort();

    let mut sets = Vec::new();
    for path in fixture_paths {
        if let Ok(set) = FixtureSet::from_file(&path) {
            sets.push(set);
        }
    }

    if sets.is_empty() {
        return Err(format!(
            "no fixture sets could be parsed from '{}'",
            fixture_dir.display()
        ));
    }

    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::{
        DecisionTraceReport, PosixCaseCategoryCounts, PosixConformanceReport, RealityCounts,
        RealityReport,
    };
    use crate::FixtureSet;

    fn sample_matrix(symbol_rows: &str, total_exported: u64) -> String {
        format!(
            r#"{{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": {total_exported},
  "symbols": [
{symbol_rows}
  ]
}}"#
        )
    }

    #[test]
    fn parses_valid_support_matrix() {
        let json = sample_matrix(
            r#"    { "symbol": "zeta", "status": "Stub" },
    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "beta", "status": "RawSyscall" },
    { "symbol": "gamma", "status": "GlibcCallThrough" },
    { "symbol": "eta", "status": "Stub" }"#,
            5,
        );
        let report = RealityReport::from_support_matrix_json_str(&json).unwrap();

        assert_eq!(report.generated_at_utc, "2026-02-11T03:14:20Z");
        assert_eq!(report.total_exported, 5);
        assert_eq!(
            report.counts,
            RealityCounts {
                implemented: 1,
                raw_syscall: 1,
                glibc_call_through: 1,
                stub: 2
            }
        );
        assert_eq!(report.stubs, vec!["eta".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn rejects_unknown_status() {
        let json = sample_matrix(
            r#"    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "omega", "status": "Experimental" }"#,
            2,
        );

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("unknown support status"));
        assert!(err.contains("Experimental"));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": 1,
  "symbols": [
    { "status": "Implemented" }
  ]
}"#;

        let err = RealityReport::from_support_matrix_json_str(json).unwrap_err();
        assert!(err.contains("symbol missing symbol name"));
    }

    #[test]
    fn rejects_total_export_mismatch() {
        let json = sample_matrix(r#"    { "symbol": "alpha", "status": "Implemented" }"#, 2);

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("does not match symbols[] length"));
    }

    #[test]
    fn decision_trace_report_flags_missing_explainability() {
        let jsonl = r#"{"timestamp":"2026-02-12T00:00:00Z","trace_id":"bd-33p.2::run::001","level":"error","event":"runtime_decision","decision":"Deny","symbol":"malloc","controller_id":"runtime_math_kernel.v1","decision_action":"Deny"}"#;
        let report = DecisionTraceReport::from_jsonl_str(jsonl);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.decision_events, 1);
        assert_eq!(report.explainable_decision_events, 0);
        assert_eq!(report.missing_explainability, 1);
        assert!(!report.fully_explainable());
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].reason.contains("risk_inputs"));
    }

    #[test]
    fn decision_trace_report_accepts_complete_decision_chain() {
        let jsonl = r#"{"timestamp":"2026-02-12T00:00:00Z","trace_id":"bd-33p.2::run::002","span_id":"abi::malloc::decision::0000000000000001","parent_span_id":"abi::malloc::entry::0000000000000001","level":"info","event":"runtime_decision","symbol":"malloc","decision":"FullValidate","controller_id":"runtime_math_kernel.v1","decision_action":"FullValidate","risk_inputs":{"requested_bytes":128,"bloom_negative":false}}"#;
        let report = DecisionTraceReport::from_jsonl_str(jsonl);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.decision_events, 1);
        assert_eq!(report.explainable_decision_events, 1);
        assert_eq!(report.missing_explainability, 0);
        assert!(report.fully_explainable());
        assert!(report.findings.is_empty());
    }

    fn sample_fixture_set() -> FixtureSet {
        FixtureSet::from_json(
            r#"{
  "version":"v1",
  "family":"string",
  "captured_at":"2026-02-26T00:00:00Z",
  "cases":[
    {
      "name":"normal_strlen",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen",
      "inputs":{"s":"abc"},
      "expected_output":"3",
      "expected_errno":0,
      "mode":"strict"
    },
    {
      "name":"boundary_strlen_size_max",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen boundary",
      "inputs":{"s":"a"},
      "expected_output":"1",
      "expected_errno":0,
      "mode":"hardened"
    },
    {
      "name":"error_strlen_efault",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen errno",
      "inputs":{"s":null},
      "expected_output":"0",
      "expected_errno":14,
      "mode":"both"
    }
  ]
}"#,
        )
        .expect("fixture set should parse")
    }

    #[test]
    fn posix_conformance_report_builds_from_inputs() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "total_exported":2,
  "symbols":[
    {"symbol":"strlen","status":"Implemented","module":"string_abi"},
    {"symbol":"malloc","status":"RawSyscall","module":"malloc_abi"}
  ]
}"#;
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "campaign":"test",
  "mode":"both",
  "total_fixture_sets":1,
  "summary":{"total_cases":3,"passed":2,"failed":1,"errors":0,"pass_rate_percent":66.7},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"t1","family":"string","symbol":"strlen","mode":"strict","case_name":"normal_strlen","spec_section":"POSIX","input_hex":"","expected_output":"3","actual_output":"3","host_output":"3","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t2","family":"string","symbol":"strlen","mode":"hardened","case_name":"boundary_strlen_size_max","spec_section":"POSIX","input_hex":"","expected_output":"1","actual_output":"1","host_output":"1","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t3","family":"string","symbol":"strlen","mode":"strict","case_name":"error_strlen_efault","spec_section":"POSIX","input_hex":"","expected_output":"0","actual_output":"-1","host_output":"-1","host_parity":false,"note":null,"status":"fail","passed":false,"error":null,"diff_offset":0}
  ]
}"#;

        let fixture_set = sample_fixture_set();
        let report =
            PosixConformanceReport::from_inputs(support_matrix, &[fixture_set], conformance_matrix)
                .expect("report should build");

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.bead, "bd-18qq.7");
        assert_eq!(report.summary.total_exported, 2);
        assert_eq!(report.summary.eligible_symbols, 2);
        assert_eq!(report.summary.symbols_with_cases, 1);
        assert_eq!(report.summary.symbols_with_all_core_categories, 1);

        let strlen_row = report
            .symbols
            .iter()
            .find(|row| row.symbol == "strlen")
            .expect("strlen row");
        assert!(strlen_row.has_errno_case);
        assert_eq!(
            strlen_row.categories,
            PosixCaseCategoryCounts {
                normal: 1,
                boundary: 1,
                error: 1,
                other: 0
            }
        );
        assert!(strlen_row.execution.has_failures());
        assert!(
            strlen_row
                .quality_flags
                .contains(&"execution_failures_present".to_string())
        );

        let malloc_row = report
            .symbols
            .iter()
            .find(|row| row.symbol == "malloc")
            .expect("malloc row");
        assert_eq!(malloc_row.case_count, 0);
        assert!(
            malloc_row
                .quality_flags
                .contains(&"missing_fixture_cases".to_string())
        );
    }
}
