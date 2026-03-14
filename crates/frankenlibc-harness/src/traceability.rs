//! Spec section mapping and traceability matrix.
//!
//! Maps every test case to POSIX/C11 spec sections and TSM policy sections.

use serde::{Deserialize, Serialize};

use crate::report::PosixObligationMatrixReport;

/// A traceability entry mapping a test to spec requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceabilityEntry {
    /// Test case identifier.
    pub test_id: String,
    /// Symbol/API covered by the test.
    #[serde(default)]
    pub symbol: String,
    /// POSIX/C11 spec section (e.g., "POSIX.1-2017 memcpy").
    pub spec_section: String,
    /// TSM policy section (e.g., "TSM-COPY-1: bounds clamping").
    pub tsm_section: Option<String>,
    /// Requirement category.
    pub category: String,
    /// Brief description.
    pub description: String,
    /// Current coverage state for the underlying obligation.
    #[serde(default)]
    pub coverage_state: String,
    /// Artifact references proving the mapping.
    #[serde(default)]
    pub artifact_refs: Vec<String>,
}

/// Traceability matrix builder.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceabilityMatrix {
    entries: Vec<TraceabilityEntry>,
}

impl TraceabilityMatrix {
    /// Create a new empty matrix.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a traceability entry.
    pub fn add(&mut self, entry: TraceabilityEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Build a traceability matrix from the machine-readable obligation report.
    #[must_use]
    pub fn from_posix_obligation_report(report: &PosixObligationMatrixReport) -> Self {
        let mut matrix = Self::default();
        for row in &report.obligations {
            if row.test_refs.is_empty() {
                continue;
            }

            let category = row.obligation_kinds.join("+");
            let description = format!(
                "{} [{}] via {}",
                row.symbol,
                row.coverage_state,
                row.test_refs.join(", ")
            );
            for test_ref in &row.test_refs {
                matrix.add(TraceabilityEntry {
                    test_id: test_ref.clone(),
                    symbol: row.symbol.clone(),
                    spec_section: row.posix_ref.clone(),
                    tsm_section: None,
                    category: category.clone(),
                    description: description.clone(),
                    coverage_state: row.coverage_state.clone(),
                    artifact_refs: row.artifact_refs.clone(),
                });
            }
        }
        matrix
    }

    /// Build with asupersync conformance integration.
    #[cfg(feature = "asupersync-tooling")]
    pub fn build_with_asupersync(&self) -> (String, String) {
        use asupersync_conformance::TraceabilityMatrixBuilder;

        let mut builder = TraceabilityMatrixBuilder::new();
        for entry in &self.entries {
            builder = builder.requirement_with_category(
                &entry.test_id,
                &entry.description,
                &entry.category,
            );
        }
        let mut matrix = builder.build();
        let markdown = matrix.to_markdown();
        let json = matrix
            .to_json()
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        (markdown, json)
    }

    /// Render as markdown (fallback without asupersync).
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# Traceability Matrix\n\n");
        out.push_str("| Test | Symbol | Spec | Coverage | Category |\n");
        out.push_str("|------|--------|------|----------|----------|\n");
        for e in &self.entries {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                e.test_id, e.symbol, e.spec_section, e.coverage_state, e.category
            ));
        }
        out
    }

    /// Render as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Entries count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the matrix is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
