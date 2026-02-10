//! PDA Validator — checks Program Derived Address validation

use crate::metrics::AnchorMetrics;
use crate::report::AnchorFinding;

pub struct PDAValidator;

impl PDAValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_pda(
        &self,
        _file_path: &str,
        _syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let findings = Vec::new();

        // Check for seeds without bump
        for line in content.lines() {
            if line.contains("seeds =") && !line.contains("bump") {
                metrics.missing_pda_validation += 1;
            }
        }

        findings
    }
}

impl Default for PDAValidator {
    fn default() -> Self {
        Self::new()
    }
}
