//! CPI Guard Detector — detects missing Cross-Program Invocation guards

use crate::metrics::AnchorMetrics;
use crate::report::AnchorFinding;

pub struct CPIGuardDetector;

impl CPIGuardDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_cpi_guards(
        &self,
        _file_path: &str,
        _syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let findings = Vec::new();

        // Check for CPI calls without signer guards
        for line in content.lines() {
            if (line.contains("invoke") || line.contains("CpiContext")) && !line.contains("signer")
            {
                metrics.missing_cpi_guards += 1;
            }
        }

        findings
    }
}

impl Default for CPIGuardDetector {
    fn default() -> Self {
        Self::new()
    }
}
