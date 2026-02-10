//! Signer Checker — validates signer constraints

use crate::metrics::AnchorMetrics;
use crate::report::AnchorFinding;

pub struct SignerChecker;

impl SignerChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn check_signers(
        &self,
        _file_path: &str,
        _syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let findings = Vec::new();

        // Regex-based detection for missing signer checks
        for line in content.lines() {
            if line.contains("authority") && line.contains("#[account")
                && !line.contains("signer") && !line.contains("has_one") {
                    metrics.missing_signer_checks += 1;
                }
        }

        findings
    }
}

impl Default for SignerChecker {
    fn default() -> Self {
        Self::new()
    }
}
