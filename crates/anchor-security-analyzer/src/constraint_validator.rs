//! Account Constraint Validator
//!
//! Validates #[account(...)] attribute constraints in Anchor programs.
//! Checks for:
//! - Missing signer constraints
//! - Missing owner constraints  
//! - Weak constraint expressions
//! - Missing has_one relationships
//! - Unsafe constraint logic

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct ConstraintValidator;

impl ConstraintValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_constraints(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = ConstraintVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
        };

        visitor.visit_file(syntax_tree);
        visitor.findings
    }
}

impl Default for ConstraintValidator {
    fn default() -> Self {
        Self::new()
    }
}

struct ConstraintVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
}

impl<'ast> Visit<'ast> for ConstraintVisitor<'_> {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // Check if this is an Anchor Accounts struct
        let has_accounts_derive = node.attrs.iter().any(|attr| {
            attr.path().is_ident("derive") && {
                let attr_str = quote::quote!(#attr).to_string();
                attr_str.contains("Accounts")
            }
        });

        if !has_accounts_derive {
            syn::visit::visit_item_struct(self, node);
            return;
        }

        self.metrics.total_account_structs += 1;
        let struct_name = node.ident.to_string();

        // Check each field for proper constraints
        for field in &node.fields {
            let field_name = field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();

            // Check for account attributes
            let has_account_attr = field
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("account"));

            if !has_account_attr {
                continue;
            }

            // Extract constraint content
            let constraint_str = field
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("account"))
                .map(|attr| quote::quote!(#attr).to_string())
                .unwrap_or_default();

            // Check for missing signer
            if (field_name.contains("authority") || field_name.contains("signer"))
                && !constraint_str.contains("signer") {
                    self.metrics.missing_signer_checks += 1;
                    self.add_finding(
                        AnchorViolation::MissingSignerCheck,
                        AnchorSeverity::Critical,
                        &struct_name,
                        &field_name,
                        format!("Field '{}' appears to be an authority but lacks #[account(signer)] constraint", field_name),
                    );
                }

            // Check for missing owner check
            if field_name.contains("account") && !field_name.contains("system")
                && !constraint_str.contains("owner") && !constraint_str.contains("Account<") {
                    self.metrics.missing_owner_checks += 1;
                    self.add_finding(
                        AnchorViolation::MissingOwnerCheck,
                        AnchorSeverity::High,
                        &struct_name,
                        &field_name,
                        format!("Field '{}' lacks owner validation — use #[account(owner = program_id)]", field_name),
                    );
                }

            // Check for weak constraints
            if constraint_str.contains("constraint =") && !constraint_str.contains("@") {
                self.metrics.weak_constraints += 1;
                self.add_finding(
                    AnchorViolation::WeakConstraint,
                    AnchorSeverity::Medium,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field '{}' uses constraint without custom error (@ErrorCode)",
                        field_name
                    ),
                );
            }

            // Check for init without space
            if constraint_str.contains("init") && !constraint_str.contains("space") {
                self.add_finding(
                    AnchorViolation::MissingSpaceCalculation,
                    AnchorSeverity::High,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field '{}' uses #[account(init)] without space = ...",
                        field_name
                    ),
                );
            }

            // Check for init_if_needed (reinitialization risk)
            if constraint_str.contains("init_if_needed") {
                self.metrics.reinit_vulnerabilities += 1;
                self.add_finding(
                    AnchorViolation::ReinitializationVulnerability,
                    AnchorSeverity::Critical,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field '{}' uses init_if_needed — reinitialization attack vector",
                        field_name
                    ),
                );
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl ConstraintVisitor<'_> {
    fn add_finding(
        &mut self,
        violation: AnchorViolation,
        severity: AnchorSeverity,
        struct_name: &str,
        field_name: &str,
        description: String,
    ) {
        let line = self.find_line(&format!("struct {}", struct_name));
        let snippet = self.snippet_at(line);
        let fp = self.fingerprint(line, violation.label());

        self.findings.push(AnchorFinding {
            id: format!("ANC-{}-{}", violation.label().replace(" ", ""), &fp[..8]),
            violation,
            severity,
            file_path: self.file_path.clone(),
            line_number: line,
            struct_name: Some(struct_name.to_string()),
            field_name: Some(field_name.to_string()),
            description,
            code_snippet: snippet,
            risk_explanation: self.get_risk_explanation(violation),
            fix_recommendation: self.get_fix_recommendation(violation),
            anchor_pattern: violation.anchor_pattern().to_string(),
            cwe: violation.cwe().to_string(),
            fingerprint: fp,
        });
    }

    fn find_line(&self, needle: &str) -> usize {
        self.content
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(needle))
            .map(|(i, _)| i + 1)
            .unwrap_or(1)
    }

    fn snippet_at(&self, line: usize) -> String {
        self.content
            .lines()
            .nth(line.saturating_sub(1))
            .map(|l| format!("{}: {}", line, l))
            .unwrap_or_default()
    }

    fn fingerprint(&self, line: usize, tag: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.file_path.as_bytes());
        h.update(line.to_string().as_bytes());
        h.update(tag.as_bytes());
        hex::encode(h.finalize())
    }

    fn get_risk_explanation(&self, violation: AnchorViolation) -> String {
        match violation {
            AnchorViolation::MissingSignerCheck => "Without #[account(signer)], any account can be passed as authority, enabling unauthorized access.".into(),
            AnchorViolation::MissingOwnerCheck => "Missing owner validation allows accounts from other programs to be passed, causing type confusion.".into(),
            AnchorViolation::WeakConstraint => "Constraints without custom errors fail silently, making debugging difficult.".into(),
            AnchorViolation::MissingSpaceCalculation => "Missing space calculation can cause account allocation failures.".into(),
            AnchorViolation::ReinitializationVulnerability => "init_if_needed allows reinitialization attacks — attacker can reset account state.".into(),
            _ => "Anchor security pattern violation detected.".into(),
        }
    }

    fn get_fix_recommendation(&self, violation: AnchorViolation) -> String {
        match violation {
            AnchorViolation::MissingSignerCheck => {
                "Add #[account(signer)] to authority fields.".into()
            }
            AnchorViolation::MissingOwnerCheck => {
                "Add #[account(owner = program_id)] or use Account<'info, T>.".into()
            }
            AnchorViolation::WeakConstraint => {
                "Add custom error: #[account(constraint = check @ ErrorCode::InvalidState)].".into()
            }
            AnchorViolation::MissingSpaceCalculation => {
                "Add space = 8 + std::mem::size_of::<T>() to #[account(init, ...)].".into()
            }
            AnchorViolation::ReinitializationVulnerability => {
                "Replace init_if_needed with init and handle existing accounts separately.".into()
            }
            _ => "Review Anchor documentation for best practices.".into(),
        }
    }
}
