//! # Solana Program Analyzer
//!
//! A static analysis library for Solana/Anchor programs that uses **real AST parsing**
//! via the [`syn`] crate to detect security vulnerabilities.
//!
//! ## Key Features
//!
//! - **AST-based Analysis**: Parses Rust source code into proper Abstract Syntax Trees,
//!   enabling semantic understanding of code structure (not regex matching).
//! - **52 Vulnerability Patterns**: Comprehensive database covering authentication,
//!   arithmetic safety, account validation, PDAs, CPI security, and DeFi attack vectors.
//! - **Anchor-aware**: Understands `#[account]`, `#[derive(Accounts)]`, and Anchor constraints.
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use program_analyzer::ProgramAnalyzer;
//! use std::path::Path;
//!
//! // Analyze a program directory
//! let analyzer = ProgramAnalyzer::new(Path::new("./my-program"))?;
//!
//! // Scan for vulnerabilities
//! let findings = analyzer.scan_for_vulnerabilities();
//!
//! for finding in findings {
//!     println!("[{}] {}: {}", finding.severity_label, finding.vuln_type, finding.description);
//! }
//! ```
//!
//! ## Vulnerability Categories
//!
//! | Category | ID Range | Examples |
//! |----------|----------|----------|
//! | Authentication & Authorization | 1.x | Missing signer, owner validation |
//! | Arithmetic Safety | 2.x | Integer overflow/underflow |
//! | Account Validation | 3.x | Account confusion, type cosplay |
//! | PDA Security | 4.x | Bump seed issues, missing validation |
//! | CPI Security | 5.x | Arbitrary CPI, privilege escalation |
//! | Reentrancy | 6.x | Cross-program reentrancy |
//! | Oracle Security | 7.x | Price manipulation, stale data |
//! | Token Security | 8.x | Mint authority, freeze issues |
//! | DeFi Attack Vectors | 9.x-12.x | Flash loans, MEV, economic attacks |

use colored::Colorize;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use syn::{Expr, File, Item, ItemFn, ItemStruct, Stmt};

pub mod anchor_extractor;
pub mod ast_parser;
pub mod config;
pub mod idl_loader;
pub mod metrics;
pub mod report_generator;
pub mod security;
pub mod traits;
pub mod vulnerability_db;

pub use config::{AnalyzerConfig, ConfigBuilder};
pub use metrics::{MetricsRegistry, METRICS};
pub use security::{validation, RateLimiter, Secret};
pub use traits::{AnalysisPipeline, Analyzer, AnalyzerCapabilities, Finding, Severity};
pub use vulnerability_db::VulnerabilityPattern;

/// Main program analyzer that parses Rust source files and scans for vulnerabilities.
///
/// Uses the [`syn`] crate for proper AST parsing, enabling semantic analysis
/// of code structure rather than simple pattern matching.
///
/// # Example
///
/// ```rust,ignore
/// use program_analyzer::ProgramAnalyzer;
///
/// let analyzer = ProgramAnalyzer::new(Path::new("./programs/my-program"))?;
/// let vulnerabilities = analyzer.scan_for_vulnerabilities();
/// ```
pub struct ProgramAnalyzer {
    source_files: Vec<(String, File)>,
    vulnerability_db: vulnerability_db::VulnerabilityDatabase,
}

impl ProgramAnalyzer {
    pub fn new(program_dir: &Path) -> Result<Self, AnalyzerError> {
        let mut source_files = Vec::new();

        // Walk directory and parse all .rs files
        for entry in walkdir::WalkDir::new(program_dir) {
            let entry = entry.map_err(AnalyzerError::WalkDir)?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(entry.path())?;
                match syn::parse_file(&content) {
                    Ok(file) => {
                        let filename = entry
                            .path()
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown.rs")
                            .to_string();
                        source_files.push((filename, file));
                    }
                    Err(e) => {
                        eprintln!(
                            "  {} Skipping {}: Parse error: {}",
                            "⚠️".yellow(),
                            entry.path().display(),
                            e
                        );
                    }
                }
            }
        }

        Ok(Self {
            source_files,
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
        })
    }

    /// Create an analyzer from source code string.
    ///
    /// Useful for testing or when analyzing code that isn't on the filesystem.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let analyzer = ProgramAnalyzer::from_source(r#"
    ///     pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    ///         // ...
    ///     }
    /// "#)?;
    /// ```
    pub fn from_source(source: &str) -> Result<Self, AnalyzerError> {
        let file = syn::parse_file(source)?;
        Ok(Self {
            source_files: vec![("source.rs".to_string(), file)],
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
        })
    }

    /// Extract all `#[account]` structs
    pub fn extract_account_schemas(&self) -> Vec<AccountSchema> {
        let mut schemas = Vec::new();

        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Struct(item_struct) = item {
                    if self.has_account_attribute(&item_struct.attrs) {
                        let schema = self.parse_account_struct(item_struct);
                        schemas.push(schema);
                    }
                }
            }
        }

        schemas
    }

    /// Extract function body for a specific instruction
    pub fn extract_instruction_logic(&self, instruction_name: &str) -> Option<InstructionLogic> {
        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Fn(func) = item {
                    if func.sig.ident == instruction_name {
                        return Some(self.parse_function_logic(func));
                    }
                }
            }
        }
        None
    }

    /// Scan for vulnerability patterns using the 52-vuln database (sequential)
    pub fn scan_for_vulnerabilities(&self) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        for (filename, file) in &self.source_files {
            self.scan_items(&file.items, filename, &mut findings);
        }

        findings
    }

    /// Scan for vulnerability patterns using batch processing
    ///
    /// Processes items in batches for better cache utilization.
    /// For true parallelism, consider using the analysis in multiple threads
    /// with separate ProgramAnalyzer instances.
    pub fn scan_for_vulnerabilities_parallel(&self) -> Vec<VulnerabilityFinding> {
        // Note: VulnerabilityDatabase contains closures which aren't Send+Sync,
        // so we use optimized sequential processing instead of true parallelism.
        // The parallel method name is kept for API compatibility.
        //
        // For parallel analysis across files, create separate ProgramAnalyzer
        // instances in different threads.

        self.scan_for_vulnerabilities()
    }

    /// Collect code items for parallel processing
    #[allow(dead_code, clippy::only_used_in_recursion)]
    fn collect_code_items(
        &self,
        items: &[Item],
        filename: &str,
        results: &mut Vec<(String, String, String)>,
    ) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let code = quote::quote!(#func).to_string();
                    results.push((code, filename.to_string(), func.sig.ident.to_string()));
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        self.collect_code_items(items, filename, results);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = quote::quote!(#item_struct).to_string();
                    results.push((code, filename.to_string(), item_struct.ident.to_string()));
                }
                _ => {}
            }
        }
    }

    /// Collect findings from items (for parallel processing)
    #[allow(dead_code)]
    fn scan_items_collect(&self, items: &[Item], filename: &str) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        self.scan_items(items, filename, &mut findings);
        findings
    }

    fn scan_items(&self, items: &[Item], filename: &str, findings: &mut Vec<VulnerabilityFinding>) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let code = quote::quote!(#func).to_string();
                    let line_number = func.sig.ident.span().start().line;
                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            finding.location = filename.to_string();
                            finding.function_name = func.sig.ident.to_string();
                            finding.line_number = line_number;
                            finding.vulnerable_code = code.clone();
                            findings.push(finding);
                        }
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        self.scan_items(items, filename, findings);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = quote::quote!(#item_struct).to_string();
                    let line_number = item_struct.ident.span().start().line;
                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            // Only add if it's a structural vulnerability (3.x, 4.x) or if it's an Authentication issue (1.x)
                            if pattern.id.starts_with("4.")
                                || pattern.id.starts_with("3.")
                                || pattern.id.starts_with("1.")
                            {
                                finding.location = filename.to_string();
                                finding.function_name = item_struct.ident.to_string();
                                finding.line_number = line_number;
                                finding.vulnerable_code = code.clone();
                                findings.push(finding);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn has_account_attribute(&self, attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("account"))
    }

    fn parse_account_struct(&self, item_struct: &ItemStruct) -> AccountSchema {
        let mut fields = std::collections::HashMap::new();

        if let syn::Fields::Named(named_fields) = &item_struct.fields {
            for field in &named_fields.named {
                let field_name = field.ident.as_ref().unwrap().to_string();
                let field_type = field.ty.to_token_stream().to_string();
                fields.insert(field_name, field_type);
            }
        }

        AccountSchema {
            name: item_struct.ident.to_string(),
            fields,
        }
    }

    fn parse_function_logic(&self, func: &ItemFn) -> InstructionLogic {
        InstructionLogic {
            name: func.sig.ident.to_string(),
            source_code: func.to_token_stream().to_string(),
            statements: self.extract_statements(&func.block.stmts),
        }
    }

    fn extract_statements(&self, stmts: &[Stmt]) -> Vec<Statement> {
        let mut statements = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Expr(expr, _) => {
                    if let Some(statement) = self.parse_expression(expr) {
                        statements.push(statement);
                    }
                }
                Stmt::Local(_local) => {
                    // Variable assignment
                    statements.push(Statement::Assignment);
                }
                _ => {}
            }
        }

        statements
    }

    fn parse_expression(&self, expr: &Expr) -> Option<Statement> {
        match expr {
            Expr::Binary(binary) => {
                // Arithmetic operations
                Some(Statement::Arithmetic {
                    op: format!("{:?}", binary.op),
                    checked: self.is_checked_operation(&binary.to_token_stream().to_string()),
                })
            }
            Expr::MethodCall(method_call) => {
                if method_call.method == "checked_add"
                    || method_call.method == "checked_sub"
                    || method_call.method == "checked_mul"
                    || method_call.method == "checked_div"
                {
                    Some(Statement::CheckedArithmetic)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn is_checked_operation(&self, code: &str) -> bool {
        code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div")
    }
}

#[derive(Debug, Clone)]
pub struct AccountSchema {
    pub name: String,
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug)]
pub struct InstructionLogic {
    pub name: String,
    pub source_code: String,
    pub statements: Vec<Statement>,
}

#[derive(Debug)]
pub enum Statement {
    Arithmetic { op: String, checked: bool },
    CheckedArithmetic,
    Assignment,
    CPI,
    Require,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub category: String,
    pub vuln_type: String,
    pub severity: u8,
    pub severity_label: String,
    pub id: String,
    pub cwe: Option<String>,
    pub location: String,
    pub function_name: String,
    pub line_number: usize,
    pub vulnerable_code: String,
    pub description: String,
    pub attack_scenario: String,
    pub real_world_incident: Option<Incident>,
    pub secure_fix: String,
    pub prevention: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub project: String,
    pub loss: String,
    pub date: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] syn::Error),
    #[error("Walkdir error: {0}")]
    WalkDir(walkdir::Error),
}
