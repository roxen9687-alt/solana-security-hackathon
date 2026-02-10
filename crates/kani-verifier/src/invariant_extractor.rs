//! Invariant Extractor
//!
//! Deeply parses Solana/Anchor Rust source using the `syn` crate to extract
//! program invariants that should hold across all states. These invariants
//! are then turned into Kani proof harnesses.

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{File, Item, ItemFn};

/// Extracts invariants from Solana program source code via AST analysis.
pub struct InvariantExtractor {
    /// Tracks seen function names to avoid duplicate invariants
    seen_functions: HashSet<String>,
    /// Mapping from account struct name → fields
    account_schemas: HashMap<String, Vec<(String, String)>>,
}

impl InvariantExtractor {
    pub fn new() -> Self {
        Self {
            seen_functions: HashSet::new(),
            account_schemas: HashMap::new(),
        }
    }

    /// Extract invariants from a Rust source file.
    pub fn extract_from_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<ExtractedInvariant>, crate::KaniError> {
        let file = syn::parse_file(source)
            .map_err(|e| crate::KaniError::ParseError(format!("{}: {}", filename, e)))?;

        let mut invariants = Vec::new();

        // Phase 1: Collect account schemas
        self.collect_account_schemas(&file);

        // Phase 2: Extract function-level invariants
        self.extract_function_invariants(&file, filename, &mut invariants);

        // Phase 3: Extract struct-level invariants
        self.extract_struct_invariants(&file, filename, &mut invariants);

        // Phase 4: Extract impl-block invariants
        self.extract_impl_invariants(&file, filename, &mut invariants);

        Ok(invariants)
    }

    /// Collect all account struct definitions.
    fn collect_account_schemas(&mut self, file: &File) {
        for item in &file.items {
            if let Item::Struct(item_struct) = item {
                let has_account_attr = item_struct.attrs.iter().any(|attr| {
                    let path_str = attr.path().to_token_stream().to_string();
                    path_str.contains("account") || path_str.contains("Account")
                });

                let has_derive_accounts = item_struct.attrs.iter().any(|attr| {
                    let full = attr.to_token_stream().to_string();
                    full.contains("Accounts") || full.contains("account")
                });

                if has_account_attr || has_derive_accounts {
                    let name = item_struct.ident.to_string();
                    let fields: Vec<(String, String)> =
                        if let syn::Fields::Named(named) = &item_struct.fields {
                            named
                                .named
                                .iter()
                                .filter_map(|f| {
                                    f.ident.as_ref().map(|id| {
                                        (id.to_string(), f.ty.to_token_stream().to_string())
                                    })
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                    self.account_schemas.insert(name, fields);
                }
            }

            // Also descend into modules
            if let Item::Mod(item_mod) = item {
                if let Some((_, items)) = &item_mod.content {
                    let inner_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: items.clone(),
                    };
                    self.collect_account_schemas(&inner_file);
                }
            }
        }
    }

    /// Extract invariants from functions in the AST.
    fn extract_function_invariants(
        &mut self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            match item {
                Item::Fn(func) => {
                    self.analyze_function(func, filename, invariants);
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        let inner_file = File {
                            shebang: None,
                            attrs: Vec::new(),
                            items: items.clone(),
                        };
                        self.extract_function_invariants(&inner_file, filename, invariants);
                    }
                }
                Item::Impl(item_impl) => {
                    for impl_item in &item_impl.items {
                        if let syn::ImplItem::Fn(method) = impl_item {
                            let func_code = method.to_token_stream().to_string();
                            let func_name = method.sig.ident.to_string();

                            // Create a synthetic ItemFn for analysis
                            self.analyze_method_code(&func_name, &func_code, filename, invariants);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Analyze a single function for invariant patterns.
    fn analyze_function(
        &mut self,
        func: &ItemFn,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        let func_name = func.sig.ident.to_string();
        let func_code = func.to_token_stream().to_string();
        let line_number = func.sig.ident.span().start().line;

        if self.seen_functions.contains(&func_name) {
            return;
        }
        self.seen_functions.insert(func_name.clone());

        // Check for Context<T> parameter (Anchor instruction handler)
        let is_instruction = func.sig.inputs.iter().any(|arg| {
            let arg_str = arg.to_token_stream().to_string();
            arg_str.contains("Context")
        });

        // Detect arithmetic patterns
        let has_unchecked_arith = Self::detect_unchecked_arithmetic(&func_code);
        let has_checked_arith = Self::detect_checked_arithmetic(&func_code);

        if has_unchecked_arith {
            invariants.push(ExtractedInvariant {
                name: format!("{}_arithmetic_safety", func_name),
                kind: InvariantKind::ArithmeticBounds,
                expression: format!(
                    "All arithmetic in '{}' must not overflow/underflow at u64 boundary",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: has_checked_arith,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: if has_checked_arith { 3 } else { 5 },
                confidence: if has_unchecked_arith && !has_checked_arith {
                    95
                } else {
                    60
                },
                related_accounts: Vec::new(),
            });
        }

        // Detect signer/authority patterns
        let has_signer_check = Self::detect_signer_check(&func_code);

        if is_instruction && !has_signer_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_access_control", func_name),
                kind: InvariantKind::AccessControl,
                expression: format!(
                    "Instruction '{}' must validate signer/authority before state mutation",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 5,
                confidence: 90,
                related_accounts: Vec::new(),
            });
        }

        // Detect owner check patterns
        let has_owner_check = Self::detect_owner_check(&func_code);

        if is_instruction && !has_owner_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_account_ownership", func_name),
                kind: InvariantKind::AccountOwnership,
                expression: format!(
                    "Instruction '{}' must verify account ownership before access",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 4,
                confidence: 85,
                related_accounts: Vec::new(),
            });
        }

        // Detect PDA validation
        let has_pda_check = Self::detect_pda_validation(&func_code);
        let uses_pda = func_code.contains("find_program_address")
            || func_code.contains("create_program_address")
            || func_code.contains("seeds")
            || func_code.contains("bump");

        if uses_pda && !has_pda_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_pda_validation", func_name),
                kind: InvariantKind::PdaValidation,
                expression: format!(
                    "PDA seeds in '{}' must be validated to prevent substitution",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: has_pda_check,
                severity: 4,
                confidence: 80,
                related_accounts: Vec::new(),
            });
        }

        // Detect balance-related operations for conservation invariants
        let modifies_balance = func_code.contains("balance")
            || func_code.contains("amount")
            || func_code.contains("lamports")
            || func_code.contains("transfer")
            || func_code.contains("mint_to")
            || func_code.contains("burn");

        if modifies_balance && is_instruction {
            invariants.push(ExtractedInvariant {
                name: format!("{}_balance_conservation", func_name),
                kind: InvariantKind::BalanceConservation,
                expression: format!(
                    "Token/SOL balance changes in '{}' must conserve total supply (no creation from nothing)",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: has_checked_arith,
                has_signer_check,
                has_owner_check,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 5,
                confidence: 75,
                related_accounts: Vec::new(),
            });
        }

        // Detect state transition patterns
        let has_state_enum = func_code.contains("State::")
            || func_code.contains("Status::")
            || func_code.contains("state =")
            || func_code.contains("status =");

        if has_state_enum && is_instruction {
            invariants.push(ExtractedInvariant {
                name: format!("{}_state_transition", func_name),
                kind: InvariantKind::StateTransition,
                expression: format!(
                    "State transitions in '{}' must follow valid FSM (no illegal transitions)",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 4,
                confidence: 70,
                related_accounts: Vec::new(),
            });
        }
    }

    /// Analyze a method's code string.
    fn analyze_method_code(
        &mut self,
        func_name: &str,
        func_code: &str,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        if self.seen_functions.contains(func_name) {
            return;
        }
        self.seen_functions.insert(func_name.to_string());

        let is_instruction = func_code.contains("Context");
        let has_unchecked = Self::detect_unchecked_arithmetic(func_code);
        let has_checked = Self::detect_checked_arithmetic(func_code);

        if has_unchecked {
            invariants.push(ExtractedInvariant {
                name: format!("{}_arithmetic_safety", func_name),
                kind: InvariantKind::ArithmeticBounds,
                expression: format!(
                    "All arithmetic in '{}' must not overflow/underflow",
                    func_name
                ),
                source_location: format!("{}:method", filename),
                function_name: func_name.to_string(),
                has_checked_math: has_checked,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: if has_checked { 3 } else { 5 },
                confidence: if has_unchecked && !has_checked {
                    95
                } else {
                    60
                },
                related_accounts: Vec::new(),
            });
        }

        if is_instruction {
            let has_signer = Self::detect_signer_check(func_code);
            if !has_signer {
                invariants.push(ExtractedInvariant {
                    name: format!("{}_access_control", func_name),
                    kind: InvariantKind::AccessControl,
                    expression: format!("Instruction '{}' requires signer validation", func_name),
                    source_location: format!("{}:method", filename),
                    function_name: func_name.to_string(),
                    has_checked_math: false,
                    has_signer_check: has_signer,
                    has_owner_check: false,
                    has_bounds_check: false,
                    has_pda_seeds_check: false,
                    severity: 5,
                    confidence: 90,
                    related_accounts: Vec::new(),
                });
            }
        }
    }

    /// Extract struct-level invariants from #[account] structs.
    #[allow(clippy::only_used_in_recursion)]
    fn extract_struct_invariants(
        &self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            if let Item::Struct(item_struct) = item {
                let _struct_code = item_struct.to_token_stream().to_string();
                let struct_name = item_struct.ident.to_string();
                let line_number = item_struct.ident.span().start().line;

                let is_account = item_struct.attrs.iter().any(|a| {
                    let s = a.to_token_stream().to_string();
                    s.contains("account") || s.contains("Account")
                });

                if !is_account {
                    continue;
                }

                // Check if account struct has balance/amount fields
                let mut balance_fields = Vec::new();
                let mut account_fields = Vec::new();

                if let syn::Fields::Named(named) = &item_struct.fields {
                    for field in &named.named {
                        let field_name = field
                            .ident
                            .as_ref()
                            .map(|i| i.to_string())
                            .unwrap_or_default();
                        let field_type = field.ty.to_token_stream().to_string();

                        if field_name.contains("balance")
                            || field_name.contains("amount")
                            || field_name.contains("supply")
                            || field_name.contains("total")
                        {
                            balance_fields.push(field_name.clone());
                        }

                        if field_type.contains("Pubkey") || field_type.contains("AccountInfo") {
                            account_fields.push(field_name.clone());
                        }
                    }
                }

                if !balance_fields.is_empty() {
                    invariants.push(ExtractedInvariant {
                        name: format!("{}_balance_fields_bounded", struct_name),
                        kind: InvariantKind::BoundsCheck,
                        expression: format!(
                            "Account '{}' balance fields ({}) must be within valid range [0, u64::MAX]",
                            struct_name,
                            balance_fields.join(", ")
                        ),
                        source_location: format!("{}:{}", filename, line_number),
                        function_name: struct_name.clone(),
                        has_checked_math: false,
                        has_signer_check: false,
                        has_owner_check: false,
                        has_bounds_check: true,
                        has_pda_seeds_check: false,
                        severity: 3,
                        confidence: 95,
                        related_accounts: account_fields.clone(),
                    });
                }
            }

            if let Item::Mod(item_mod) = item {
                if let Some((_, items)) = &item_mod.content {
                    let inner_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: items.clone(),
                    };
                    self.extract_struct_invariants(&inner_file, filename, invariants);
                }
            }
        }
    }

    /// Extract invariants from impl blocks.
    fn extract_impl_invariants(
        &self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            if let Item::Impl(item_impl) = item {
                let impl_type = item_impl.self_ty.to_token_stream().to_string();

                for impl_item in &item_impl.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let method_name = method.sig.ident.to_string();
                        let method_code = method.to_token_stream().to_string();

                        // Check for `require!` or `assert!` within methods
                        let constraint_count = method_code.matches("require!").count()
                            + method_code.matches("require_keys_eq!").count()
                            + method_code.matches("assert!").count()
                            + method_code.matches("assert_eq!").count();

                        if constraint_count > 0 {
                            invariants.push(ExtractedInvariant {
                                name: format!("{}_{}_constraints", impl_type, method_name),
                                kind: InvariantKind::BoundsCheck,
                                expression: format!(
                                    "{} constraints in {}.{} must hold in all execution paths",
                                    constraint_count, impl_type, method_name
                                ),
                                source_location: format!("{}:impl", filename),
                                function_name: method_name.clone(),
                                has_checked_math: false,
                                has_signer_check: false,
                                has_owner_check: false,
                                has_bounds_check: true,
                                has_pda_seeds_check: false,
                                severity: 3,
                                confidence: 85,
                                related_accounts: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    // ─── Detection Helpers ────────────────────────────────────────────────

    /// Detect unchecked arithmetic (raw +, -, *, /).
    fn detect_unchecked_arithmetic(code: &str) -> bool {
        // Look for patterns like `a + b`, `x - y`, etc. that are NOT inside checked calls
        let has_raw_ops = code.contains(" + ")
            || code.contains(" - ")
            || code.contains(" * ")
            || code.contains(" / ");

        let has_assignment_ops = code.contains("+= ")
            || code.contains("-= ")
            || code.contains("*= ")
            || code.contains("/= ");

        (has_raw_ops || has_assignment_ops) && !Self::detect_checked_arithmetic(code)
    }

    /// Detect checked arithmetic calls.
    fn detect_checked_arithmetic(code: &str) -> bool {
        code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div")
            || code.contains("saturating_add")
            || code.contains("saturating_sub")
            || code.contains("saturating_mul")
            || code.contains("overflowing_add")
            || code.contains("overflowing_sub")
    }

    /// Detect signer/authority checks.
    fn detect_signer_check(code: &str) -> bool {
        code.contains("is_signer")
            || code.contains("Signer")
            || code.contains("has_one")
            || code.contains("constraint")
            || code.contains("require_keys_eq!")
            || code.contains("account(signer")
            || code.contains("authority")
            || code.contains(".key()")
    }

    /// Detect account owner checks.
    fn detect_owner_check(code: &str) -> bool {
        code.contains("owner")
            || code.contains("Owner")
            || code.contains("has_one")
            || code.contains("constraint")
            || code.contains("Account<") // Anchor Account<> wrapper validates owner
    }

    /// Detect PDA validation.
    fn detect_pda_validation(code: &str) -> bool {
        code.contains("find_program_address")
            || code.contains("create_program_address")
            || code.contains("seeds =")
            || code.contains("bump =")
            || code.contains("account(seeds")
    }
}

impl Default for InvariantExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// An invariant extracted from program source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedInvariant {
    /// Human-readable invariant name
    pub name: String,
    /// Category of invariant
    pub kind: InvariantKind,
    /// Formal or semi-formal invariant expression
    pub expression: String,
    /// Source file and line
    pub source_location: String,
    /// Function containing this invariant
    pub function_name: String,
    // ─── Detection flags ─────
    pub has_checked_math: bool,
    pub has_signer_check: bool,
    pub has_owner_check: bool,
    pub has_bounds_check: bool,
    pub has_pda_seeds_check: bool,
    /// Severity (1-5)
    pub severity: u8,
    /// Confidence percentage (0-100)
    pub confidence: u8,
    /// Related account names
    pub related_accounts: Vec<String>,
}

/// Categories of invariants that Kani can verify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantKind {
    /// Arithmetic operations must not overflow/underflow
    ArithmeticBounds,
    /// Token/SOL balances must be conserved
    BalanceConservation,
    /// Only authorized signers can mutate state
    AccessControl,
    /// Account ownership must match expected program
    AccountOwnership,
    /// State machine transitions must be valid
    StateTransition,
    /// Values must be within protocol-defined limits
    BoundsCheck,
    /// PDA seeds must be properly validated
    PdaValidation,
}
