# Part 3 — Complete Crate Catalogue & Architecture Reference

> **Solana Security Swarm** — Full engineering reference for every crate, data structure, and integration point.

---

## Table of Contents

1. [Workspace Overview](#1-workspace-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Crate Catalogue](#3-crate-catalogue)
   - 3.1 [Core Analysis Crates](#31-core-analysis-crates)
   - 3.2 [Formal Verification Crates](#32-formal-verification-crates)
   - 3.3 [Fuzzing Crates](#33-fuzzing-crates)
   - 3.4 [Orchestration & Pipeline Crates](#34-orchestration--pipeline-crates)
   - 3.5 [AI & Strategy Crates](#35-ai--strategy-crates)
   - 3.6 [Security Expert Crates](#36-security-expert-crates)
   - 3.7 [Infrastructure Crates](#37-infrastructure-crates)
   - 3.8 [Programs (On-Chain)](#38-programs-on-chain)
4. [Key Data Structures](#4-key-data-structures)
5. [Pipeline Flow](#5-pipeline-flow)
6. [Dependency Graph](#6-dependency-graph)
7. [Build Configuration](#7-build-configuration)
8. [Next Steps & Blockers](#8-next-steps--blockers)

---

## 1. Workspace Overview

The workspace is a Cargo workspace with **35+ crates** and **5 on-chain programs**, organized into a layered security analysis pipeline.

```
hackathon/
├── Cargo.toml              # Workspace root (resolver = "2")
├── crates/                  # 35 library crates
│   ├── orchestrator/        # Central pipeline coordinator
│   ├── program-analyzer/    # Core Rust AST static analysis
│   ├── symbolic-engine/     # Z3 SMT solver integration
│   ├── transaction-forge/   # Exploit transaction builder
│   ├── l3x-analyzer/        # AI-driven ML analysis
│   ├── ...                  # (see full catalogue below)
├── programs/                # 5 Anchor on-chain programs
│   ├── vulnerable-vault/    # Test target: vault with missing checks
│   ├── vulnerable-token/    # Test target: token with overflow bugs
│   ├── vulnerable-staking/  # Test target: staking with auth bypass
│   ├── security_shield/     # Defensive program (pausing/freezing)
│   └── exploit-registry/    # On-chain audit record storage
└── exploits/                # Standalone exploit crate
```

**Key Dependencies:**
| Category | Packages | Version |
|----------|----------|---------|
| Solana | `anchor-lang`, `solana-sdk`, `solana-client` | 0.30.1 / 1.18 |
| Parsing | `syn` (full), `quote`, `proc-macro2` | 2.0 / 1.0 |
| Symbolic | `z3` (optional, static-link) | 0.12 |
| Async | `tokio` (full), `reqwest` (json) | 1.35 / 0.11 |
| Serialization | `serde`, `serde_json`, `borsh` | 1.0 / 0.10 |

---

## 2. Architecture Diagram

```
                        ┌─────────────────────────────────────────┐
                        │         ORCHESTRATOR (audit_pipeline)   │
                        │  Merges all findings → ConfirmedExploit │
                        └────────────────┬────────────────────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          │                              │                              │
    ┌─────▼──────┐              ┌────────▼────────┐            ┌───────▼───────┐
    │  STATIC    │              │   FORMAL        │            │   DYNAMIC     │
    │  ANALYSIS  │              │   VERIFICATION  │            │   TESTING     │
    │            │              │                 │            │               │
    │• L3X (AI)  │              │• Kani (CBMC)    │            │• Trident      │
    │• Geiger    │              │• Certora (SBF)  │            │• FuzzDelSol   │
    │• Anchor    │              │• Symbolic Engine│            │• Security     │
    │• Sec3      │              │• Concolic Exec  │            │  Fuzzer       │
    │• Program   │              │• Economic       │            │• WACANA       │
    │  Analyzer  │              │  Verifier       │            │  (concolic)   │
    │• Taint     │              │• Invariant Miner│            │               │
    │• Dataflow  │              │                 │            │               │
    │• CPI       │              │                 │            │               │
    │• Abstract  │              │                 │            │               │
    │  Interp    │              │                 │            │               │
    └─────┬──────┘              └────────┬────────┘            └───────┬───────┘
          │                              │                              │
          └──────────────────────────────┼──────────────────────────────┘
                                         │
                        ┌────────────────▼────────────────────────┐
                        │         POST-ANALYSIS PIPELINE          │
                        │                                         │
                        │  ┌──────────────┐  ┌─────────────────┐  │
                        │  │ Transaction  │  │ LLM Strategist  │  │
                        │  │ Forge (PoC)  │  │ (AI strategy)   │  │
                        │  └──────┬───────┘  └────────┬────────┘  │
                        │         │                   │           │
                        │  ┌──────▼───────────────────▼────────┐  │
                        │  │  Exploit Proof + PoC Generation   │  │
                        │  └──────────────┬────────────────────┘  │
                        │                 │                        │
                        │  ┌──────────────▼────────────────────┐  │
                        │  │    On-Chain Registry + Reports     │  │
                        │  │  ┌──────────┐ ┌────────────────┐  │  │
                        │  │  │Registry  │ │ PDF/Markdown   │  │  │
                        │  │  │(Solana)  │ │ Report Gen     │  │  │
                        │  │  └──────────┘ └────────────────┘  │  │
                        │  └───────────────────────────────────┘  │
                        └─────────────────────────────────────────┘
                                         │
                        ┌────────────────▼────────────────────────┐
                        │          RUNTIME MONITORING              │
                        │                                         │
                        │  ┌──────────────┐  ┌─────────────────┐  │
                        │  │ Mainnet      │  │ TUI Dashboard   │  │
                        │  │ Guardian     │  │ (ratatui)       │  │
                        │  └──────────────┘  └─────────────────┘  │
                        │                                         │
                        │  ┌──────────────┐  ┌─────────────────┐  │
                        │  │ Mitigation   │  │ Chain Explorer  │  │
                        │  │ Engine       │  │                 │  │
                        │  └──────────────┘  └─────────────────┘  │
                        │                                         │
                        │  ┌──────────────┐                       │
                        │  │ Firedancer   │                       │
                        │  │ Monitor      │                       │
                        │  └──────────────┘                       │
                        └─────────────────────────────────────────┘
```

---

## 3. Crate Catalogue

### 3.1 Core Analysis Crates

#### `program-analyzer`
**Purpose:** Core Rust AST static analysis engine for Solana programs.

| Field | Value |
|-------|-------|
| Entry point | `ProgramAnalyzer::analyze()` |
| Input | Solana program source directory (`.rs` files) |
| Output | `VulnerabilityFinding` vector |
| Parser | `syn` 2.0 (full AST) |
| Technique | Rule-based pattern matching on AST nodes |
| Detects | Missing signer checks, unchecked arithmetic, authority bypass, PDA issues, account confusion |

**Key types consumed downstream:**
- `VulnerabilityFinding` — used by `llm-strategist`, `orchestrator`, `consensus-engine`

---

#### `l3x-analyzer`
**Purpose:** AI-driven static analyzer using ML models for vulnerability detection.

| Field | Value |
|-------|-------|
| Entry point | `L3xAnalyzer::analyze_program(&Path)` |
| Output | `L3xAnalysisReport` with `Vec<L3xFinding>` |
| Engine version | `l3x-ai-analyzer-3.2.1` |
| Confidence threshold | 0.75 (configurable) |

**5-Phase ML Pipeline:**
1. **Code Embeddings** (`CodeEmbedder`) — Transformer-based semantic understanding
2. **Control Flow GNN** (`ControlFlowGNN`) — Graph neural network for dataflow
3. **Anomaly Detection** (`AnomalyDetector`) — Zero-day pattern identification
4. **Pattern Learning** (`PatternLearner`) — Historical Solana exploit patterns
5. **Ensemble Scoring** (`EnsembleScorer`) — Multi-model confidence ranking

**Key types:**
```rust
pub struct L3xFinding {
    pub id: String,
    pub category: L3xCategory,
    pub severity: L3xSeverity,        // Critical | High | Medium | Low | Info
    pub confidence: f32,
    pub fingerprint: String,
    pub ml_reasoning: String,          // AI explanation
    pub line_number: usize,
    pub file_path: String,
    // ...
}
```

---

#### `geiger-analyzer`
**Purpose:** Unsafe Rust code detection (inspired by `cargo-geiger`).

| Field | Value |
|-------|-------|
| Entry point | `GeigerAnalyzer::analyze_program(&Path)` |
| Output | `GeigerAnalysisReport` with safety score (0-100) |
| Engine version | `cargo-geiger-analyzer-1.0.0` |

**Detection modules:**
| Module | Detects |
|--------|---------|
| `UnsafeDetector` | `unsafe {}` blocks, `unsafe fn` |
| `FFIAnalyzer` | Foreign function interface calls |
| `PointerAnalyzer` | `*const`, `*mut` raw pointer usage |
| `TransmuteDetector` | `mem::transmute` calls |

**Safety score formula:**
```
score = 100 - Σ(pattern_count / total_lines * weight)
```
Weights: asm(900) > unsafe_blocks(1000) > transmute(700) > unsafe_fn(800) > ffi(600) > pointers(500)

---

#### `anchor-security-analyzer`
**Purpose:** Anchor Framework-specific security validation.

| Field | Value |
|-------|-------|
| Entry point | `AnchorSecurityAnalyzer::analyze_program(&Path)` |
| Precondition | Checks `Cargo.toml` for `anchor-lang` dependency |
| Output | `AnchorAnalysisReport` with security score (0-100) |
| Engine version | `anchor-security-analyzer-1.0.0` |

**Validation modules:**
| Module | Checks |
|--------|--------|
| `ConstraintValidator` | `#[account(...)]` attributes correctness |
| `SignerChecker` | `has_one`, `constraint = signer` patterns |
| `PDAValidator` | Seeds and bump validation for PDA derivation |
| `CPIGuardDetector` | Missing `#[account(signer)]` on CPI calls |
| `TokenHookAnalyzer` | Token-2022 transfer hook implementation |

---

#### `sec3-analyzer`
**Purpose:** Enterprise-grade static analyzer (Soteria-style) covering 10 vulnerability categories.

| Field | Value |
|-------|-------|
| Entry point | `Sec3Analyzer::analyze_program(&Path)` |
| Output | `Sec3AnalysisReport` with security checklist |
| Engine version | `sec3-soteria-2.1.0` |

**Vulnerability Categories (with CWE mapping):**

| # | Category | CWE | Detector Module |
|---|----------|-----|-----------------|
| 1 | Missing Owner Checks | CWE-284 | `ownership_checker` |
| 2 | Integer Overflow/Underflow | CWE-190 | `integer_analyzer` |
| 3 | Account Type Confusion | CWE-345 | `account_confusion` |
| 4 | Missing Signer Validation | CWE-287 | `signer_checker` |
| 5 | Duplicate Mutable Accounts | CWE-362 | `duplicate_accounts` |
| 6 | Arbitrary CPI | CWE-94 | `cpi_guard` |
| 7 | Insecure PDA Derivation | CWE-330 | `pda_validator` |
| 8 | Close Account Drain | CWE-672 | `close_account` |
| 9 | Re-Initialization | CWE-665 | (via constraints) |
| 10 | Unchecked Remaining Accounts | CWE-20 | `remaining_accounts` |

**Security checklist output:**
```rust
vec![
    ("All accounts have owner validation",     !has(MissingOwnerCheck)),
    ("All arithmetic uses checked operations", !has(IntegerOverflow)),
    ("No raw AccountInfo without CHECK doc",   !has(AccountConfusion)),
    // ... 10 items total
]
```

---

#### `taint-analyzer`
**Purpose:** Tracks data flow from untrusted sources to sensitive sinks.
| Entry | `TaintAnalyzer` |
|-------|-----|
| Output | `TaintAnalysisReport` |

---

#### `dataflow-analyzer`
**Purpose:** Interprocedural dataflow analysis for control and data dependencies.

---

#### `abstract-interpreter`
**Purpose:** Abstract interpretation for computing sound overapproximations of program behavior.

---

#### `cpi-analyzer`
**Purpose:** Cross-Program Invocation chain analysis, detecting unsafe CPI patterns.

---

#### `git-scanner`
**Purpose:** Scans git history for security-relevant patterns (leaked keys, configuration changes).

---

### 3.2 Formal Verification Crates

#### `symbolic-engine`
**Purpose:** Z3 SMT solver integration for mathematical exploit proof generation.

| Field | Value |
|-------|-------|
| Entry point | `SymbolicEngine::prove_exploitability(instruction, vulcan_id, program_id)` |
| Solver | Z3 (via `z3` crate, statically linked) |
| Output | `Option<ExploitProof>` |
| **Requires** | System Z3 libraries |

**Key capabilities:**
- `check_arithmetic_overflow()` → Proves overflow is reachable
- `check_authority_bypass()` → Proves authority skip is satisfiable  
- `check_logic_invariant()` → Proves invariant violation
- `prove_oracle_manipulation()` → SOL-019 specific proof

**Key types:**
```rust
pub struct ExploitProof {
    pub vulnerability_type: VulnerabilityType,  // ArithmeticOverflow | AuthorityBypass | etc.
    pub constraint_system: String,              // Z3 constraint dump
    pub satisfying_assignment: HashMap<String, String>,  // Variable → Value
    pub proof_valid: bool,
    pub proof_hash: String,
    pub counterexample: Option<String>,
}
```

---

#### `kani-verifier`
**Purpose:** Integration with Kani (AWS), a bit-precise model checker using CBMC backend.

| Field | Value |
|-------|-------|
| Entry point | `KaniVerifier::verify_program(&Path)` |
| Output | `KaniVerificationReport` |
| Backend | CBMC (C Bounded Model Checker) |
| Offline fallback | Static invariant analysis when `cargo kani` unavailable |

**5-Phase Pipeline:**
1. Parse `.rs` files → extract invariants (`InvariantExtractor`)
2. Generate Solana-specific invariants (`SolanaInvariantGenerator`)
3. Generate `#[kani::proof]` harness files (`HarnessGenerator`)
4. Invoke `cargo kani` subprocess (`KaniRunner`)
5. Parse CBMC output → `PropertyCheckResult` vector

**Invariant Categories:**
| Kind | Example | Offline Check |
|------|---------|---------------|
| `ArithmeticBounds` | `total == sum_of_parts` | Has checked math? |
| `BalanceConservation` | No token creation from nothing | Undetermined (needs runtime) |
| `AccessControl` | Only authority modifies state | Has signer check? |
| `AccountOwnership` | PDA owned by correct program | Has owner check? |
| `StateTransition` | Valid FSM transitions only | Undetermined |
| `BoundsCheck` | Values within protocol limits | Has bounds check? |
| `PdaValidation` | Seeds derivation validated | Has PDA seeds check? |

**Verification Statuses:**
```rust
pub enum VerificationStatus {
    AllPropertiesHold,
    InvariantViolation,
    PartiallyVerified,
    NoPropertiesChecked,
}
```

---

#### `certora-prover`
**Purpose:** SBF bytecode-level formal verification using Certora Solana Prover.

| Field | Value |
|-------|-------|
| Entry point | `CertoraVerifier::verify_program(&Path)` |
| Input | Compiled `.so` SBF binary |
| Output | `CertoraVerificationReport` |
| Specification | CVLR (Certora Verification Language for Rust) |
| Cloud prover | `certoraSolanaProver` / `cargo certora-sbf` |
| Offline fallback | Direct SBF binary pattern analysis |

**Why SBF-level?** Source analysis misses bugs introduced by:
- LLVM optimizations (dead code elimination, reordering)
- BPF code generation (register allocation, stack management)
- Linking (cross-crate inlining, monomorphization)

**6-Phase Pipeline:**
1. Build program → `.so` via `cargo build-sbf`
2. Analyze SBF binary (`SbfAnalyzer`)
3. Generate CVLR specification rules (`CvlrSpecGenerator`)
4. Scan bytecode patterns (`BytecodePatternScanner`) — always runs
5. Run Certora Prover (if cloud available)
6. Aggregate results

---

#### `concolic-executor`
**Purpose:** Concolic (concrete + symbolic) execution engine for path exploration.

| Field | Value |
|-------|-------|
| Entry point | `ConcolicExecutor::execute(initial_inputs)` |
| Solver | Z3 |
| Output | `ConcolicResult` with test inputs, coverage, vulnerabilities |
| **Requires** | System Z3 libraries |

**Algorithm:**
1. Start with concrete inputs in a worklist
2. Execute path → collect path conditions at branches
3. Negate last condition → solve with Z3 → discover new inputs
4. Add new states to worklist (BFS exploration)
5. Record coverage (locations, branches taken/not-taken)
6. Report vulnerabilities with triggering inputs

**Key interface:**
```rust
pub trait ConcolicTestable {
    fn execute_concrete(&self, inputs: &HashMap<String, u64>) -> ExecutionState;
    fn input_variables(&self) -> Vec<String>;
    fn check_vulnerability(&self, state: &ExecutionState) -> Option<(String, FindingSeverity)>;
}
```

---

#### `economic-verifier`
**Purpose:** Economic model verification for DeFi protocols (AMM invariants, lending ratios).
| Requires | Z3 |

---

#### `invariant-miner`
**Purpose:** Automated invariant discovery from program traces.
| Requires | Z3 |

---

### 3.3 Fuzzing Crates

#### `trident-fuzzer`
**Purpose:** Stateful Anchor-integrated fuzzing with full ledger simulation.

| Field | Value |
|-------|-------|
| Entry point | `TridentFuzzer::fuzz_program(&Path)` |
| Output | `TridentFuzzReport` with `Vec<TridentFinding>` |
| Backend | Trident CLI + SVM simulation |
| Offline fallback | Static model analysis when CLI unavailable |

**5-Phase Pipeline:**
1. **Extract** Anchor program model from source (`AnchorExtractor`)
2. **Generate** fuzz harnesses: `fuzz_test.rs`, `invariants.rs`, `attack_flows.rs`
3. **Execute** fuzz campaign (`TridentExecutor`)
4. **Analyze** crashes (`CrashAnalyzer`)
5. **Report** structured findings

**Vulnerability Categories Detected:**

| Category | Description |
|----------|-------------|
| `AccountConfusion` | Wrong account substitution bypasses checks |
| `ArithmeticOverflow` | Unchecked math leads to token inflation |
| `MissingSigner` | Transaction accepted without required signer |
| `ReInitialization` | Account re-initialized to attacker-controlled state |
| `PDASeedCollision` | Derived addresses collide across users/pools |
| `CPIReentrancy` | Cross-program invocation re-enters mutably |
| `UnauthorizedWithdrawal` | Funds drained without proper authorization |
| `StateCorruption` | Discriminator / data layout corruption |
| `ConstraintBypass` | Anchor constraint circumvented |
| `CloseAccountDrain` | Lamport drain via account closing race |

**Offline Analysis (when CLI unavailable):**
- Missing signer constraints
- Re-initialization vulnerabilities
- Unchecked `AccountInfo` without constraints
- PDA seed collision (low-entropy derivation)
- Arithmetic without checked math
- CPI without ownership verification
- Close-account without `close` constraint

---

#### `fuzzdelsol`
**Purpose:** Coverage-guided eBPF binary fuzzer for compiled Solana programs.

| Field | Value |
|-------|-------|
| Entry point | `FuzzDelSol::fuzz_binary(&Path)` |
| Input | Compiled `.so` binary from `target/deploy/` |
| Technique | Coverage-guided + security oracles |
| Speed | Under 5 seconds for most programs |
| Default iterations | 10,000 |

**Security Oracles:**
- Missing signer checks
- Unauthorized state changes
- Missing owner checks
- Account substitution vulnerabilities

---

#### `wacana-analyzer`
**Purpose:** Concolic analysis for WASM/SBF smart contracts (post-fuzzing deep analysis).

| Field | Value |
|-------|-------|
| Entry point | `WacanaAnalyzer::analyze_program(&Path)` |
| Output | `WacanaReport` with `Vec<WacanaFinding>` |
| Solver | Z3 SMT |
| Engine version | `WACANA 0.1.0` |

**3-Phase Analysis:**
1. **WASM analysis** — Parse `.wasm` bytecode → concolic execution per function
2. **SBF analysis** — Decode `.so` ELF binary → concolic execution per entry point
3. **Source-assisted** — Parse `.rs` files with `syn` for WASM-relevant patterns

**Concolic Execution Model:**
```
Parse → Concrete Seed → Symbolic Shadow → Negate & Solve → Vulnerability Detection → Report
```

**Vulnerability Detectors:**

| Detector | Target |
|----------|--------|
| `MemorySafetyDetector` | Linear memory out-of-bounds |
| `TypeConfusionDetector` | Type punning / confusion |
| `IndirectCallDetector` | Unvalidated indirect calls |
| `LinearMemoryOverflowDetector` | Stack/heap overflow in WASM linear memory |
| `UninitializedDataDetector` | Use of uninitialized data |
| `ReentrancyPatternDetector` | Cross-contract reentrancy |
| `IntegerIssueDetector` | Integer overflow/underflow |

---

#### `security-fuzzer`
**Purpose:** General-purpose security fuzzing framework for Solana programs.

---

### 3.4 Orchestration & Pipeline Crates

#### `orchestrator`
**Purpose:** Central coordination hub — the "brain" of the security swarm.

**Modules (22 total):**

| Module | Purpose |
|--------|---------|
| `audit_pipeline` | **Main pipeline** — merges all analysis results into `ConfirmedExploit` |
| `mainnet_guardian` | Real-time Solana transaction monitoring & threat detection |
| `dashboard` | TUI dashboard (ratatui) for visualization |
| `mitigation_engine` | Automated defensive transaction generation |
| `chain_explorer` | Account/transaction lookup via RPC |
| `on_chain_registry` | Register exploits/audits on Solana blockchain |
| `pdf_report` | PDF audit report generation |
| `markdown_engine` | Markdown report generation |
| `terminal_ui` | Terminal UI utilities |
| `strategy_engine` | Exploit strategy coordination |
| `watcher` | File/program change watcher |
| `comprehensive_analysis` | Full analysis orchestration |
| `enhanced_comprehensive` | Extended analysis with more tools |
| `flash_loan_detector` | Flash loan attack detection |
| `flash_loan_enhanced` | Enhanced flash loan analysis |
| `oracle_analyzer` | Oracle manipulation detection |
| `oracle_enhanced` | Enhanced oracle analysis |
| `pda_analyzer` | PDA security analysis |
| `reentrancy_detector` | Reentrancy vulnerability detection |
| `privilege_escalation` | Privilege escalation detection |
| `access_control` | Access control validation |
| `account_validator` | Account validation checks |

##### `audit_pipeline` (Core Pipeline)

**Central data merger — transforms heterogeneous analysis results into unified format:**

```
L3X Report ──────────┐
Geiger Report ───────┤
Anchor Report ───────┤
Sec3 Report ─────────┼──→ merge_*_findings() ──→ Vec<ConfirmedExploit>
Kani Report ─────────┤                               │
Taint Report ────────┤                               ▼
Symbolic Proofs ─────┘                          prove_exploits()
                                                     │
                                                     ▼
                                              register_exploits()
                                                     │
                                                     ▼
                                               AuditReport
```

**Merge functions:**
- `merge_l3x_findings()` — Maps L3X AI findings → `ConfirmedExploit`
- `merge_geiger_findings()` — Maps cargo-geiger unsafe findings → `ConfirmedExploit`
- `merge_anchor_findings()` — Maps Anchor violations → `ConfirmedExploit`
- `merge_kani_results()` — Maps Kani verification failures → `ConfirmedExploit`
- `merge_enhanced_findings()` — Maps taint/dataflow findings → `ConfirmedExploit`

##### `mainnet_guardian` (Real-time Monitor)

| Field | Value |
|-------|-------|
| Entry point | `MainnetGuardian::monitoring_loop()` |
| Method | Polls RPC for recent transaction signatures |
| Detection | Predefined `ThreatPattern` functions |
| Alerting | Slack, Discord, Email webhooks |

**Threat Patterns:**
- Flash Loan Attack detection
- Abnormal Token Flow detection
- Suspicious Account Pattern detection

**Threat Levels:**
```rust
pub enum ThreatLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

##### `mitigation_engine` (Active Defense)

**Automated defensive transaction generation:**

| Maneuver | When | Action |
|----------|------|--------|
| `PauseProgram` | IDL has `pause`/`freeze` instruction | Call program's pause IX |
| `FreezeAccount` | Specific account suspicious | Freeze individual account |
| `SecureWithdraw` | Critical threat detected | Emergency withdraw to treasury |
| `FrontRunSecurity` | Active attack in progress | Front-run with defensive TX |

Decision logic:
```
threat_level < High → None
IDL has pause instruction → PauseProgram
Critical → SecureWithdraw
```

##### `chain_explorer`

| Function | Input | Output |
|----------|-------|--------|
| `fetch_network_stats()` | — | `NetworkStats { tps, slot, block_height }` |
| `inspect_account(pubkey)` | Pubkey string | `AccountOverview { lamports, owner, executable, ... }` |
| `inspect_transaction(sig)` | Signature string | `TransactionDetail { status, fee, logs, balances }` |

##### `on_chain_registry`

Registers findings on Solana blockchain as immutable records:
- `register_exploit()` → Creates PDA entry with SHA-256 proof hash
- `register_audit()` → Creates PDA entry for complete audit record

---

#### `transaction-forge`
**Purpose:** Build and execute exploit transactions, generate PoC code.

**Modules:**

| Module | Purpose |
|--------|---------|
| `builder.rs` | `TransactionBuilder` — construct Solana `Instruction` and `Transaction` |
| `executor.rs` | `ExploitExecutor` — send/confirm transactions, verify vulnerabilities |
| `proof_generator.rs` | `ExploitProofConverter` — convert symbolic proofs to transaction builders |
| `error.rs` | `ForgeError` types |

**Key function — `generate_exploit_poc()`:**
- Takes `ExploitProof` → generates Rust test file
- SOL-019 (Oracle Manipulation): Full simulation with vault math
- Other vulns: Generic test skeleton

---

#### `integration-orchestrator`
**Purpose:** Generates deployment packages with security checklists.

```rust
pub struct DeploymentPackage {
    pub architecture_review: String,
    pub secure_code_template: String,
    pub testing_framework_template: String,
    pub deployment_protocol: String,
    pub pre_deployment_checklist: Vec<String>,
}
```

---

#### `hackathon-client`
**Purpose:** CLI client for the security swarm (user-facing binary).

---

### 3.5 AI & Strategy Crates

#### `llm-strategist`
**Purpose:** LLM-powered exploit strategy generation via OpenRouter API.

| Field | Value |
|-------|-------|
| Entry point | `LlmStrategist::generate_exploit_strategy()` |
| API | OpenRouter (configurable model) |
| Input | `VulnerabilityFinding` + instruction source code |
| Output | `ExploitStrategy` (attack vector, payload, expected outcome) |

**Prompt engineering:** Structured security researcher prompt → JSON response with:
- `attack_vector` — exact input/action that triggers vulnerability
- `payload` — concrete values (e.g., `u64::MAX`)
- `expected_outcome` — error code or state change
- `explanation` — 2-sentence technical explanation

---

#### `ai-enhancer`
**Purpose:** AI-enhanced analysis augmentation layer.

---

### 3.6 Security Expert Crates

Domain-specific vulnerability analyzers:

| Crate | Domain | Key Checks |
|-------|--------|------------|
| `defi-security-expert` | DeFi protocols | Flash loans, oracle manipulation, MEV |
| `token-security-expert` | Token programs | Mint authority, freeze authority, decimals |
| `account-security-expert` | Account security | PDA validation, ownership, rent exemption |
| `arithmetic-security-expert` | Math safety | Overflow/underflow, precision loss, rounding |

---

### 3.7 Infrastructure Crates

| Crate | Purpose |
|-------|---------|
| `consensus-engine` | Multi-agent consensus on vulnerability classification |
| `benchmark-suite` | Performance benchmarking for analysis tools |
| `secure-code-gen` | Generates secure code templates and fixes |
| `attack-simulator` | Simulates attack scenarios against programs |
| `firedancer-monitor` | Monitors Firedancer validator nodes |

---

### 3.8 Programs (On-Chain)

| Program | Purpose |
|---------|---------|
| `vulnerable-vault` | Test target with intentional vault vulnerabilities |
| `vulnerable-token` | Test target with token overflow bugs |
| `vulnerable-staking` | Test target with authority bypass issues |
| `security_shield` | Defensive program for pausing/freezing onchain |
| `exploit-registry` | On-chain registry for audit findings and exploit records |

---

## 4. Key Data Structures

### `ConfirmedExploit` (Central Finding Type)

The unified representation for all findings from any analysis tool:

```rust
pub struct ConfirmedExploit {
    pub id: String,                        // Unique identifier (e.g., "L3X-001")
    pub category: String,                  // "L3X AI Analysis (Overflow)"
    pub vulnerability_type: String,        // "ML-Detected: Overflow"
    pub severity: u8,                      // 1-5 numeric severity
    pub severity_label: String,            // "Critical" | "High" | etc.
    pub description: String,              
    pub attack_scenario: String,           // How to exploit
    pub fix: String,                       // Recommended fix
    pub confidence: f32,                   // 0.0-1.0
    pub risk: f32,                         // Computed risk score
    pub proof: Option<ExploitProofReceipt>, // Mathematical proof if available
    pub ai_explanation: Option<String>,     // LLM/AI explanation
    // ... location, historical context, etc.
}
```

### `ExploitProof` (Symbolic Engine Output)

```rust
pub struct ExploitProof {
    pub vulnerability_type: VulnerabilityType,
    pub constraint_system: String,
    pub satisfying_assignment: HashMap<String, String>,
    pub proof_valid: bool,
    pub proof_hash: String,
    pub counterexample: Option<String>,
}
```

### `AuditReport` (Final Output)

```rust
pub struct AuditReport {
    pub program_id: String,
    pub exploits: Vec<ConfirmedExploit>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub security_score: f32,              // 0-100
    pub deployment_advice: String,        // "DEPLOY" | "FIX_REQUIRED" | "CRITICAL_HALT"
    pub timestamp: String,
}
```

### `ThreatDetection` (Runtime Monitoring)

```rust
pub struct ThreatDetection {
    pub signature: String,
    pub timestamp: i64,
    pub threat_type: ThreatType,          // FlashLoanAttack | AbnormalTokenFlow | etc.
    pub threat_level: ThreatLevel,        // Info | Low | Medium | High | Critical
    pub confidence: f32,
    pub explanation: String,
    pub affected_accounts: Vec<String>,
    pub estimated_impact: Option<f64>,
    pub recommended_actions: Vec<String>,
}
```

---

## 5. Pipeline Flow

### Full Audit Pipeline Execution Order

```
1. SOURCE COLLECTION
   └─ Discover .rs files in target program directory

2. PARALLEL STATIC ANALYSIS (all run concurrently)
   ├─ L3X AI Analysis          → L3xAnalysisReport
   ├─ Geiger Unsafe Detection  → GeigerAnalysisReport  
   ├─ Anchor Security          → AnchorAnalysisReport
   ├─ Sec3 Soteria Analysis    → Sec3AnalysisReport
   ├─ Taint Analysis           → TaintAnalysisReport
   ├─ Dataflow Analysis        → DataflowReport
   ├─ CPI Analysis             → CpiReport
   └─ Abstract Interpretation  → AbstractReport

3. FORMAL VERIFICATION (requires Z3 / external tools)
   ├─ Kani Model Checking      → KaniVerificationReport
   ├─ Certora SBF Verification → CertoraVerificationReport
   ├─ Symbolic Engine Z3       → Vec<ExploitProof>
   └─ Concolic Execution       → ConcolicResult

4. DYNAMIC TESTING (requires built binary)
   ├─ Trident Stateful Fuzzing → TridentFuzzReport
   ├─ FuzzDelSol Binary Fuzz   → FuzzDelSolReport
   ├─ WACANA Concolic Analysis → WacanaReport
   └─ Security Fuzzer          → FuzzerReport

5. MERGE & UNIFICATION (audit_pipeline)
   └─ All reports → merge_*_findings() → Vec<ConfirmedExploit>

6. PROOF GENERATION
   └─ prove_exploits() → Z3 proofs + PoC code generation

7. AI ENRICHMENT
   └─ LLM Strategist → exploit strategies + explanations

8. CONSENSUS
   └─ Consensus Engine → multi-agent agreement on severity

9. REPORTING
   ├─ AuditReport (structured)
   ├─ PDF Report
   ├─ Markdown Report
   └─ On-Chain Registry (Solana TX)

10. RUNTIME MONITORING (ongoing)
    ├─ Mainnet Guardian → real-time threat detection
    ├─ Dashboard (TUI) → visualization
    └─ Mitigation Engine → automated defense
```

---

## 6. Dependency Graph

### Build Groups

**Default build** (no Z3 required):
```
program-analyzer, l3x-analyzer, geiger-analyzer, anchor-security-analyzer,
sec3-analyzer, taint-analyzer, dataflow-analyzer, abstract-interpreter,
cpi-analyzer, kani-verifier, certora-prover, trident-fuzzer, fuzzdelsol,
security-fuzzer, llm-strategist, transaction-forge, orchestrator,
hackathon-client, secure-code-gen, attack-simulator, consensus-engine,
benchmark-suite, integration-orchestrator, firedancer-monitor,
defi-security-expert, token-security-expert, account-security-expert,
arithmetic-security-expert, git-scanner, ai-enhancer,
+ all program crates
```

**Z3-dependent** (build separately: `cargo build -p <name>`):
```
symbolic-engine, concolic-executor, economic-verifier, invariant-miner,
wacana-analyzer
```

### Key Crate Dependencies

```
orchestrator
├── program-analyzer       (VulnerabilityFinding)
├── l3x-analyzer           (L3xAnalysisReport)
├── geiger-analyzer        (GeigerAnalysisReport)
├── anchor-security-analyzer (AnchorAnalysisReport)
├── sec3-analyzer          (Sec3AnalysisReport)
├── kani-verifier          (KaniVerificationReport)
├── certora-prover         (CertoraVerificationReport)
├── symbolic-engine        (ExploitProof)  [optional, Z3]
├── transaction-forge      (TransactionBuilder, ExploitExecutor)
├── llm-strategist         (ExploitStrategy)
├── consensus-engine       (ConsensusResult)
├── solana-client           (RPC calls)
├── solana-sdk              (Keypair, Transaction)
└── ratatui                 (TUI dashboard)

llm-strategist
└── program-analyzer       (VulnerabilityFinding)

transaction-forge
├── solana-sdk
└── solana-client

symbolic-engine [Z3]
└── z3

concolic-executor [Z3]
└── z3

wacana-analyzer [Z3]
├── z3
├── syn
├── sha2
└── walkdir
```

---

## 7. Build Configuration

### Workspace `Cargo.toml`

```toml
[workspace]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"

[profile.release]
overflow-checks = true    # Critical for security tool
lto = "fat"
codegen-units = 1

[profile.dev]
overflow-checks = true
```

### Building

```bash
# Default build (no Z3 needed):
cargo build

# Full build including Z3-dependent crates:
cargo build --workspace

# Specific Z3 crates:
cargo build -p symbolic-engine -p concolic-executor

# Release build:
cargo build --release
```

### Clean

```bash
# WARNING: target/ can grow to 32GB+
cargo clean
```

---

## 8. Next Steps & Blockers

### Active Blockers

| Blocker | Affected Crates | Resolution |
|---------|-----------------|------------|
| Z3 system libraries required | `symbolic-engine`, `concolic-executor`, `economic-verifier`, `invariant-miner`, `wacana-analyzer` | Install `libz3-dev` or use `static-link-z3` feature |
| Kani CLI not installed | `kani-verifier` | Falls back to offline static analysis |
| Certora Prover not installed | `certora-prover` | Falls back to offline SBF pattern analysis |
| Trident CLI not installed | `trident-fuzzer` | Falls back to offline model analysis |
| No compiled `.so` binary | `fuzzdelsol`, `certora-prover` | Run `cargo build-sbf` first |
| On-chain registry program not deployed | `on_chain_registry` | Deploy `exploit-registry` program to devnet |
| No funded payer keypair | `on_chain_registry`, `transaction-forge` | Configure funded Solana keypair |

### Priority Next Steps

1. **Complete Transaction Forging** — Integrate `generate_exploit_poc()` with `TransactionBuilder` + RPC for live verification
2. **Enhance Mainnet Guardian** — Fetch full transaction data (logs, account states) for richer threat detection
3. **On-Chain Registry Testing** — Deploy `exploit-registry` to devnet, test with funded payer
4. **TUI Dashboard Polish** — Complete `ChainExplorer` integration, add interactive drill-down views
5. **Expand Threat Patterns** — Add more `ThreatPattern` definitions for common Solana exploits
6. **AI Analysis Integration** — Wire LLM Strategist into audit pipeline for auto-explanation generation
7. **Refine Symbolic Engine** — Expand beyond SOL-019 to cover more vulnerability types
8. **Cross-tool Correlation** — When multiple tools flag the same location, boost confidence automatically
