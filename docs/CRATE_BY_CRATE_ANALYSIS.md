# Solana Security Swarm - Crate-by-Crate Analysis

> **Total Crates:** 24  
> **Total Lines of Rust:** ~30,500  
> **Analysis Date:** 2026-02-09

---

## Crate Overview Matrix

| # | Crate | Lines | Tests | Status | Notes |
|---|-------|-------|-------|--------|-------|
| 1 | orchestrator | ~7,500 | 22 | ✅ Working | Main CLI, 3 test failures |
| 2 | program-analyzer | ~2,000 | 26 | ✅ Working | Core engine |
| 3 | cpi-analyzer | ~1,640 | 0 | ✅ Working | CPI patterns |
| 4 | economic-verifier | ~1,530 | 0 | ✅ Working | DeFi checks |
| 5 | dataflow-analyzer | ~755 | 7 | ✅ Working | CFG analysis |
| 6 | abstract-interpreter | ~712 | 6 | ✅ Working | Intervals |
| 7 | security-fuzzer | ~697 | 3 | ✅ Working | Fuzzing |
| 8 | taint-analyzer | ~500 | 14 | ✅ Working | Taint tracking |
| 9 | concolic-executor | ~456 | 0 | ✅ Working | Concolic exec |
| 10 | invariant-miner | ~422 | 3 | ✅ Working | Invariants |
| 11 | ai-enhancer | ~417 | 0 | ✅ Working | AI features |
| 12 | transaction-forge | ~400 | 3 | ✅ Working | Exploits |
| 13 | consensus-engine | ~386 | 3 | ✅ Working | Multi-LLM |
| 14 | secure-code-gen | ~313 | 0 | ✅ Working | Fix gen |
| 15 | llm-strategist | ~304 | 0 | ⚠️ Has Stub | LLM client |
| 16 | symbolic-engine | ~284 | 3 | ✅ Working | Z3 solver |
| 17 | hackathon-client | ~126 | 0 | ✅ Working | Forum API |
| 18 | attack-simulator | ~35 | 0 | ⚠️ Minimal | Template only |
| 19 | account-security-expert | ~100 | 0 | ⚠️ Limited | 2 patterns |
| 20 | token-security-expert | ~80 | 0 | ⚠️ Limited | 1 pattern |
| 21 | defi-security-expert | ~80 | 0 | ⚠️ Limited | 1 pattern |
| 22 | arithmetic-security-expert | ~80 | 0 | ⚠️ Limited | 1 pattern |
| 23 | benchmark-suite | ~50 | 0 | ⚠️ Minimal | Basic perf |
| 24 | integration-orchestrator | ~50 | 0 | ⚠️ Minimal | Meta layer |

---

## Detailed Crate Analysis

### 1. `orchestrator` (Main Application)

**Path:** `crates/orchestrator`  
**Entry Point:** `src/main.rs`  
**Lines:** ~7,500

#### Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.rs` | ~680 | CLI entry, argument parsing |
| `lib.rs` | ~100 | Module exports |
| `audit_pipeline.rs` | ~800 | Core audit workflow |
| `comprehensive_analysis.rs` | ~850 | Multi-engine coordination |
| `enhanced_comprehensive.rs` | ~690 | Enhanced analysis |
| `flash_loan_detector.rs` | ~560 | Flash loan patterns |
| `flash_loan_enhanced.rs` | ~980 | Enhanced flash loan |
| `oracle_analyzer.rs` | ~600 | Oracle security |
| `oracle_enhanced.rs` | ~910 | Enhanced oracle |
| `pda_analyzer.rs` | ~500 | PDA analysis |
| `reentrancy_detector.rs` | ~330 | Reentrancy patterns |
| `on_chain_registry.rs` | ~310 | Blockchain registration |
| `markdown_engine.rs` | ~300 | Report generation |
| `terminal_ui.rs` | ~400 | Terminal output |
| `watcher.rs` | ~200 | Mainnet monitoring |
| `access_control.rs` | ~650 | Auth analysis |
| `privilege_escalation.rs` | ~600 | Privilege checks |
| `strategy_engine.rs` | ~90 | Triage ranking |
| `account_validator.rs` | ~400 | Account validation |
| `pdf_report.rs` | 9 | **MINIMAL** |

#### Key Dependencies

```toml
program-analyzer = { path = "../program-analyzer" }
transaction-forge = { path = "../transaction-forge" }
consensus-engine = { path = "../consensus-engine" }
llm-strategist = { path = "../llm-strategist" }
hackathon-client = { path = "../hackathon-client" }
solana-sdk = "1.18"
tokio = { version = "1", features = ["full"] }
clap = { version = "3", features = ["derive"] }
colored = "2"
```

#### Public APIs

```rust
// Main struct
pub struct EnterpriseAuditor {
    pub async fn audit_program(...) -> Result<AuditReport>;
}

// Report struct
pub struct AuditReport {
    pub program_id: String,
    pub security_score: u8,
    pub findings: Vec<ConfirmedExploit>,
    pub total_exploits: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
}

// On-chain registry
pub struct OnChainRegistry {
    pub async fn register_exploit(...) -> Result<String>;
    pub async fn register_audit(...) -> Result<AuditEntry>;
}
```

---

### 2. `program-analyzer` (Core Analysis)

**Path:** `crates/program-analyzer`  
**Lines:** ~2,000

#### Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | ~300 | Main analyzer |
| `vulnerability_db.rs` | ~800 | 52 patterns |
| `anchor_extractor.rs` | ~200 | Anchor parsing |
| `instruction_parser.rs` | ~250 | Instruction extraction |
| `account_schema.rs` | ~150 | Schema detection |
| `report_generator.rs` | ~100 | Finding format |
| `error.rs` | ~50 | Error types |

#### Key Types

```rust
pub struct ProgramAnalyzer {
    source_dir: PathBuf,
    parsed_files: HashMap<String, syn::File>,
}

pub struct VulnerabilityFinding {
    pub vuln_id: String,
    pub vuln_type: String,
    pub severity: u8,
    pub location: String,
    pub function_name: String,
    pub line_number: usize,
    pub description: String,
    pub attack_scenario: String,
    pub recommendation: String,
    pub code_snippet: String,
}

pub struct AccountSchema {
    pub name: String,
    pub fields: Vec<AccountField>,
    pub constraints: Vec<String>,
}
```

#### Test Coverage

- 15 unit tests
- 4 integration tests  
- 11 property tests (false positive detection)

---

### 3. `cpi-analyzer` (CPI Security)

**Path:** `crates/cpi-analyzer`  
**Lines:** ~1,640

#### Capabilities

- Detect arbitrary CPI targets
- Analyze CPI privilege escalation
- Track CPI call chains
- Identify callback patterns
- Validate CPI return handling

#### Key Functions

```rust
pub fn analyze_cpi_patterns(source: &str) -> Vec<CpiFinding>;
pub fn build_cpi_call_graph(source: &str) -> CpiGraph;
pub fn detect_arbitrary_cpi(source: &str) -> Vec<Finding>;
```

---

### 4. `economic-verifier` (DeFi Security)

**Path:** `crates/economic-verifier`  
**Lines:** ~1,530

#### Capabilities

- Price manipulation detection
- Flash loan attack patterns
- Slippage calculation verification
- Fee computation analysis
- Liquidity pool safety

#### Key Types

```rust
pub struct EconomicVerifier;

pub enum EconomicVulnerability {
    PriceManipulation,
    FlashLoanAttack,
    SlippageExploit,
    FeeExploit,
    LiquidityDrain,
}
```

---

### 5. `dataflow-analyzer` (Control Flow)

**Path:** `crates/dataflow-analyzer`  
**Lines:** ~755

#### Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | ~100 | Exports |
| `cfg.rs` | ~200 | CFG construction |
| `reaching_defs.rs` | ~150 | Reaching definitions |
| `live_vars.rs` | ~100 | Live variables |
| `use_def.rs` | ~100 | Use-def chains |
| `dominators.rs` | ~105 | Dominator trees |

#### Algorithms

- CFG construction from AST
- Reaching definitions (forward flow)
- Live variables (backward flow)
- Use-def chain extraction
- Dominator/post-dominator computation

---

### 6. `abstract-interpreter` (Interval Analysis)

**Path:** `crates/abstract-interpreter`  
**Lines:** ~712

#### Abstract Domains

```rust
pub struct IntervalDomain {
    pub min: i128,
    pub max: i128,
}

pub enum SignDomain {
    Positive,
    Negative,
    Zero,
    NonNegative,
    NonPositive,
    Unknown,
}
```

#### Operations

- Join (⊔) - least upper bound
- Meet (⊓) - greatest lower bound  
- Widening (∇) - acceleration for loops
- Transfer functions for arithmetic

---

### 7. `security-fuzzer` (Mutation Fuzzing)

**Path:** `crates/security-fuzzer`  
**Lines:** ~697

#### Mutation Strategies

| Strategy | Description |
|----------|-------------|
| BitFlip | Flip random bits |
| ByteReplace | Replace random bytes |
| Arithmetic | Add/subtract small values |
| Splice | Combine two inputs |
| RandomInsert | Insert random bytes |

#### Key Functions

```rust
pub fn fuzz_instruction(seed: &[u8], iterations: u32) -> Vec<CrashInput>;
pub fn mutate(input: &[u8], strategy: MutationStrategy) -> Vec<u8>;
```

---

### 8. `taint-analyzer` (Data Flow Security)

**Path:** `crates/taint-analyzer`  
**Lines:** ~500

#### Taint Sources

- `ctx.accounts.*` - User-provided accounts
- `remaining_accounts` - Dynamic accounts
- `data[*]` - Instruction data
- `Pubkey::new*` - User pubkeys

#### Taint Sinks

- `invoke`, `invoke_signed` - CPI calls
- `transfer`, `token::mint_to` - Value transfer
- `lamports` mutations - Balance changes
- Authority assignments - Privilege changes

---

### 9. `concolic-executor` (Hybrid Execution)

**Path:** `crates/concolic-executor`  
**Lines:** ~456

#### Approach

1. Execute program concretely
2. Collect path constraints symbolically
3. Negate constraints to explore alternatives
4. Generate boundary inputs

#### Key Functions

```rust
pub fn execute_concolic(program: &Program, input: &Input) -> ExecutionTrace;
pub fn generate_alternative_inputs(trace: &ExecutionTrace) -> Vec<Input>;
```

---

### 10. `invariant-miner` (Property Discovery)

**Path:** `crates/invariant-miner`  
**Lines:** ~422

#### Invariant Categories

| Category | Example |
|----------|---------|
| Balance Conservation | `total_supply == sum(balances)` |
| Access Control | `only_authority_can_withdraw` |
| Arithmetic Bounds | `amount <= MAX_SUPPLY` |
| State Transition | `state != Finalized => mutable` |
| Account Relationship | `token.mint == pool.token_mint` |

---

### 11. `ai-enhancer` (AI Features)

**Path:** `crates/ai-enhancer`  
**Lines:** ~417

#### Capabilities

- Enhance finding descriptions
- Generate attack explanations
- Suggest remediation steps
- Classify vulnerability severity

---

### 12. `transaction-forge` (Exploit Builder)

**Path:** `crates/transaction-forge`  
**Lines:** ~400

#### Exploit Types

```rust
pub enum VulnerabilityType {
    MissingSigner,
    IntegerOverflow,
    MissingOwnerCheck,
    TypeCosplay,
    PDAValidation,
    ArbitraryCPI,
    Reentrancy,
    OracleManipulation,
    AccountConfusion,
    UninitializedData,
}
```

#### Key Functions

```rust
pub fn build_exploit(vuln: VulnerabilityType, params: &ExploitParams) -> Instruction;
pub fn simulate_exploit(instruction: &Instruction) -> ExploitResult;
pub fn execute_exploit(instruction: &Instruction) -> ExploitResult;
```

---

### 13. `consensus-engine` (Multi-LLM)

**Path:** `crates/consensus-engine`  
**Lines:** ~386

#### Workflow

1. Send finding to multiple LLMs
2. Collect verdicts (Confirmed/Rejected/Uncertain)
3. Calculate agreement ratio
4. Apply threshold for final verdict

#### Configuration

```rust
pub struct LlmConfig {
    pub provider: Provider,
    pub model: String,
    pub api_key: String,
    pub weight: f32,
}

pub struct ConsensusEngine {
    models: Vec<LlmConfig>,
    threshold: f32,  // Default: 0.6
    require_majority: bool,
}
```

---

### 14. `secure-code-gen` (Fix Generation)

**Path:** `crates/secure-code-gen`  
**Lines:** ~313

#### Available Patterns

| Pattern ID | Name | Fixes Vulns |
|------------|------|-------------|
| signer-check | Signer Validation | SOL-001, SOL-047 |
| owner-check | Owner Validation | SOL-003, SOL-015 |
| checked-arithmetic | Checked Arithmetic | SOL-002, SOL-037-040, SOL-045 |
| pda-validation | PDA Validation | SOL-007, SOL-008, SOL-027 |
| reentrancy-guard | Reentrancy Guard | SOL-017, SOL-018 |
| token-validation | Token Validation | SOL-021-024 |
| slippage-protection | Slippage Protection | SOL-033, SOL-034, SOL-051 |
| account-close | Safe Account Close | SOL-009, SOL-028, SOL-029 |

---

### 15. `llm-strategist` (LLM Integration)

**Path:** `crates/llm-strategist`  
**Lines:** ~304

#### Supported APIs

| Provider | Key Prefix | Endpoint |
|----------|------------|----------|
| OpenRouter | `sk-or-*` | openrouter.ai |
| OpenAI | `sk-proj-*`, `sk-*` | api.openai.com |
| NVIDIA NIM | `nvapi-*` | integrate.api.nvidia.com |

#### Key Functions

```rust
pub async fn generate_exploit_strategy(vuln: &Finding, code: &str) -> ExploitStrategy;
pub async fn infer_system_invariants(code: &str) -> Vec<Invariant>;
pub async fn enhance_finding(...) -> EnhancedFinding;  // ⚠️ STUB
```

---

### 16. `symbolic-engine` (Z3 Solver)

**Path:** `crates/symbolic-engine`  
**Lines:** ~284

#### Capabilities

- SMT constraint solving via Z3
- Arithmetic overflow proving
- Authority bypass detection
- Counterexample generation

**Note:** Requires system Z3 libraries installed.

---

### 17. `hackathon-client` (Forum API)

**Path:** `crates/hackathon-client`  
**Lines:** ~126

#### API Functions

```rust
pub async fn create_post(title: &str, body: &str, tags: &[&str]) -> Result<String>;
pub async fn post_update(post_id: &str, ...) -> Result<String>;
pub async fn submit_audit_results(...) -> Result<String>;
```

---

### 18. `attack-simulator` (Minimal)

**Path:** `crates/attack-simulator`  
**Lines:** 35

**Status:** ⚠️ Template generation only, no real simulation.

---

### 19-22. Expert Crates (Limited)

| Crate | Patterns Implemented |
|-------|---------------------|
| `account-security-expert` | SOL-001, SOL-003 |
| `token-security-expert` | SOL-021 |
| `defi-security-expert` | SOL-018 |
| `arithmetic-security-expert` | SOL-002 |

**Note:** Most analysis done by core `program-analyzer`.

---

### 23-24. Utility Crates

| Crate | Purpose |
|-------|---------|
| `benchmark-suite` | Performance testing |
| `integration-orchestrator` | Meta-coordination |

---

## Dependency Graph Summary

```
orchestrator (main)
├── program-analyzer (core)
├── transaction-forge (exploits)
├── consensus-engine (voting)
├── llm-strategist (AI)
├── hackathon-client (API)
├── taint-analyzer (flow)
├── dataflow-analyzer (CFG)
├── cpi-analyzer (CPI)
├── symbolic-engine (Z3)
├── security-fuzzer (fuzz)
├── invariant-miner (props)
├── secure-code-gen (fixes)
├── attack-simulator (sim)
├── abstract-interpreter (domains)
├── concolic-executor (hybrid)
├── economic-verifier (DeFi)
├── ai-enhancer (enhance)
└── expert crates (domain)
```

---

## Build Commands

```bash
# Build all (excluding Z3)
cargo build --release

# Build with Z3
cargo build --release -p symbolic-engine -p economic-verifier \
                      -p concolic-executor -p invariant-miner

# Build single crate
cargo build -p program-analyzer

# Run main binary
./target/release/solana-security-swarm --help
```

---

*Crate analysis from actual source code - 2026-02-09*
