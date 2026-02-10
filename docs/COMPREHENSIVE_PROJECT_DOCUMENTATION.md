# Solana Security Swarm - Comprehensive Project Documentation

> **Version:** 0.1.0  
> **Last Updated:** 2026-02-09  
> **Total Lines of Rust Code:** ~30,500+  
> **Total Crates:** 24  
> **Total Programs:** 5 Anchor Programs

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview](#2-project-overview)
3. [Getting Started](#3-getting-started)
4. [Architecture Deep Dive](#4-architecture-deep-dive)
5. [CLI Reference](#5-cli-reference)
6. [All Crates Detailed Documentation](#6-all-crates-detailed-documentation)
7. [On-Chain Programs](#7-on-chain-programs)
8. [Vulnerability Database](#8-vulnerability-database)
9. [Implementation Status](#9-implementation-status)
10. [Known Issues & Placeholders](#10-known-issues--placeholders)
11. [Test Coverage](#11-test-coverage)
12. [Configuration Reference](#12-configuration-reference)
13. [API Reference](#13-api-reference)
14. [Troubleshooting](#14-troubleshooting)
15. [Development Guide](#15-development-guide)

---

## 1. Executive Summary

### What Is This Project?

**Solana Security Swarm** is an enterprise-grade autonomous security auditing platform for Solana/Anchor smart contracts. It combines:

- **Static Analysis** - AST-based vulnerability detection using `syn` parser
- **AI-Enhanced Analysis** - LLM-powered vulnerability reasoning via OpenRouter/OpenAI/NVIDIA
- **Multi-LLM Consensus** - Reduces false positives through multi-model voting
- **Symbolic Execution** - Z3-based constraint solving for overflow detection
- **Fuzzing** - Coverage-guided input mutation for crash discovery
- **On-Chain Proving** - Real transaction execution to verify vulnerabilities
- **Exploit Registry** - Blockchain-based permanent audit records

### Key Metrics

| Metric | Value |
|--------|-------|
| Vulnerability Patterns | 52 |
| Supported Crates | 24 |
| On-Chain Programs | 5 |
| Test Files | 20+ |
| Lines of Rust | ~30,500 |
| Analysis Engines | 8 |

### Quick Assessment

| Category | Status | Notes |
|----------|--------|-------|
| Core Analysis | ✅ **Working** | AST parsing, 52 vulnerability patterns |
| AI Enhancement | ✅ **Working** | OpenRouter, OpenAI, NVIDIA APIs |
| Symbolic Engine | ✅ **Working** | Z3 integration for overflow detection |
| Transaction Forge | ✅ **Working** | Real Solana RPC transactions |
| Consensus Engine | ✅ **Working** | Multi-LLM voting implemented |
| On-Chain Registry | ✅ **Working** | Real transaction submission |
| PDF Reports | ⚠️ **Minimal** | Only generates single-line HTML |
| Forum Client | ✅ **Working** | Real HTTP API calls |

---

## 2. Project Overview

### 2.1 What This Tool Does

1. **Scans Solana Programs** - Analyzes Rust/Anchor source code for 52+ vulnerability patterns
2. **Uses Multiple Analyzers** - Runs 8+ analysis engines in parallel
3. **AI-Enhanced Findings** - Uses LLMs to explain vulnerabilities and suggest fixes
4. **Proves Vulnerabilities** - Builds and executes exploit transactions on devnet
5. **Registers On-Chain** - Creates permanent blockchain records of audits
6. **Generates Reports** - Outputs JSON, Markdown, and HTML reports

### 2.2 Technology Stack

**Languages:**
- Rust (core analysis, ~30k lines)
- TypeScript (tests, ~500 lines)
- Shell (scripts, ~300 lines)

**Frameworks:**
- Anchor 0.30.1 (Solana smart contracts)
- Solana SDK 1.18 (blockchain interaction)
- Tokio (async runtime)
- Reqwest (HTTP client)
- Syn (Rust AST parsing)

**External Services:**
- OpenRouter API (LLM orchestration)
- OpenAI API (GPT models)
- NVIDIA NIM API (Nemotron models)
- Solana RPC (devnet/mainnet)

### 2.3 Project Structure

```
hackathon/
├── crates/                          # 24 Rust library crates
│   ├── orchestrator/                # Main CLI and pipeline (~7,500 lines)
│   ├── program-analyzer/            # Core vulnerability scanner (~2,000 lines)
│   ├── transaction-forge/           # Exploit transaction builder (~400 lines)
│   ├── consensus-engine/            # Multi-LLM voting (~400 lines)
│   ├── invariant-miner/             # Invariant discovery (~420 lines)
│   ├── secure-code-gen/             # Fix generation (~310 lines)
│   ├── llm-strategist/              # LLM integration (~300 lines)
│   ├── hackathon-client/            # Forum API client (~130 lines)
│   ├── taint-analyzer/              # Taint tracking (~500 lines)
│   ├── dataflow-analyzer/           # CFG and dataflow (~750 lines)
│   ├── abstract-interpreter/        # Interval analysis (~700 lines)
│   ├── symbolic-engine/             # Z3 constraint solving (~280 lines)
│   ├── concolic-executor/           # Concrete+symbolic (~450 lines)
│   ├── security-fuzzer/             # Coverage-guided fuzzing (~700 lines)
│   ├── cpi-analyzer/                # CPI security (~1,600 lines)
│   ├── economic-verifier/           # Economic verification (~1,500 lines)
│   ├── ai-enhancer/                 # AI enhancement (~420 lines)
│   ├── attack-simulator/            # Attack scenario gen (~35 lines)
│   ├── benchmark-suite/             # Performance testing
│   ├── integration-orchestrator/    # Meta-orchestration
│   └── [4 expert crates]/           # Domain-specific knowledge
├── programs/                        # 5 Anchor on-chain programs
│   ├── exploit-registry/            # Exploit tracking (~400 lines)
│   ├── security_shield/             # Security features (~2,900 lines)
│   ├── vulnerable-vault/            # Test vulnerable program
│   ├── vulnerable-token/            # Test vulnerable program
│   └── vulnerable-staking/          # Test vulnerable program
├── tests/                           # TypeScript integration tests
├── test_targets/                    # Real-world programs for testing
│   ├── sealevel-attacks/            # 11 intentionally vulnerable programs
│   ├── raydium-amm/                 # Production DeFi code
│   ├── spl/                         # Solana Program Library
│   └── solana-cctp-contracts/       # Circle CCTP contracts
├── scripts/                         # Shell scripts
├── audit_reports/                   # Generated audit outputs
└── docs/                            # Documentation
```

---

## 3. Getting Started

### 3.1 Prerequisites

- **Rust** 1.70+ with Cargo
- **Solana CLI** 1.18+
- **Anchor CLI** 0.30.1+
- **Node.js** 18+ (for TypeScript tests)
- **Z3** (for symbolic engine - optional)

### 3.2 Installation

```bash
# Clone the repository
git clone https://github.com/your-org/solana-security-swarm
cd solana-security-swarm

# Build all crates (excluding Z3-dependent ones)
cargo build --release

# Build with Z3 support (requires system z3 libraries)
cargo build --release -p economic-verifier -p concolic-executor -p invariant-miner -p symbolic-engine

# Verify installation
./target/release/solana-security-swarm --help
```

### 3.3 Configuration

Create a `.env` file in the project root:

```bash
# Required: OpenRouter API key for LLM features
OPENROUTER_API_KEY=sk-or-v1-your-key-here

# Optional: Custom RPC endpoint
SOLANA_RPC_URL=https://api.devnet.solana.com

# Optional: Specific LLM model
LLM_MODEL=anthropic/claude-sonnet-4

# Optional: Hackathon forum API key
HACKATHON_API_KEY=your-forum-key
```

### 3.4 Quick Start Examples

```bash
# 1. Run against built-in vulnerable programs (test mode)
./target/release/solana-security-swarm \
  --test-mode \
  --api-key $OPENROUTER_API_KEY \
  --dry-run

# 2. Scan a GitHub repository
./target/release/solana-security-swarm \
  --repo https://github.com/coral-xyz/sealevel-attacks \
  --api-key $OPENROUTER_API_KEY \
  --output-dir ./my_audit

# 3. Full audit with exploit proving
./target/release/solana-security-swarm \
  --repo https://github.com/target/program \
  --api-key $OPENROUTER_API_KEY \
  --prove \
  --rpc-url https://api.devnet.solana.com

# 4. Multi-LLM consensus mode
./target/release/solana-security-swarm \
  --test-mode \
  --api-key $OPENROUTER_API_KEY \
  --consensus \
  --dry-run
```

---

## 4. Architecture Deep Dive

### 4.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATOR (Main CLI)                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │  CLI Args   │ │ Source      │ │ Analysis    │ │ Report      │   │
│  │  Parser     │ │ Fetcher     │ │ Pipeline    │ │ Generator   │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ STATIC ANALYSIS  │ │ DYNAMIC ANALYSIS │ │ AI ENHANCEMENT   │
├──────────────────┤ ├──────────────────┤ ├──────────────────┤
│ program-analyzer │ │ symbolic-engine  │ │ llm-strategist   │
│ taint-analyzer   │ │ concolic-executor│ │ ai-enhancer      │
│ dataflow-analyzer│ │ security-fuzzer  │ │ consensus-engine │
│ cpi-analyzer     │ │ invariant-miner  │ │                  │
│ abstract-interp  │ │                  │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               ▼
              ┌──────────────────────────────┐
              │        POST-PROCESSING       │
              ├──────────────────────────────┤
              │ transaction-forge            │
              │ secure-code-gen              │
              │ on-chain-registry            │
              │ hackathon-client             │
              └──────────────────────────────┘
                               │
                               ▼
              ┌──────────────────────────────┐
              │         OUTPUT               │
              ├──────────────────────────────┤
              │ JSON Report                  │
              │ Markdown Report              │
              │ HTML Report                  │
              │ Forum Post                   │
              │ On-Chain Record              │
              └──────────────────────────────┘
```

### 4.2 Analysis Pipeline Flow

1. **Source Acquisition**
   - Fetch from GitHub repo URL
   - Load from local filesystem
   - Extract from Anchor IDL

2. **Parsing Phase**
   - Parse Rust source with `syn` crate
   - Extract function signatures, structs, modules
   - Build AST representation

3. **Static Analysis Phase**
   - Run 52 vulnerability pattern checks
   - Perform taint analysis (source → sink)
   - Build control flow graphs
   - Execute dataflow analysis
   - Analyze CPI patterns

4. **Dynamic Analysis Phase**
   - Symbolic execution with Z3
   - Concolic path exploration
   - Coverage-guided fuzzing
   - Invariant mining

5. **AI Enhancement Phase**
   - LLM-powered vulnerability explanation
   - Multi-LLM consensus voting
   - Attack strategy generation
   - Fix suggestion generation

6. **Proving Phase**
   - Build exploit transactions
   - Simulate on devnet
   - Execute real transactions (if enabled)
   - Capture transaction signatures

7. **Reporting Phase**
   - Generate structured JSON
   - Create Markdown report
   - Build HTML visualization
   - Post to forum (if enabled)
   - Register on-chain (if enabled)

### 4.3 Data Flow

```
Source Code (String)
        │
        ▼
   syn::parse_file()
        │
        ▼
   syn::File (AST)
        │
        ├──────────────────────────────────────────┐
        ▼                                          ▼
  ProgramAnalyzer                            TaintAnalyzer
  - scan_for_vulnerabilities()               - analyze_source()
  - extract_account_schemas()                - track_propagation()
        │                                          │
        ▼                                          ▼
  Vec<VulnerabilityFinding>               Vec<TaintFlow>
        │                                          │
        └──────────────┬───────────────────────────┘
                       ▼
              EnhancedFindings
                       │
                       ▼
              TransactionForge
              - build_exploit()
              - simulate_exploit()
                       │
                       ▼
              ExploitResult
                       │
                       ▼
              AuditReport
              - findings
              - proofs
              - recommendations
```

---

## 5. CLI Reference

### 5.1 Main Binary: `solana-security-swarm`

#### Input Options

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--repo` | `-r` | STRING | - | GitHub repository URL to scan |
| `--idl` | `-i` | PATH | - | Path to Anchor IDL JSON file |
| `--test-mode` | - | FLAG | false | Use built-in vulnerable programs |
| `--watcher` | - | FLAG | false | Continuous mainnet monitoring |

#### API & Authentication

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--api-key` | STRING | **Required** | OpenRouter API key |
| `--hackathon-api-key` | STRING | - | Forum platform API key |
| `--model` | STRING | `anthropic/claude-sonnet-4` | LLM model ID |

#### Network Configuration

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rpc-url` | STRING | `https://api.devnet.solana.com` | Solana RPC endpoint |

#### Output Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output-dir` | PATH | `audit_reports` | Report output directory |
| `--post-to-forum` | FLAG | false | Submit to hackathon forum |
| `--auto-submit` | FLAG | false | Auto-submit on completion |

#### Analysis Features

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prove` | FLAG | false | Enable exploit proving |
| `--register` | FLAG | false | Register exploits on-chain |
| `--consensus` | FLAG | false | Multi-LLM consensus mode |
| `--dry-run` | FLAG | false | Simulation mode (no transactions) |

### 5.2 Environment Variables

| Variable | Flag Equivalent | Description |
|----------|-----------------|-------------|
| `OPENROUTER_API_KEY` | `--api-key` | OpenRouter API key |
| `SOLANA_RPC_URL` | `--rpc-url` | Solana RPC endpoint |
| `LLM_MODEL` | `--model` | LLM model identifier |
| `HACKATHON_API_KEY` | `--hackathon-api-key` | Forum API key |

### 5.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Analysis error |
| 2 | Configuration error |

---

## 6. All Crates Detailed Documentation

### 6.1 Core Crates

#### 6.1.1 `orchestrator` (~7,500 lines)

**Purpose:** Main CLI application and analysis pipeline orchestration.

**Key Modules:**

| Module | Lines | Description |
|--------|-------|-------------|
| `main.rs` | ~600 | CLI entry point, argument parsing |
| `audit_pipeline.rs` | ~800 | Core audit workflow |
| `comprehensive_analysis.rs` | ~850 | Multi-engine analysis |
| `enhanced_comprehensive.rs` | ~690 | Enhanced analysis patterns |
| `flash_loan_detector.rs` | ~560 | Flash loan vulnerability detection |
| `flash_loan_enhanced.rs` | ~980 | Enhanced flash loan patterns |
| `oracle_analyzer.rs` | ~600 | Oracle security analysis |
| `oracle_enhanced.rs` | ~910 | Enhanced oracle patterns |
| `pda_analyzer.rs` | ~500 | PDA security analysis |
| `reentrancy_detector.rs` | ~330 | Reentrancy detection |
| `on_chain_registry.rs` | ~310 | Blockchain registration |
| `markdown_engine.rs` | ~300 | Report generation |
| `terminal_ui.rs` | ~400 | Terminal visualization |
| `watcher.rs` | ~200 | Mainnet monitoring |
| `pdf_report.rs` | 9 | **STUB - Minimal HTML only** |

**Key Structs:**

```rust
pub struct EnterpriseAuditor {
    source_dir: PathBuf,
    output_dir: PathBuf,
    api_key: String,
    model: String,
    rpc_url: String,
    test_mode: bool,
    dry_run: bool,
}

pub struct AuditReport {
    pub program_id: String,
    pub security_score: u8,
    pub findings: Vec<VulnerabilityFinding>,
    pub duration_secs: u64,
    pub timestamp: String,
}
```

**Status:** ✅ Fully functional

---

#### 6.1.2 `program-analyzer` (~2,000 lines)

**Purpose:** Core static analysis engine with AST parsing and vulnerability detection.

**Key Features:**
- Real AST parsing via `syn` crate
- 52 vulnerability pattern database
- Function-level analysis
- Account schema extraction
- Parallel scanning support

**Key Structs:**

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
```

**Key Methods:**

```rust
impl ProgramAnalyzer {
    pub fn new(program_dir: &Path) -> Result<Self, AnalyzerError>;
    pub fn from_source(source: &str) -> Result<Self, AnalyzerError>;
    pub fn scan_for_vulnerabilities(&self) -> Vec<VulnerabilityFinding>;
    pub fn scan_for_vulnerabilities_parallel(&self) -> Vec<VulnerabilityFinding>;
    pub fn extract_account_schemas(&self) -> Vec<AccountSchema>;
    pub fn extract_instruction_logic(&self, name: &str) -> Option<InstructionLogic>;
}
```

**Status:** ✅ Fully functional

---

#### 6.1.3 `transaction-forge` (~400 lines)

**Purpose:** Builds and executes exploit transactions on Solana.

**Key Features:**
- Real RPC client integration
- Missing signer exploit builder
- Integer overflow exploit builder
- Custom exploit builder
- Transaction simulation
- Real transaction execution

**Key Structs:**

```rust
pub struct TransactionForge {
    client: RpcClient,
    config: ForgeConfig,
    payer: Option<Keypair>,
}

pub struct ExploitResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub error_code: Option<u32>,
    pub error_message: Option<String>,
    pub logs: Vec<String>,
    pub compute_units_used: Option<u64>,
}

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

**Key Methods:**

```rust
impl TransactionForge {
    pub fn new(config: ForgeConfig) -> Self;
    pub fn devnet() -> Self;
    pub fn mainnet_readonly() -> Self;
    pub fn build_missing_signer_exploit(&self, ...) -> Result<Instruction, ForgeError>;
    pub fn build_overflow_exploit(&self, ...) -> Result<Instruction, ForgeError>;
    pub fn build_custom_exploit(&self, ...) -> Result<Instruction, ForgeError>;
    pub fn simulate_exploit(&self, instruction: &Instruction) -> Result<ExploitResult, ForgeError>;
    pub fn execute_exploit(&self, instruction: &Instruction) -> Result<ExploitResult, ForgeError>;
    pub fn verify_vulnerability(&self, ...) -> Result<(bool, ExploitResult), ForgeError>;
}
```

**Status:** ✅ Fully functional

---

#### 6.1.4 `consensus-engine` (~386 lines)

**Purpose:** Multi-LLM voting for vulnerability verification.

**Key Features:**
- Multiple LLM provider support (OpenRouter, OpenAI, Anthropic, NVIDIA)
- Weighted voting
- Configurable agreement thresholds
- Confidence scoring
- Batch verification

**Key Structs:**

```rust
pub struct ConsensusEngine {
    client: Client,
    models: Vec<LlmConfig>,
    threshold: f32,
    pub require_majority: bool,
}

pub enum Verdict {
    Confirmed,
    Rejected,
    Uncertain,
}

pub struct ConsensusResult {
    pub finding_id: String,
    pub final_verdict: Verdict,
    pub votes: Vec<LlmVote>,
    pub agreement_ratio: f32,
    pub confidence_score: f32,
    pub should_report: bool,
}
```

**Key Methods:**

```rust
impl ConsensusEngine {
    pub fn new(models: Vec<LlmConfig>) -> Self;
    pub fn with_openrouter(api_key: &str) -> Self;
    pub fn with_threshold(self, threshold: f32) -> Self;
    pub async fn verify_finding(&self, finding: &FindingForConsensus) -> Result<ConsensusResult, ConsensusError>;
    pub async fn verify_findings_batch(&self, findings: &[FindingForConsensus]) -> Vec<ConsensusResult>;
    pub fn filter_confirmed<'a>(&self, results: &'a [ConsensusResult]) -> Vec<&'a ConsensusResult>;
}
```

**Status:** ✅ Fully functional

---

#### 6.1.5 `invariant-miner` (~422 lines)

**Purpose:** Automatic program invariant discovery.

**Key Features:**
- Balance conservation invariants
- Access control invariants
- Arithmetic bounds invariants
- State transition invariants
- Evidence-based mining
- Counterexample detection

**Key Structs:**

```rust
pub struct InvariantMiner {
    config: MinerConfig,
    discovered_invariants: Vec<MinedInvariant>,
    balance_vars: HashSet<String>,
    authority_vars: HashSet<String>,
    state_vars: HashSet<String>,
}

pub enum InvariantCategory {
    BalanceConservation,
    StateTransition,
    AccessControl,
    ArithmeticBounds,
    AccountRelationship,
    Temporal,
}

pub struct Invariant {
    pub id: String,
    pub category: InvariantCategory,
    pub expression: String,
    pub description: String,
    pub confidence: f32,
    pub source_locations: Vec<String>,
    pub violation_impact: String,
}
```

**Status:** ✅ Fully functional

---

#### 6.1.6 `secure-code-gen` (~313 lines)

**Purpose:** Generates secure code patterns and fixes.

**Key Features:**
- 8 secure code patterns
- Vulnerability-to-fix mapping
- Template-based generation
- Multiple fix formats

**Available Patterns:**

| Pattern ID | Name | Fixes |
|------------|------|-------|
| `signer-check` | Signer Validation | SOL-001, SOL-047 |
| `owner-check` | Owner Validation | SOL-003, SOL-015 |
| `checked-arithmetic` | Checked Arithmetic | SOL-002, SOL-037, SOL-038, SOL-045 |
| `pda-validation` | PDA Validation | SOL-007, SOL-008, SOL-027 |
| `reentrancy-guard` | Reentrancy Guard | SOL-017, SOL-018 |
| `token-validation` | Token Validation | SOL-021, SOL-023, SOL-024 |
| `slippage-protection` | Slippage Protection | SOL-033, SOL-034, SOL-051 |
| `account-close` | Safe Account Close | SOL-009, SOL-028, SOL-029 |

**Status:** ✅ Fully functional

---

### 6.2 Analysis Crates

#### 6.2.1 `taint-analyzer` (~500 lines)

**Purpose:** Tracks data flow from tainted sources to dangerous sinks.

**Sources Tracked:**
- `ctx.accounts.*`
- `remaining_accounts`
- `Pubkey::new*`
- `data[*]`
- User-supplied inputs

**Sinks Tracked:**
- `invoke`, `invoke_signed`
- `transfer`, `token::mint_to`
- `lamports` modifications
- Authority assignments

**Status:** ✅ Fully functional

---

#### 6.2.2 `dataflow-analyzer` (~755 lines)

**Purpose:** Control flow graph construction and dataflow analysis.

**Key Features:**
- CFG construction from AST
- Reaching definitions analysis
- Live variable analysis
- Use-def chain extraction
- Dead definition detection

**Status:** ✅ Fully functional (algorithm correct, operates on AST)

---

#### 6.2.3 `abstract-interpreter` (~712 lines)

**Purpose:** Abstract interpretation with interval domains.

**Domains:**
- `IntervalDomain` - Numeric bounds tracking
- `SignDomain` - Sign tracking (positive/negative/zero)

**Operations:**
- Join (⊔)
- Meet (⊓)
- Widening (∇)

**Status:** ✅ Fully functional

---

#### 6.2.4 `symbolic-engine` (~284 lines)

**Purpose:** Z3-based symbolic execution for vulnerability proving.

**Key Features:**
- Z3 SMT solver integration
- Arithmetic overflow detection
- Authority bypass detection
- Invariant violation proofs
- Counterexample generation

**Dependencies:**
- Requires `z3-sys` crate
- Requires system Z3 libraries

**Status:** ✅ Fully functional (requires Z3 installation)

---

#### 6.2.5 `concolic-executor` (~456 lines)

**Purpose:** Concrete + symbolic execution for path exploration.

**Key Features:**
- Path condition tracking
- Constraint solving for alternatives
- Coverage tracking
- Boundary input generation

**Status:** ✅ Fully functional

---

#### 6.2.6 `security-fuzzer` (~697 lines)

**Purpose:** Coverage-guided mutation-based fuzzing.

**Mutation Strategies:**
- Bit flipping
- Byte replacement
- Arithmetic mutations
- Splice mutations
- Random insertions

**Supported Types:**
- u8 through u128
- Pubkey (32 bytes)
- Arbitrary byte arrays

**Status:** ✅ Fully functional

---

#### 6.2.7 `cpi-analyzer` (~1,640 lines)

**Purpose:** Cross-program invocation security analysis.

**Patterns Detected:**
- Arbitrary CPI targets
- Missing program ID validation
- Privilege escalation via CPI
- Deep CPI chains
- Callback patterns

**Status:** ✅ Fully functional

---

#### 6.2.8 `economic-verifier` (~1,530 lines)

**Purpose:** Economic security verification for DeFi protocols.

**Checks:**
- Price manipulation risks
- Flash loan vulnerabilities
- Slippage protection
- Fee calculation correctness
- Liquidity safety

**Status:** ✅ Functional (pattern-based)

---

### 6.3 Integration Crates

#### 6.3.1 `llm-strategist` (~304 lines)

**Purpose:** LLM integration for exploit strategy generation.

**Key Features:**
- OpenRouter API integration
- OpenAI direct API support
- NVIDIA NIM API support
- Exploit strategy generation
- System invariant inference

**Supported API Providers:**
- OpenRouter (default): `sk-or-*` keys
- OpenAI: `sk-proj-*` or `sk-*` keys
- NVIDIA NIM: `nvapi-*` keys

**Key Methods:**

```rust
impl LlmStrategist {
    pub async fn generate_exploit_strategy(
        &self,
        vulnerability: &VulnerabilityFinding,
        instruction_code: &str,
    ) -> Result<ExploitStrategy, StrategistError>;
    
    pub async fn infer_system_invariants(
        &self,
        program_code: &str,
    ) -> Result<Vec<LogicInvariant>, StrategistError>;
    
    pub async fn enhance_finding(
        &self,
        description: &str,
        attack_scenario: &str,
    ) -> Result<EnhancedFinding, StrategistError>;  // ⚠️ Stub implementation
}
```

**Status:** ✅ Mostly functional (enhance_finding is stub)

---

#### 6.3.2 `hackathon-client` (~126 lines)

**Purpose:** HTTP client for hackathon forum API.

**Key Methods:**

```rust
impl HackathonClient {
    pub fn new(api_key: String, api_url: String) -> Self;
    
    pub async fn create_post(
        &self,
        title: &str,
        body: &str,
        tags: &[&str]
    ) -> Result<String, String>;
    
    pub async fn post_update(
        &self,
        post_id: &str,
        title: &str,
        body: &str,
        tags: &[&str]
    ) -> Result<String, String>;
    
    pub async fn submit_audit_results(
        &self,
        program_name: &str,
        findings_count: usize,
        critical_count: usize,
        high_count: usize,
        report_markdown: &str,
    ) -> Result<String, String>;
}
```

**Status:** ✅ Fully functional

---

#### 6.3.3 `ai-enhancer` (~417 lines)

**Purpose:** AI-powered vulnerability analysis enhancement.

**Status:** ✅ Fully functional

---

#### 6.3.4 `attack-simulator` (35 lines)

**Purpose:** Attack scenario generation.

**Note:** This is a lightweight template generator, not a real simulator.

```rust
impl AttackSimulator {
    pub fn generate_simulation(finding: &VulnerabilityFinding) -> SimulationResult;
    pub fn format_markdown(result: &SimulationResult) -> String;
}
```

**Status:** ⚠️ Minimal - generates template attack steps only

---

### 6.4 Expert Crates

These crates contain domain-specific security knowledge:

| Crate | Patterns | Status |
|-------|----------|--------|
| `account-security-expert` | SOL-001, SOL-003 | ✅ Working |
| `token-security-expert` | SOL-010 | ✅ Working |
| `defi-security-expert` | SOL-020 | ✅ Working |
| `arithmetic-security-expert` | SOL-002 | ✅ Working |

**Note:** Each expert crate handles only a few vulnerability IDs. Most analysis is done by `program-analyzer`.

---

## 7. On-Chain Programs

### 7.1 `exploit-registry` (~400 lines)

**Purpose:** On-chain exploit submission and tracking.

**Instructions:**
- `initialize` - Initialize registry state
- `submit_exploit` - Submit new exploit finding
- `validate_exploit` - Validator confirms exploit
- `add_validator` - Admin adds validator
- `withdraw_stake` - Withdraw staked funds

**Account Types:**
- `RegistryState` - Global registry configuration
- `ExploitRecord` - Individual exploit entry
- `ValidatorAccount` - Authorized validator

**Status:** ✅ Fully functional

---

### 7.2 `security_shield` (~2,900 lines)

**Purpose:** Runtime security features for Solana programs.

**Modules:**
- Flash loan defense
- MEV defense
- Oracle security
- Secure vault
- Emergency systems
- Compute guards
- Rent guards
- Token extension support

**Note:** Large scope - could benefit from being split into multiple programs.

**Status:** ⚠️ Functional but untested on devnet

---

### 7.3 Vulnerable Test Programs

These programs are intentionally vulnerable for testing:

| Program | Vulnerabilities |
|---------|-----------------|
| `vulnerable-vault` | Missing signer, overflow, PDA issues |
| `vulnerable-token` | No authority check, mint manipulation |
| `vulnerable-staking` | Reentrancy, underflow |

---

## 8. Vulnerability Database

### 8.1 Complete Pattern List (52 Patterns)

#### Authentication & Authorization (SOL-001, SOL-003, SOL-029, SOL-030, SOL-041, SOL-047)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-001 | Missing Signer Check | CRITICAL | Authority not validated as signer |
| SOL-003 | Missing Owner Check | CRITICAL | Account owner not validated |
| SOL-029 | Missing Close Authority | HIGH | Improper account closure |
| SOL-030 | Privilege Escalation | CRITICAL | Unauthorized privilege gain |
| SOL-041 | Unrestricted Transfer | CRITICAL | No transfer restrictions |
| SOL-047 | Missing Access Control | CRITICAL | No access control checks |

#### Arithmetic Safety (SOL-002, SOL-037-040, SOL-045)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-002 | Integer Overflow | HIGH | Unchecked arithmetic |
| SOL-037 | Division Before Multiplication | MEDIUM | Precision loss |
| SOL-038 | Precision Loss | HIGH | Rounding errors |
| SOL-039 | Rounding Direction Error | MEDIUM | Incorrect rounding |
| SOL-040 | Missing Zero Check | MEDIUM | Division by zero |
| SOL-045 | Unsafe Exponentiation | HIGH | Overflow in power |

#### Account Validation (SOL-004, SOL-006, SOL-011-014)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-004 | Type Cosplay | CRITICAL | Account type confusion |
| SOL-006 | Duplicate Mutable Accounts | HIGH | Same account passed twice |
| SOL-011 | Reinitialization | HIGH | Account can be reinitialized |
| SOL-012 | Account Data Mismatch | HIGH | Relationship not validated |
| SOL-013 | Missing Rent Exemption | MEDIUM | Rent not checked |
| SOL-014 | Unsafe Deserialization | HIGH | Invalid data parsing |

#### PDA Security (SOL-007, SOL-008, SOL-027)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-007 | Bump Seed Issues | HIGH | Non-canonical bump |
| SOL-008 | PDA Sharing | HIGH | Shared PDA across users |
| SOL-027 | Missing Seeds Validation | HIGH | Seeds not verified |

#### CPI Security (SOL-005, SOL-015, SOL-016, SOL-026)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-005 | Arbitrary CPI | CRITICAL | Unvalidated CPI target |
| SOL-015 | Missing Program ID Check | CRITICAL | CPI program not verified |
| SOL-016 | Unchecked Return Value | HIGH | CPI result ignored |
| SOL-026 | Deep CPI Chain | MEDIUM | Excessive CPI depth |

#### Reentrancy & DeFi (SOL-017-020)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-017 | Cross-Program Reentrancy | CRITICAL | State modification after CPI |
| SOL-018 | Flash Loan Vulnerability | CRITICAL | Unprotected flash loans |
| SOL-019 | Oracle Price Manipulation | CRITICAL | Manipulable price feeds |
| SOL-020 | Stale Oracle Data | HIGH | Outdated price data |

#### Token Security (SOL-021-024, SOL-031-032)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-021 | Unprotected Mint Authority | CRITICAL | Mint authority exposed |
| SOL-022 | Freeze Authority Issues | HIGH | Freeze authority problems |
| SOL-023 | Token Account Confusion | HIGH | Wrong token account |
| SOL-024 | Missing Token Validation | HIGH | Token not verified |
| SOL-031 | Unlimited Token Mint | CRITICAL | No mint limits |
| SOL-032 | Missing Decimals Check | MEDIUM | Decimal mismatch |

#### MEV & Slippage (SOL-033-035, SOL-051)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-033 | Missing Slippage Protection | HIGH | No slippage limits |
| SOL-034 | Sandwich Attack Vulnerability | HIGH | Sandwichable transactions |
| SOL-035 | Front-Running Vulnerability | HIGH | Frontrunnable operations |
| SOL-051 | Missing Deadline Check | MEDIUM | No transaction deadline |

#### Account Management (SOL-009, SOL-010, SOL-025, SOL-028, SOL-048)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-009 | Account Closing Issues | HIGH | Revival attack possible |
| SOL-010 | Sysvar Address Issues | MEDIUM | Fake sysvar injection |
| SOL-025 | Lamport Balance Drain | CRITICAL | Balance can be drained |
| SOL-028 | Account Resurrection | HIGH | Closed account revived |
| SOL-048 | Account Hijacking | CRITICAL | Account takeover |

#### Miscellaneous (SOL-036, SOL-042-044, SOL-046, SOL-049-050, SOL-052)

| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| SOL-036 | Missing Amount Validation | HIGH | No input validation |
| SOL-042 | Missing Pause Mechanism | MEDIUM | No emergency pause |
| SOL-043 | Hardcoded Address | LOW | Inflexible addresses |
| SOL-044 | Missing Event Emission | LOW | No logging |
| SOL-046 | Time Manipulation Risk | MEDIUM | Clock abuse |
| SOL-049 | LP Token Manipulation | HIGH | LP token exploits |
| SOL-050 | Reward Calculation Error | HIGH | Wrong rewards |
| SOL-052 | Governance Attack | HIGH | Governance exploits |

---

## 9. Implementation Status

### 9.1 Fully Implemented ✅

| Component | Lines | Status Details |
|-----------|-------|----------------|
| Program Analyzer | ~2,000 | 52 patterns, AST parsing |
| Transaction Forge | ~400 | Real RPC, simulations |
| Consensus Engine | ~386 | Multi-LLM voting |
| Invariant Miner | ~422 | Pattern discovery |
| Secure Code Gen | ~313 | 8 secure patterns |
| Hackathon Client | ~126 | HTTP API calls |
| Taint Analyzer | ~500 | Source-sink tracking |
| Dataflow Analyzer | ~755 | CFG, reaching defs |
| Abstract Interpreter | ~712 | Interval domains |
| Symbolic Engine | ~284 | Z3 integration |
| Concolic Executor | ~456 | Path exploration |
| Security Fuzzer | ~697 | Mutation fuzzing |
| CPI Analyzer | ~1,640 | CPI patterns |
| Reentrancy Detector | ~332 | 4 patterns |
| On-Chain Registry | ~311 | Real transactions |

### 9.2 Partially Implemented ⚠️

| Component | Issue |
|-----------|-------|
| `llm-strategist.enhance_finding()` | Returns stub data |
| `attack-simulator` | Template text only, no real simulation |
| `pdf_report` | Single-line HTML, no real PDF |
| Expert crates | Only 1-4 patterns each |

### 9.3 Known Gaps

| Feature | Status | Notes |
|---------|--------|-------|
| BPF Bytecode Analysis | ❌ Not implemented | Source-only analysis |
| Real Coverage Tracking | ❌ Not implemented | No instrumentation |
| Formal Verification | ❌ Not implemented | Pattern-based only |
| Comprehensive CI/CD | ⚠️ Partial | Workflow exists |

---

## 10. Known Issues & Placeholders

### 10.1 Placeholder Code Locations

| Location | Line | Issue |
|----------|------|-------|
| `llm-strategist/src/lib.rs` | 225 | `enhance_finding()` returns stub |
| `dataflow-analyzer/src/live_vars.rs` | 9 | Comment says "Placeholder" |
| `program-analyzer/src/anchor_extractor.rs` | 24 | "placeholder logic" comment |
| `program-analyzer/src/report_generator.rs` | 7 | "Placeholder configuration fields" |

### 10.2 Stub Functions

```rust
// llm-strategist/src/lib.rs:220-233
pub async fn enhance_finding(
    &self,
    description: &str,
    attack_scenario: &str,
) -> Result<EnhancedFinding, StrategistError> {
    // Stub implementation for now
    Ok(EnhancedFinding {
        explanation: format!("AI analysis of: {}", description),
        vulnerability_type: "Unknown".to_string(),
        description: description.to_string(),
        attack_scenario: attack_scenario.to_string(),
        fix_suggestion: "Review and fix the identified issue.".to_string(),
    })
}
```

### 10.3 Minimal Implementations

```rust
// pdf_report.rs - Only 9 lines, generates minimal HTML
pub struct PdfReportGenerator;

impl PdfReportGenerator {
    pub fn generate_html_report(report: &AuditReport) -> String {
        format!("<html><body><h1>Audit Report for {}</h1><p>Score: {}</p></body></html>", 
            report.program_id, report.security_score)
    }
}
```

### 10.4 Compiler Warnings

```
warning: unused import: `Config`
  --> crates/symbolic-engine/src/lib.rs:13:10

warning: fields `config` and `context` are never read
 --> crates/symbolic-engine/src/solver.rs:4:5

warning: field `context` is never read
 --> crates/symbolic-engine/src/constraint_builder.rs:5:5
```

---

## 11. Test Coverage

### 11.1 Test Summary

| Crate | Unit Tests | Integration Tests | Property Tests |
|-------|------------|-------------------|----------------|
| program-analyzer | 15+ | 4 | 11 |
| taint-analyzer | 14 | - | - |
| dataflow-analyzer | 7 | - | - |
| abstract-interpreter | 6 | - | - |
| security-fuzzer | 3 | - | - |
| symbolic-engine | 3 | - | - |
| consensus-engine | 3 | - | - |
| transaction-forge | 3 | - | - |
| **Total** | **54+** | **4** | **11** |

### 11.2 Running Tests

```bash
# Run all workspace tests
cargo test --workspace

# Run specific crate tests
cargo test -p program-analyzer

# Run with verbose output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_overflow_detection
```

### 11.3 Test Targets

The `test_targets/` directory contains real-world programs for testing:

| Directory | Description | Programs |
|-----------|-------------|----------|
| `sealevel-attacks/` | Intentionally vulnerable | 11 programs |
| `raydium-amm/` | Production DeFi | AMM contracts |
| `spl/` | Solana Program Library | Token, governance, etc. |
| `solana-cctp-contracts/` | Circle CCTP | Cross-chain |

---

## 12. Configuration Reference

### 12.1 Environment Configuration

```bash
# .env file
OPENROUTER_API_KEY=sk-or-v1-xxxxx
SOLANA_RPC_URL=https://api.devnet.solana.com
LLM_MODEL=anthropic/claude-sonnet-4
HACKATHON_API_KEY=forum-key
```

### 12.2 Analyzer Configuration

```toml
# analyzer.example.toml

[analyzer]
# Severity threshold (1-5, only report findings >= this)
min_severity = 2

# Enable/disable specific vulnerability categories
[analyzer.categories]
authentication = true
arithmetic = true
account_validation = true
pda_security = true
cpi_security = true
reentrancy = true
oracle_security = true
token_security = true
mev_protection = true

# Analysis thresholds
[analyzer.thresholds]
max_function_complexity = 50
max_cpi_depth = 4
oracle_staleness_seconds = 3600
```

### 12.3 Forge Configuration

```rust
pub struct ForgeConfig {
    pub rpc_url: String,           // Solana RPC endpoint
    pub commitment: CommitmentConfig,
    pub simulate_only: bool,       // Default: true (safe)
    pub max_retries: u32,          // Transaction retry count
}
```

---

## 13. API Reference

### 13.1 ProgramAnalyzer API

```rust
// Create analyzer from directory
let analyzer = ProgramAnalyzer::new(Path::new("./programs/my-program"))?;

// Create from source string
let analyzer = ProgramAnalyzer::from_source(source_code)?;

// Scan for vulnerabilities
let findings: Vec<VulnerabilityFinding> = analyzer.scan_for_vulnerabilities();

// Parallel scanning (batch processing)
let findings = analyzer.scan_for_vulnerabilities_parallel();

// Extract account schemas
let schemas: Vec<AccountSchema> = analyzer.extract_account_schemas();

// Get instruction logic
let logic: Option<InstructionLogic> = analyzer.extract_instruction_logic("transfer");
```

### 13.2 TransactionForge API

```rust
// Create forge for devnet
let forge = TransactionForge::devnet();

// Set payer keypair
let forge = forge.with_payer(keypair);

// Build exploit instruction
let instruction = forge.build_missing_signer_exploit(
    "program_id",
    "victim_account",
    "attacker_account"
)?;

// Simulate without executing
let result = forge.simulate_exploit(&instruction)?;

// Execute on-chain
let result = forge.execute_exploit(&instruction)?;
```

### 13.3 ConsensusEngine API

```rust
// Create with OpenRouter
let engine = ConsensusEngine::with_openrouter("api-key");

// Configure threshold
let engine = engine.with_threshold(0.7);

// Verify single finding
let result = engine.verify_finding(&finding).await?;

// Batch verification
let results = engine.verify_findings_batch(&findings).await;

// Filter confirmed findings
let confirmed = engine.filter_confirmed(&results);
```

---

## 14. Troubleshooting

### 14.1 Common Issues

#### "API key required"
```bash
# Solution: Set the API key
export OPENROUTER_API_KEY="your-key-here"
# Or
./solana-security-swarm --api-key "your-key"
```

#### "Parse error" on source files
```bash
# Ensure valid Rust syntax
cargo check --lib

# Some Anchor macros may not parse without dependencies
# Try analyzing the full project, not individual files
```

#### "RPC connection failed"
```bash
# Check network connectivity
curl https://api.devnet.solana.com -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'

# Try a different RPC
--rpc-url https://api.mainnet-beta.solana.com
```

#### Z3 compilation errors
```bash
# Install system Z3
sudo apt install z3 libz3-dev  # Ubuntu
brew install z3                 # macOS

# Or exclude Z3 crates from build
cargo build --release  # Uses default-members (excludes Z3)
```

### 14.2 Performance Issues

```bash
# Reduce analysis scope
--test-mode  # Use built-in programs only

# Use dry-run mode
--dry-run  # No network transactions

# Limit LLM calls
--model "google/gemini-flash-1.5"  # Faster model
```

---

## 15. Development Guide

### 15.1 Adding New Vulnerability Patterns

1. Add pattern to `crates/program-analyzer/src/vulnerability_db.rs`:

```rust
patterns.push(VulnerabilityPattern::new(
    "SOL-053",                    // ID
    "New Vulnerability Name",     // Name
    4,                            // Severity (1-5)
    check_new_vulnerability       // Check function
));

fn check_new_vulnerability(code: &str) -> Option<VulnerabilityFinding> {
    // Pattern detection logic
    if code.contains("vulnerable_pattern") {
        return Some(VulnerabilityFinding {
            vuln_id: "SOL-053".to_string(),
            // ... fill in fields
        });
    }
    None
}
```

2. Add fix mapping to `crates/secure-code-gen/src/lib.rs`:

```rust
fn map_vuln_to_pattern(&self, vuln_id: &str) -> Option<&str> {
    match vuln_id {
        // ... existing mappings
        "SOL-053" => Some("new-pattern"),
        _ => None,
    }
}
```

3. Add tests:

```rust
#[test]
fn test_new_vulnerability_detection() {
    let analyzer = ProgramAnalyzer::from_source(r#"
        // vulnerable code sample
    "#).unwrap();
    let findings = analyzer.scan_for_vulnerabilities();
    assert!(findings.iter().any(|f| f.vuln_id == "SOL-053"));
}
```

### 15.2 Adding New Analyzers

1. Create new crate:
```bash
cargo new crates/my-analyzer --lib
```

2. Add to workspace `Cargo.toml`:
```toml
members = [
    # ... existing
    "crates/my-analyzer",
]
```

3. Implement analyzer trait pattern:
```rust
pub struct MyAnalyzer;

impl MyAnalyzer {
    pub fn new() -> Self { Self }
    
    pub fn analyze(&self, source: &str) -> Vec<Finding> {
        // Analysis logic
    }
}
```

4. Integrate in orchestrator.

### 15.3 Contributing Guidelines

1. **Code Style**
   - Run `cargo fmt` before committing
   - Run `cargo clippy` and fix warnings
   - Add rustdoc comments to public APIs

2. **Testing**
   - Add unit tests for new functionality
   - Add false positive tests for vulnerability patterns
   - Run full test suite before PR

3. **Documentation**
   - Update this documentation file
   - Update CLI_REFERENCE.md if adding flags
   - Add inline comments for complex logic

---

## Appendix A: File Inventory

### Rust Source Files by Crate

| Crate | Files | Total Lines |
|-------|-------|-------------|
| orchestrator | 18 | ~7,500 |
| program-analyzer | 8 | ~2,000 |
| cpi-analyzer | 3 | ~1,640 |
| economic-verifier | 3 | ~1,530 |
| dataflow-analyzer | 6 | ~755 |
| abstract-interpreter | 4 | ~712 |
| security-fuzzer | 2 | ~697 |
| taint-analyzer | 6 | ~500 |
| concolic-executor | 2 | ~456 |
| invariant-miner | 2 | ~422 |
| ai-enhancer | 2 | ~417 |
| transaction-forge | 2 | ~400 |
| consensus-engine | 2 | ~386 |
| reentrancy-detector | (in orchestrator) | ~332 |
| secure-code-gen | 2 | ~313 |
| on-chain-registry | (in orchestrator) | ~311 |
| llm-strategist | 2 | ~304 |
| symbolic-engine | 6 | ~284 |
| hackathon-client | 2 | ~126 |
| attack-simulator | 2 | ~35 |

---

## Appendix B: Dependency Graph

```
orchestrator
├── program-analyzer
│   └── syn, quote, proc-macro2
├── transaction-forge
│   └── solana-sdk, solana-client
├── consensus-engine
│   └── reqwest, serde
├── llm-strategist
│   └── reqwest, serde_json
├── hackathon-client
│   └── reqwest
├── taint-analyzer
│   └── syn
├── dataflow-analyzer
│   └── syn
├── cpi-analyzer
│   └── syn
├── symbolic-engine
│   └── z3, syn
├── security-fuzzer
│   └── rand
├── invariant-miner
│   └── syn, quote
├── secure-code-gen
│   └── (minimal deps)
└── attack-simulator
    └── program-analyzer
```

---

## Appendix C: Changelog

### Version 0.1.0 (2026-02-09)

**Initial Release:**
- 24 analysis crates
- 52 vulnerability patterns
- Multi-LLM consensus
- Real transaction execution
- On-chain exploit registry
- Comprehensive documentation

---

*This documentation covers the complete Solana Security Swarm project as of 2026-02-09.*
