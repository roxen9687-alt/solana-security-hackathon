# Complete Project Documentation - Part 2: Programs & Core Analysis Engine

## 5. ON-CHAIN PROGRAMS (Anchor Framework)

### 5.1 exploit-registry

**Location**: `/programs/exploit-registry/`

**Purpose**: On-chain immutable registry for storing verified security vulnerabilities and exploits

**Program ID**: `HG1LKfUipjq5d1WdXLpxNqtv2ZbgFHqJZvvmFZoXNhbz`

#### File: `lib.rs` (78 lines)

**Imports**:
- `anchor_lang::prelude::*` - Core Anchor framework
- `state::*` - Local state module

**Module Structure**:
```rust
pub mod state;  // Account state definitions
```

**Program Module**: `exploit_registry`

**Instructions**:

##### 1. `initialize(ctx: Context<Initialize>) -> Result<()>`
**Purpose**: Initializes the global registry configuration

**Parameters**: None (uses context)

**Logic Flow**:
1. Gets mutable reference to config account
2. Sets admin to transaction signer's public key
3. Initializes total_reports counter to 0
4. Sets is_frozen flag to false
5. Stores the bump seed from PDA derivation

**Account Context** (`Initialize`):
- `config`: PDA account (seeds: `[b"config"]`)
  - Space: 8 (discriminator) + 32 (admin) + 8 (total_reports) + 1 (is_frozen) + 1 (bump) = 50 bytes
  - Initialized with `init` constraint
  - Payer: admin
- `admin`: Signer (mutable, pays for account creation)
- `system_program`: System program for account creation

**Side Effects**: Creates on-chain config account

**Error Handling**: Returns Anchor errors if account creation fails

**Used By**: Initial deployment script

---

##### 2. `register_exploit(...) -> Result<()>`
**Purpose**: Registers a verified vulnerability/exploit on-chain

**Parameters**:
- `vulnerability_type: String` - Type of vulnerability (e.g., "Missing Signer Check")
- `severity: u8` - Severity level (1-5, where 5 is critical)
- `proof_hash: [u8; 32]` - SHA-256 hash of the exploit proof (IPFS/Arweave CID)
- `metadata_url: String` - URL to full exploit documentation

**Logic Flow**:
1. Gets mutable reference to exploit_profile account
2. Gets mutable reference to config account
3. Stores target program ID (the vulnerable program)
4. Stores reporter's public key
5. Records current Unix timestamp from Clock sysvar
6. Stores severity level
7. Stores vulnerability type string
8. Stores proof hash (for verification)
9. Stores metadata URL
10. Stores bump seed
11. Increments global total_reports counter

**Account Context** (`RegisterExploit`):
- `exploit_profile`: PDA account (seeds: `[b"exploit", target_program.key(), vulnerability_type.as_bytes()]`)
  - Space: 8 + ExploitProfile::SIZE (298 bytes total)
  - Initialized with `init` constraint
  - Payer: reporter
- `config`: Mutable config account (to increment counter)
- `target_program`: UncheckedAccount (the vulnerable program being reported)
- `reporter`: Signer (mutable, pays for account creation)
- `system_program`: System program

**Side Effects**: 
- Creates immutable on-chain record of vulnerability
- Increments global exploit counter

**Error Handling**: Returns Anchor errors

**Used By**: `orchestrator` after successful exploit verification

---

#### File: `state.rs` (26 lines)

**Account Structs**:

##### `ExploitProfile`
**Purpose**: Stores detailed information about a verified exploit

**Fields**:
- `program_id: Pubkey` (32 bytes) - Address of the vulnerable program
- `reporter: Pubkey` (32 bytes) - Address of the security researcher who found it
- `timestamp: i64` (8 bytes) - Unix timestamp of registration
- `severity: u8` (1 byte) - Severity level (1-5)
- `vulnerability_type: String` (64 bytes allocated) - Human-readable vulnerability name
- `proof_hash: [u8; 32]` (32 bytes) - Hash of the proof document
- `metadata_url: String` (128 bytes allocated) - IPFS/Arweave link to full report
- `bump: u8` (1 byte) - PDA bump seed

**Total Size**: 298 bytes (8 discriminator + 290 data)

**Serialization**: Borsh (Solana standard)

---

##### `RegistryConfig`
**Purpose**: Global configuration for the exploit registry

**Fields**:
- `admin: Pubkey` (32 bytes) - Registry administrator
- `total_reports: u64` (8 bytes) - Total number of registered exploits
- `is_frozen: bool` (1 byte) - Emergency freeze flag
- `bump: u8` (1 byte) - PDA bump seed

**Total Size**: 50 bytes (8 discriminator + 42 data)

---

### 5.2 vulnerable-vault (security_shield)

**Location**: `/programs/vulnerable-vault/`

**Purpose**: Intentionally vulnerable DeFi vault for testing security tools. Also contains secure reference implementations.

**Program ID**: `47poGSxjXsErkcCrZqEJtomHrdxHtfAbpfYmx3xRndVJ`

**Note**: Despite the directory name "vulnerable-vault", the program module is named "security_shield" and contains both vulnerable and secure patterns.

#### File: `lib.rs` (541 lines)

**Imports**:
- `anchor_lang::prelude::*` - Core Anchor
- `anchor_spl::token_interface::{TokenAccount, Mint}` - Token 2022 support
- `anchor_spl::token::{TokenAccount as LegacyTokenAccount, Token, Mint as LegacyMint}` - Legacy SPL Token

**Module Structure**:
```rust
pub mod mev_defense_mod;           // MEV protection mechanisms
pub mod secure_oracle_mod;         // Oracle security patterns
pub mod secure_vault_mod;          // Vault deposit/withdraw logic
pub mod flash_loan_defense_mod;    // Flash loan attack prevention
pub mod emergency_systems_mod;     // Circuit breakers and pause mechanisms
pub mod token_extensions_mod;      // Token 2022 transfer fee support
pub mod pda_utils;                 // PDA helper functions
pub mod compute_guard;             // Compute budget guards
pub mod secure_time;               // Timestamp validation
pub mod rent_guard;                // Rent exemption checks
pub mod auto_response;             // Autonomous threat response
```

**Program Module**: `security_shield`

**Instructions** (23 total):

##### Core Instructions:

1. **`initialize(ctx: Context<Initialize>) -> Result<()>`**
   - **Purpose**: Initialize global program configuration
   - **Logic**: Sets admin, is_initialized flag, paused state, version, and bump
   - **Accounts**: config (PDA), authority (signer), system_program

2. **`verify_transfer_amount(ctx, amount: u64, decimals: u8) -> Result<u64>`**
   - **Purpose**: Transfer tokens with Token 2022 transfer fee validation
   - **Logic**: Calls `token_extensions_mod::handle_transfer_with_fee_check()`
   - **Returns**: Actual amount received after fees
   - **Accounts**: source, destination, mint, authority, token_program

##### MEV Defense Instructions:

3. **`swap_with_protection(ctx, amount_in: u64, min_out: u64, deadline: i64) -> Result<u64>`**
   - **Purpose**: Execute swap with MEV protection (slippage + deadline)
   - **Logic**: Delegates to `mev_defense_mod::handle_swap_with_protection()`
   - **Parameters**:
     - `amount_in`: Input token amount
     - `min_out`: Minimum acceptable output (slippage protection)
     - `deadline`: Unix timestamp deadline (prevents stale transactions)
   - **Returns**: Actual output amount
   - **Accounts**: pool (PDA), user_source, user_destination, pool_source, pool_token_out, user (signer), token_program

4. **`initialize_pool(ctx, initial_reserve_in: u64, initial_reserve_out: u64) -> Result<()>`**
   - **Purpose**: Initialize AMM pool with initial liquidity
   - **Logic**: Delegates to `mev_defense_mod::handle_initialize_pool()`
   - **Accounts**: pool (PDA), mint_in, mint_out, admin (signer), system_program

##### Oracle Security Instructions:

5. **`get_secure_price(ctx: Context<GetSecurePrice>) -> Result<u64>`**
   - **Purpose**: Fetch price with multi-oracle validation and circuit breaker
   - **Logic**: Delegates to `secure_oracle_mod::handle_get_secure_price()`
   - **Returns**: Validated price (median of Pyth + Switchboard)
   - **Accounts**: pyth_price_feed (unchecked), switchboard_feed (unchecked), price_state (PDA), token_mint

6. **`initialize_price_state(ctx: Context<InitializePriceState>) -> Result<()>`**
   - **Purpose**: Initialize oracle price tracking state
   - **Accounts**: price_state (PDA), token_mint, admin (signer), system_program

7. **`reset_circuit_breaker(ctx: Context<ResetCircuitBreaker>) -> Result<()>`**
   - **Purpose**: Admin function to reset circuit breaker after price anomaly
   - **Accounts**: price_state (PDA), token_mint, admin (signer)

##### Vault Instructions:

8. **`initialize_vault(ctx: Context<InitializeVault>) -> Result<()>`**
   - **Purpose**: Initialize secure vault for deposits
   - **Logic**: Delegates to `secure_vault_mod::handle_initialize_vault()`
   - **Accounts**: vault (PDA), admin (signer), mint, system_program

9. **`deposit(ctx, amount: u64) -> Result<u64>`**
   - **Purpose**: Deposit tokens into vault, receive shares
   - **Logic**: Delegates to `secure_vault_mod::handle_deposit()`
   - **Returns**: Number of shares minted
   - **Accounts**: vault (PDA), user_shares (PDA), user_token, vault_token, user (signer), token_program

10. **`withdraw(ctx, shares: u64) -> Result<u64>`**
    - **Purpose**: Burn shares to withdraw tokens
    - **Logic**: Delegates to `secure_vault_mod::handle_withdraw()`
    - **Returns**: Amount of tokens withdrawn
    - **Accounts**: vault (PDA), user_shares (PDA), user_token, vault_token, user (signer), token_program

11. **`initialize_user_shares(ctx: Context<InitializeUserShares>) -> Result<()>`**
    - **Purpose**: Create user's share tracking account
    - **Accounts**: user_shares (PDA), user (signer), system_program

##### Flash Loan Defense Instructions:

12. **`create_voting_escrow(ctx, amount: u64, lock_duration: i64) -> Result<()>`**
    - **Purpose**: Lock tokens in voting escrow (prevents flash loan governance attacks)
    - **Logic**: Delegates to `flash_loan_defense_mod::handle_create_voting_escrow()`
    - **Parameters**:
      - `amount`: Tokens to lock
      - `lock_duration`: Lock period in seconds
    - **Accounts**: escrow (PDA), user (signer), system_program

13. **`vote_on_proposal(ctx, proposal_id: u64, vote: bool) -> Result<()>`**
    - **Purpose**: Vote on governance proposal using locked tokens
    - **Logic**: Delegates to `flash_loan_defense_mod::handle_vote_on_proposal()`
    - **Accounts**: escrow (PDA), proposal (PDA), user (signer)

14. **`create_proposal(ctx, proposal_id: u64, title: String, voting_duration: i64) -> Result<()>`**
    - **Purpose**: Create governance proposal
    - **Accounts**: proposal (PDA), proposer (signer), system_program

15. **`execute_proposal(ctx, proposal_id: u64) -> Result<()>`**
    - **Purpose**: Execute passed proposal
    - **Accounts**: proposal (PDA)

16. **`extend_lock(ctx, additional_duration: i64) -> Result<()>`**
    - **Purpose**: Extend voting escrow lock period
    - **Accounts**: escrow (PDA), owner (signer)

17. **`withdraw_from_escrow(ctx: Context<WithdrawFromEscrow>) -> Result<()>`**
    - **Purpose**: Withdraw tokens after lock expires
    - **Accounts**: escrow (PDA), user (signer)

##### Emergency System Instructions:

18. **`initialize_emergency_state(ctx: Context<InitializeEmergencyState>) -> Result<()>`**
    - **Purpose**: Initialize emergency pause system
    - **Accounts**: emergency_state (PDA), admin (signer), system_program

19. **`emergency_pause(ctx, reason: String, duration: i64) -> Result<()>`**
    - **Purpose**: Trigger emergency pause (circuit breaker)
    - **Logic**: Delegates to `emergency_systems_mod::handle_emergency_pause()`
    - **Parameters**:
      - `reason`: Human-readable pause reason
      - `duration`: Pause duration in seconds
    - **Accounts**: emergency_state (PDA), caller (signer)

20. **`unpause(ctx: Context<Unpause>) -> Result<()>`**
    - **Purpose**: Admin function to unpause system
    - **Accounts**: emergency_state (PDA), admin (signer)

##### Commented Out (Pending CPI Integration):

21. **`autonomous_pause` (DISABLED)**
    - **Purpose**: Automatically pause when exploit detected in registry
    - **Status**: Commented out until CPI integration with exploit_registry is complete
    - **Why**: Requires cross-program invocation to read exploit_registry

**Account Structs**:

- `Config`: Global program configuration (admin, is_initialized, paused, version, bump)

**Error Codes**:
```rust
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
```

---

#### Module Files:

##### `mev_defense_mod.rs` (2229 bytes)

**Purpose**: Implements MEV (Maximal Extractable Value) protection for swaps

**Key Struct**: `ProtectedPool`
- Fields: mint_in, mint_out, reserve_in, reserve_out, last_price, last_update_slot, bump
- LEN: Calculated size constant

**Functions**:

1. **`handle_initialize_pool(...) -> Result<()>`**
   - Initializes AMM pool with reserves
   - Stores mint addresses and initial reserves
   - Records initial price and slot

2. **`handle_swap_with_protection(...) -> Result<u64>`**
   - **Validates deadline**: `require!(Clock::get()?.unix_timestamp <= deadline)`
   - **Calculates output**: Constant product formula (x * y = k)
   - **Validates slippage**: `require!(amount_out >= min_out)`
   - **Updates reserves**: Modifies pool state
   - **Returns**: Actual output amount

**MEV Protections**:
- Deadline check prevents stale transactions
- Slippage protection prevents sandwich attacks
- Price impact calculation

---

##### `secure_oracle_mod.rs` (1538 bytes)

**Purpose**: Multi-oracle price aggregation with circuit breaker

**Key Struct**: `PriceState`
- Fields: token_mint, admin, last_price, last_update_slot, circuit_breaker_triggered, price_deviation_threshold, bump
- LEN: Calculated size

**Functions**:

1. **`handle_initialize_price_state(...) -> Result<()>`**
   - Initializes price tracking
   - Sets admin and token mint
   - Sets default deviation threshold

2. **`handle_get_secure_price(...) -> Result<u64>`**
   - **Fetches Pyth price**: Reads from Pyth oracle account
   - **Fetches Switchboard price**: Reads from Switchboard aggregator
   - **Calculates median**: Takes median of two sources
   - **Checks deviation**: Triggers circuit breaker if prices diverge too much
   - **Validates freshness**: Checks timestamp/slot
   - **Returns**: Validated median price

3. **`handle_reset_circuit_breaker(...) -> Result<()>`**
   - Admin-only function
   - Resets circuit breaker flag

**Security Features**:
- Multi-oracle redundancy
- Circuit breaker for anomalies
- Freshness validation
- Deviation threshold

---

##### `secure_vault_mod.rs` (2876 bytes)

**Purpose**: Secure vault with share-based accounting

**Key Structs**:

1. **`SecureVault`**
   - Fields: admin, mint, total_shares, total_assets, bump
   - LEN: Calculated size

2. **`UserShares`**
   - Fields: owner, shares, bump
   - LEN: Calculated size

**Functions**:

1. **`handle_initialize_vault(...) -> Result<()>`**
   - Initializes vault
   - Sets admin and mint
   - Initializes counters to 0

2. **`handle_deposit(...) -> Result<u64>`**
   - **Calculates shares**: `shares = (amount * total_shares) / total_assets` (or 1:1 if first deposit)
   - **Transfers tokens**: CPI to token program
   - **Mints shares**: Updates user_shares and total_shares
   - **Updates total_assets**: Increments by deposit amount
   - **Returns**: Shares minted

3. **`handle_withdraw(...) -> Result<u64>`**
   - **Calculates withdrawal**: `amount = (shares * total_assets) / total_shares`
   - **Burns shares**: Decrements user_shares and total_shares
   - **Transfers tokens**: CPI to token program
   - **Updates total_assets**: Decrements by withdrawal amount
   - **Returns**: Tokens withdrawn

4. **`handle_initialize_user_shares(...) -> Result<()>`**
   - Creates user's share tracking account
   - Sets owner and initializes shares to 0

**Security Features**:
- Share-based accounting prevents inflation attacks
- Proper rounding (rounds down for user, up for vault)
- Atomic operations

---

##### `flash_loan_defense_mod.rs` (3057 bytes)

**Purpose**: Voting escrow system to prevent flash loan governance attacks

**Key Structs**:

1. **`VotingEscrow`**
   - Fields: owner, amount, lock_end, voting_power, bump
   - LEN: Calculated size

2. **`Proposal`**
   - Fields: id, title, proposer, yes_votes, no_votes, start_time, end_time, executed, bump
   - LEN: Calculated size

**Functions**:

1. **`handle_create_voting_escrow(...) -> Result<()>`**
   - Locks tokens for specified duration
   - Calculates voting power based on lock duration
   - Prevents flash loan attacks by requiring time-locked tokens

2. **`handle_vote_on_proposal(...) -> Result<()>`**
   - Validates escrow is locked
   - Validates proposal is active
   - Records vote weighted by voting power
   - Prevents double voting

3. **`handle_create_proposal(...) -> Result<()>`**
   - Creates governance proposal
   - Sets voting period

4. **`handle_execute_proposal(...) -> Result<()>`**
   - Validates voting period ended
   - Validates proposal passed
   - Marks as executed

5. **`handle_extend_lock(...) -> Result<()>`**
   - Extends lock duration
   - Recalculates voting power

6. **`handle_withdraw_from_escrow(...) -> Result<()>`**
   - Validates lock expired
   - Returns tokens to user

**Flash Loan Defense**:
- Time-locked tokens cannot be borrowed and returned in same transaction
- Voting power increases with lock duration
- Prevents governance manipulation via flash loans

---

##### `emergency_systems_mod.rs` (1377 bytes)

**Purpose**: Circuit breaker and emergency pause mechanisms

**Key Struct**: `EmergencyState`
- Fields: admin, is_paused, pause_reason, pause_start, pause_duration, bump
- SPACE: Calculated size

**Functions**:

1. **`handle_initialize_emergency_state(...) -> Result<()>`**
   - Initializes emergency system
   - Sets admin
   - Sets is_paused to false

2. **`handle_emergency_pause(...) -> Result<()>`**
   - Validates caller is admin or authorized guardian
   - Sets is_paused flag
   - Records reason and duration
   - Records pause start time

3. **`handle_unpause(...) -> Result<()>`**
   - Admin-only
   - Clears is_paused flag
   - Clears pause metadata

**Use Cases**:
- Detected exploit
- Oracle failure
- Abnormal market conditions
- Governance decision

---

##### `token_extensions_mod.rs` (778 bytes)

**Purpose**: Support for Token 2022 transfer fees

**Functions**:

1. **`handle_transfer_with_fee_check(...) -> Result<u64>`**
   - **Performs transfer**: CPI to token program with `transfer_checked`
   - **Reads post-transfer balance**: Checks actual amount received
   - **Calculates fee**: `fee = amount - actual_received`
   - **Returns**: Actual amount after fees

**Why Important**:
- Token 2022 supports transfer fees
- Naive code assumes full amount arrives
- This validates actual received amount

---

##### Other Module Files:

- **`pda_utils.rs`** (424 bytes): PDA derivation helpers
- **`compute_guard.rs`** (148 bytes): Compute budget validation
- **`secure_time.rs`** (109 bytes): Timestamp validation utilities
- **`rent_guard.rs`** (156 bytes): Rent exemption checks
- **`auto_response.rs`** (441 bytes): Autonomous threat response (WIP)

---

## 6. CORE ANALYSIS ENGINE

### 6.1 program-analyzer

**Location**: `/crates/program-analyzer/`

**Purpose**: Core static analysis engine that parses Rust source code and detects 52 vulnerability patterns

#### File: `lib.rs` (408 lines)

**Module Documentation** (lines 1-43):
- Comprehensive doc comments explaining the analyzer
- Lists 52 vulnerability patterns organized by category
- Provides usage examples

**Imports**:
- `colored::Colorize` - Terminal colors
- `syn::{File, Item, ItemFn, ItemStruct, Expr, Stmt}` - Rust AST types
- `quote::ToTokens` - Convert AST back to code
- `serde::{Serialize, Deserialize}` - JSON serialization
- `std::path::Path` - File system paths
- `std::fs` - File operations

**Public Modules**:
```rust
pub mod ast_parser;           // AST parsing utilities
pub mod anchor_extractor;     // Anchor-specific extraction
pub mod vulnerability_db;     // 52 vulnerability patterns
pub mod idl_loader;           // IDL file parsing
pub mod report_generator;     // Report formatting
pub mod config;               // Configuration management
pub mod traits;               // Analyzer trait definitions
pub mod metrics;              // Performance metrics
pub mod security;             // Security utilities
```

**Public Re-exports**:
```rust
pub use vulnerability_db::VulnerabilityPattern;
pub use config::{AnalyzerConfig, ConfigBuilder};
pub use traits::{Analyzer, AnalyzerCapabilities, Finding, Severity, AnalysisPipeline};
pub use metrics::{METRICS, MetricsRegistry};
pub use security::{Secret, validation, RateLimiter};
```

**Main Struct**: `ProgramAnalyzer`

**Fields**:
- `source_files: Vec<(String, File)>` - Parsed AST of all .rs files (filename, syn::File)
- `vulnerability_db: VulnerabilityDatabase` - Database of 52 vulnerability checkers

**Methods**:

##### 1. `new(program_dir: &Path) -> Result<Self, AnalyzerError>`
**Purpose**: Create analyzer by scanning directory for Rust files

**Parameters**:
- `program_dir`: Path to program directory

**Logic Flow**:
1. Creates empty source_files vector
2. Walks directory recursively using `walkdir::WalkDir`
3. For each entry:
   - Checks if file extension is ".rs"
   - Reads file content to string
   - Parses with `syn::parse_file()`
   - On success: Stores (filename, AST) tuple
   - On error: Prints warning and skips file
4. Loads vulnerability database
5. Returns analyzer instance

**Return Value**: `Result<ProgramAnalyzer, AnalyzerError>`

**Error Handling**: 
- WalkDir errors mapped to AnalyzerError::WalkDir
- IO errors mapped to AnalyzerError::Io
- Parse errors logged but don't fail the analyzer

**Used By**: `orchestrator::audit_pipeline`

---

##### 2. `from_source(source: &str) -> Result<Self, AnalyzerError>`
**Purpose**: Create analyzer from source code string (for testing)

**Parameters**:
- `source`: Rust source code as string

**Logic Flow**:
1. Parses source with `syn::parse_file()`
2. Creates analyzer with single file named "source.rs"
3. Loads vulnerability database

**Return Value**: `Result<ProgramAnalyzer, AnalyzerError>`

**Used By**: Unit tests

---

##### 3. `extract_account_schemas(&self) -> Vec<AccountSchema>`
**Purpose**: Extract all `#[account]` structs from code

**Logic Flow**:
1. Iterates through all source files
2. For each file, iterates through items
3. Checks if item is a struct with `#[account]` attribute
4. Parses struct fields into HashMap
5. Returns vector of AccountSchema

**Return Value**: `Vec<AccountSchema>`

**Used By**: IDL generation, account validation analysis

---

##### 4. `extract_instruction_logic(&self, instruction_name: &str) -> Option<InstructionLogic>`
**Purpose**: Extract function body for specific instruction

**Parameters**:
- `instruction_name`: Name of function to extract

**Logic Flow**:
1. Searches all files for function with matching name
2. Parses function body into statements
3. Returns InstructionLogic with parsed statements

**Return Value**: `Option<InstructionLogic>`

**Used By**: Exploit generation, dataflow analysis

---

##### 5. `scan_for_vulnerabilities(&self) -> Vec<VulnerabilityFinding>`
**Purpose**: Main vulnerability scanning function (sequential)

**Logic Flow**:
1. Creates empty findings vector
2. For each source file:
   - Calls `scan_items()` on file's AST items
3. Returns all findings

**Return Value**: `Vec<VulnerabilityFinding>`

**Used By**: `audit_pipeline::EnterpriseAuditor`

---

##### 6. `scan_for_vulnerabilities_parallel(&self) -> Vec<VulnerabilityFinding>`
**Purpose**: Parallel vulnerability scanning (currently sequential due to closure limitations)

**Note**: VulnerabilityDatabase contains closures which aren't Send+Sync, so true parallelism isn't possible. Method kept for API compatibility.

**Logic Flow**: Delegates to `scan_for_vulnerabilities()`

**Return Value**: `Vec<VulnerabilityFinding>`

---

##### 7. `scan_items(&self, items: &[Item], filename: &str, findings: &mut Vec<VulnerabilityFinding>)` (private)
**Purpose**: Recursively scan AST items for vulnerabilities

**Parameters**:
- `items`: Slice of AST items to scan
- `filename`: Current file being scanned
- `findings`: Mutable vector to accumulate findings

**Logic Flow**:
1. For each item in items:
   - **If Item::Fn (function)**:
     - Converts function to code string using `quote!`
     - Gets line number from span
     - For each vulnerability pattern in database:
       - Calls pattern's checker function with code
       - If vulnerability found:
         - Fills in location, function_name, line_number
         - Adds to findings vector
   - **If Item::Mod (module)**:
     - Recursively scans module contents
   - **If Item::Struct (struct)**:
     - Converts struct to code string
     - Gets line number
     - For each vulnerability pattern:
       - Calls checker
       - Only adds if pattern is structural (3.x, 4.x) or authentication (1.x)
       - Fills in metadata and adds to findings

**Side Effects**: Mutates findings vector

**Why Structural Filter**: Prevents false positives from checking function-level patterns on structs

---

**Helper Methods**:

- `has_account_attribute(&self, attrs: &[syn::Attribute]) -> bool`: Checks if struct has `#[account]` attribute
- `parse_account_struct(&self, item_struct: &ItemStruct) -> AccountSchema`: Extracts fields from account struct
- `parse_function_logic(&self, func: &ItemFn) -> InstructionLogic`: Parses function into statements
- `extract_statements(&self, stmts: &[Stmt]) -> Vec<Statement>`: Converts syn::Stmt to Statement enum
- `parse_expression(&self, expr: &Expr) -> Option<Statement>`: Parses expressions (arithmetic, method calls)
- `is_checked_operation(&self, code: &str) -> bool`: Checks if arithmetic uses checked_* methods

**Data Structures**:

##### `AccountSchema`
```rust
pub struct AccountSchema {
    pub name: String,
    pub fields: HashMap<String, String>,  // field_name -> type
}
```

##### `InstructionLogic`
```rust
pub struct InstructionLogic {
    pub name: String,
    pub source_code: String,
    pub statements: Vec<Statement>,
}
```

##### `Statement` (enum)
```rust
pub enum Statement {
    Arithmetic { op: String, checked: bool },
    CheckedArithmetic,
    Assignment,
    CPI,
    Require,
}
```

##### `VulnerabilityFinding`
```rust
pub struct VulnerabilityFinding {
    pub category: String,              // e.g., "Authentication"
    pub vuln_type: String,             // e.g., "Missing Signer Check"
    pub severity: u8,                  // 1-5
    pub severity_label: String,        // "CRITICAL", "HIGH", etc.
    pub id: String,                    // e.g., "SOL-001"
    pub cwe: Option<String>,           // CWE identifier
    pub location: String,              // Filename
    pub function_name: String,         // Function where found
    pub line_number: usize,            // Line number
    pub vulnerable_code: String,       // Code snippet
    pub description: String,           // What the vulnerability is
    pub attack_scenario: String,       // How it can be exploited
    pub real_world_incident: Option<Incident>,  // Historical example
    pub secure_fix: String,            // How to fix it
    pub prevention: String,            // Best practices
}
```

##### `Incident`
```rust
pub struct Incident {
    pub project: String,   // e.g., "Wormhole"
    pub loss: String,      // e.g., "$320M"
    pub date: String,      // e.g., "2022-02-02"
}
```

##### `AnalyzerError` (enum)
```rust
pub enum AnalyzerError {
    Io(std::io::Error),
    Parse(syn::Error),
    WalkDir(walkdir::Error),
}
```

---

#### File: `vulnerability_db.rs` (1517 lines, 71KB)

**Purpose**: Database of 52 vulnerability patterns with checker functions

**Key Struct**: `VulnerabilityPattern`

**Fields**:
- `id: String` - Unique identifier (e.g., "SOL-001")
- `name: String` - Human-readable name
- `severity: u8` - Severity level (1-5)
- `description: String` - What it is
- `example: String` - Code example
- `mitigation: String` - How to fix
- `checker: fn(&str) -> Option<VulnerabilityFinding>` - Detection function

**Database Struct**: `VulnerabilityDatabase`

**Methods**:
- `load() -> Self`: Loads default 52 patterns
- `patterns(&self) -> &[VulnerabilityPattern]`: Returns pattern slice

**Function**: `get_default_patterns() -> Vec<VulnerabilityPattern>`

**Returns**: Vector of 52 vulnerability patterns

**Pattern Categories**:

1. **Authentication & Authorization (SOL-001 to SOL-003)**
   - Missing Signer Check
   - Missing Owner Check

2. **Arithmetic Safety (SOL-002)**
   - Integer Overflow/Underflow

3. **Account Validation (SOL-004, SOL-006, SOL-012, SOL-023)**
   - Type Cosplay
   - Duplicate Mutable Accounts
   - Account Data Mismatch
   - Token Account Confusion

4. **PDA Security (SOL-007, SOL-008, SOL-027)**
   - Bump Seed Issues
   - PDA Sharing
   - Missing Seeds Validation

5. **CPI Security (SOL-005, SOL-015, SOL-026)**
   - Arbitrary CPI
   - Missing Program ID Check
   - CPI Depth Issues

6. **Account Management (SOL-009, SOL-013, SOL-025, SOL-028, SOL-029)**
   - Account Closing Issues
   - Missing Rent Exemption
   - Lamport Balance Drain
   - Account Resurrection
   - Missing Close Authority

7. **Initialization (SOL-011)**
   - Reinitialization Vulnerability

8. **Sysvar Security (SOL-010)**
   - Sysvar Address Issues

9. **Data Validation (SOL-014)**
   - Unsafe Deserialization

10. **Error Handling (SOL-016)**
    - Unchecked Return Value

11. **Reentrancy (SOL-017)**
    - Cross-Program Reentrancy

12. **DeFi Security (SOL-018, SOL-033-SOL-035, SOL-049-SOL-050)**
    - Flash Loan Attack
    - Slippage Attack
    - Sandwich Attack
    - Front-Running
    - LP Token Manipulation
    - Reward Calculation Error

13. **Oracle Security (SOL-019, SOL-020)**
    - Oracle Manipulation
    - Stale Oracle Data

14. **Token Security (SOL-021-SOL-024, SOL-031)**
    - Mint Authority Issues
    - Freeze Authority Issues
    - Token Account Confusion
    - Missing Token Validation
    - Unauthorized Token Mint

15. **Arithmetic (SOL-032, SOL-036-SOL-040, SOL-045)**
    - Missing Decimals Check
    - Missing Amount Validation
    - Division Before Multiplication
    - Precision Loss
    - Rounding Errors
    - Missing Zero Check
    - Unsafe Math Operations

16. **Access Control (SOL-030, SOL-041, SOL-047-SOL-048)**
    - Privilege Escalation
    - Unrestricted Transfer
    - Missing Access Control
    - Account Hijacking

17. **Operational Security (SOL-042-SOL-044, SOL-046, SOL-051)**
    - Missing Pause Mechanism
    - Hardcoded Address
    - Missing Event Emission
    - Time Manipulation
    - Missing Deadline Check

18. **Governance (SOL-052)**
    - Governance Attack

**Checker Function Pattern** (example):

```rust
fn check_missing_signer(code: &str) -> Option<VulnerabilityFinding> {
    // Pattern detection logic
    let has_account_info = code.contains("AccountInfo<");
    let has_signer = code.contains("Signer<") || 
                     code.contains("#[account(signer)]") ||
                     code.contains("is_signer");
    
    let authority_pattern = code.contains("authority") || 
                           code.contains("admin") || 
                           code.contains("owner");
    
    // Vulnerability condition
    if has_account_info && !has_signer && authority_pattern {
        return Some(VulnerabilityFinding {
            category: "Authentication".to_string(),
            vuln_type: "Missing Signer Check".to_string(),
            severity: 5,
            severity_label: "CRITICAL".to_string(),
            id: "SOL-001".to_string(),
            cwe: Some("CWE-287".to_string()),
            // ... metadata filled by caller
            description: "Authority account is not validated as a signer...".to_string(),
            attack_scenario: "Attacker passes their own account as authority...".to_string(),
            real_world_incident: Some(Incident { 
                project: "Wormhole".to_string(), 
                loss: "$320M".to_string(), 
                date: "2022-02-02".to_string() 
            }),
            secure_fix: "Add Signer<'info> constraint...".to_string(),
            prevention: "Always use Signer<'info> for authority accounts".to_string(),
        });
    }
    
    None
}
```

**All 52 Checker Functions** (lines 104-1517):
Each follows similar pattern:
1. Pattern detection (string matching, AST analysis)
2. Condition evaluation
3. Return VulnerabilityFinding if vulnerable, None otherwise

**Real-World Incidents Referenced**:
- Wormhole ($320M, 2022-02-02)
- Cashio ($52M, 2022-03-23)
- Mango Markets ($114M, 2022-10-11)
- Various DeFi protocols ($100M+, 2021-2023)
- Flash loan attacks ($200M+, 2020-2023)

---

*End of Part 2*

**Next**: Part 3 will cover the orchestrator, AI components, formal verification tools, and fuzzing engines.
