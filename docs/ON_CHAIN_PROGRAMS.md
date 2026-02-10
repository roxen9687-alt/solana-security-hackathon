# Solana Security Swarm - On-Chain Programs Documentation

> **Total Programs:** 5 Anchor Programs  
> **Framework:** Anchor 0.30.1  
> **Network:** Solana (devnet/mainnet)

---

## Programs Overview

| Program | Purpose | Status | Lines |
|---------|---------|--------|-------|
| `exploit-registry` | Store exploit findings on-chain | ✅ Ready | ~400 |
| `security_shield` | Runtime security features | ⚠️ Large scope | ~2,900 |
| `vulnerable-vault` | **Test program** - intentionally vulnerable | ✅ Test only | ~200 |
| `vulnerable-token` | **Test program** - intentionally vulnerable | ✅ Test only | ~350 |
| `vulnerable-staking` | **Test program** - intentionally vulnerable | ✅ Test only | ~150 |

---

## 1. Exploit Registry Program

**Path:** `programs/exploit-registry/`  
**Program ID:** Configurable in `Anchor.toml`

### Purpose

Provides immutable on-chain storage for:
- Verified exploit submissions
- Audit records
- Validator registrations

### Instructions

#### `initialize`

Initialize the global registry state.

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()>
```

**Accounts:**
- `authority` - Registry owner (signer)
- `registry_state` - PDA for global state (init)
- `system_program` - System program

---

#### `submit_exploit`

Submit a new exploit finding.

```rust
pub fn submit_exploit(
    ctx: Context<SubmitExploit>,
    program_id: Pubkey,
    vulnerability_type: String,
    severity: u8,
    proof_hash: String,
) -> Result<()>
```

**Accounts:**
- `finder` - Exploit discoverer (signer)
- `exploit_record` - PDA for this exploit (init)
- `target_program` - Program being reported
- `system_program` - System program

**PDA Seeds:** `["exploit", target_program, proof_hash]`

---

#### `validate_exploit`

Validator confirms exploit validity.

```rust
pub fn validate_exploit(
    ctx: Context<ValidateExploit>,
    validation_status: ValidationStatus,
) -> Result<()>
```

**Accounts:**
- `validator` - Authorized validator (signer)
- `exploit_record` - Exploit being validated (mut)
- `validator_account` - Validator registration

**Validation Status:**
- `Confirmed` - Exploit verified
- `Rejected` - False positive
- `Pending` - Needs more review

---

#### `add_validator`

Admin adds new validator.

```rust
pub fn add_validator(
    ctx: Context<AddValidator>,
    stake_amount: u64,
) -> Result<()>
```

**Accounts:**
- `authority` - Registry owner (signer)
- `registry_state` - Global state
- `validator_account` - New validator PDA (init)
- `validator` - Validator pubkey

---

#### `withdraw_stake`

Validator withdraws their stake.

```rust
pub fn withdraw_stake(
    ctx: Context<WithdrawStake>,
) -> Result<()>
```

---

### Account Structures

```rust
#[account]
pub struct RegistryState {
    pub authority: Pubkey,
    pub total_exploits: u64,
    pub total_validators: u64,
    pub created_at: i64,
    pub bump: u8,
}

#[account]
pub struct ExploitRecord {
    pub id: u64,
    pub finder: Pubkey,
    pub target_program: Pubkey,
    pub vulnerability_type: String,
    pub severity: u8,
    pub proof_hash: String,
    pub status: ValidationStatus,
    pub validator: Option<Pubkey>,
    pub submitted_at: i64,
    pub validated_at: Option<i64>,
    pub bump: u8,
}

#[account]
pub struct ValidatorAccount {
    pub validator: Pubkey,
    pub stake_amount: u64,
    pub validations_count: u64,
    pub accuracy_score: u8,
    pub registered_at: i64,
    pub bump: u8,
}
```

---

## 2. Security Shield Program

**Path:** `programs/security_shield/`  
**Lines:** ~2,900

### Purpose

Provides runtime security features that other programs can use:
- Flash loan defense
- MEV protection
- Oracle security wrappers
- Emergency systems
- Compute guards

### Modules

| Module | Purpose |
|--------|---------|
| `flash_loan_defense` | Detect and prevent flash loan attacks |
| `mev_defense` | Anti-sandwich/frontrun protections |
| `oracle_security` | Secure oracle price reading |
| `secure_vault` | Protected token custody |
| `emergency_systems` | Pause and recovery mechanisms |
| `compute_guards` | Compute unit management |
| `rent_guards` | Rent exemption validation |
| `token_extensions` | Token-2022 support |

### Key Features

#### Flash Loan Defense

```rust
pub fn check_flash_loan_guard(ctx: Context<CheckFlashLoan>) -> Result<bool>;
pub fn set_flash_loan_lock(ctx: Context<SetLock>, locked: bool) -> Result<()>;
```

#### MEV Defense

```rust
pub fn validate_slippage(
    ctx: Context<ValidateSlippage>,
    expected_amount: u64,
    actual_amount: u64,
    max_slippage_bps: u16,
) -> Result<()>;
```

#### Emergency Pause

```rust
pub fn emergency_pause(ctx: Context<EmergencyPause>) -> Result<()>;
pub fn emergency_resume(ctx: Context<EmergencyResume>) -> Result<()>;
pub fn is_paused(ctx: Context<IsPaused>) -> Result<bool>;
```

### Note

This program has a large scope and could benefit from being split into separate, focused programs. Testing on devnet is recommended before mainnet deployment.

---

## 3. Vulnerable Vault (Test Program)

**Path:** `programs/vulnerable-vault/`  
**Purpose:** Intentionally vulnerable for testing

### Vulnerabilities Present

| ID | Type | Location |
|----|------|----------|
| SOL-001 | Missing Signer Check | `withdraw()` |
| SOL-002 | Integer Overflow | `deposit()` |
| SOL-007 | PDA Bump Issues | Account derivation |
| SOL-017 | Reentrancy | State after CPI |

### Instructions

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()>;
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()>;
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()>;
pub fn transfer_authority(ctx: Context<TransferAuthority>, new_authority: Pubkey) -> Result<()>;
```

### Intentional Bugs

```rust
// Missing signer check - INTENTIONAL BUG
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // No check that authority == signer
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;  // Also potential underflow
    // Transfer to user...
    Ok(())
}

// Integer overflow - INTENTIONAL BUG
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance + amount;  // No checked_add
    Ok(())
}
```

---

## 4. Vulnerable Token (Test Program)

**Path:** `programs/vulnerable-token/`  
**Purpose:** Intentionally vulnerable for testing

### Vulnerabilities Present

| ID | Type | Location |
|----|------|----------|
| SOL-021 | Unprotected Mint | `mint_tokens()` |
| SOL-023 | Token Account Confusion | Missing mint validation |
| SOL-019 | Oracle Manipulation | Spot price usage |
| SOL-024 | Missing Token Validation | No token checks |

### Instructions

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()>;
pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()>;
pub fn burn_tokens(ctx: Context<BurnTokens>, amount: u64) -> Result<()>;
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()>;
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()>;
```

### Intentional Bugs

```rust
// Missing mint authority check - INTENTIONAL BUG
pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    // Anyone can call this!
    let mint = &ctx.accounts.mint;
    token::mint_to(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: mint.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
        ),
        amount,
    )?;
    Ok(())
}
```

---

## 5. Vulnerable Staking (Test Program)

**Path:** `programs/vulnerable-staking/`  
**Purpose:** Intentionally vulnerable for testing

### Vulnerabilities Present

| ID | Type | Location |
|----|------|----------|
| SOL-017 | Reentrancy | `claim_rewards()` |
| SOL-002 | Underflow | `unstake()` |
| SOL-050 | Reward Calculation Error | `calculate_rewards()` |

### Instructions

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()>;
pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()>;
pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()>;
pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()>;
```

### Intentional Bugs

```rust
// Reentrancy vulnerability - INTENTIONAL BUG
pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
    let rewards = calculate_rewards(&ctx.accounts.stake_account)?;
    
    // CPI to transfer rewards
    token::transfer(..., rewards)?;
    
    // State update AFTER CPI - reentrancy!
    ctx.accounts.stake_account.last_claim = Clock::get()?.unix_timestamp;
    Ok(())
}

// Underflow vulnerability - INTENTIONAL BUG
pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
    let stake = &mut ctx.accounts.stake_account;
    stake.amount = stake.amount - amount;  // No checked_sub
    Ok(())
}
```

---

## Building Programs

```bash
# Build all programs
anchor build

# Build specific program
anchor build -p exploit-registry

# Generate IDL
anchor idl parse --file programs/exploit-registry/src/lib.rs

# Deploy to devnet
anchor deploy --provider.cluster devnet

# Run tests
anchor test
```

---

## Program Deployment Checklist

### Before Mainnet

- [ ] Full security audit completed
- [ ] All intentional bugs in test programs NOT deployed
- [ ] Upgrade authority properly configured
- [ ] Multi-sig for admin functions
- [ ] Emergency pause tested
- [ ] Rate limiting configured
- [ ] Monitoring set up

### Test Programs Warning

⚠️ **DO NOT DEPLOY** `vulnerable-vault`, `vulnerable-token`, or `vulnerable-staking` to mainnet. These contain intentional security vulnerabilities for testing purposes only.

---

## TypeScript Tests

Located in: `tests/`

```typescript
// tests/exploit_registry.ts
describe("exploit-registry", () => {
  it("Initializes registry", async () => {});
  it("Submits exploit", async () => {});
  it("Validates exploit", async () => {});
});

// tests/vault_security.ts
describe("vulnerable-vault security", () => {
  it("Detects missing signer", async () => {});
  it("Detects integer overflow", async () => {});
});
```

Run tests:
```bash
anchor test
```

---

*On-chain program documentation from actual source code - 2026-02-09*
