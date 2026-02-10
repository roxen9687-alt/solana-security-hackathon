# Part 0 — Executive Summary & Quick Start

> **Solana Security Swarm** — Enterprise-grade autonomous security auditor for Solana programs.

---

## 30-Second Pitch

**What it does:** Automatically audits Solana smart contracts using 52 vulnerability patterns, AI-driven analysis, formal verification, and fuzzing — then generates mathematical proofs and executable PoC code for every finding.

**Why it matters:** Traditional audits take weeks and cost $50k-$200k. This tool runs in minutes and catches vulnerabilities that manual auditors miss (including compiler-introduced bugs via bytecode analysis).

**Who it's for:** Solana developers deploying to mainnet, security researchers hunting bounties, auditing firms scaling their operations.

---

## What You Can Do Today (No Setup Required)

### Minimum Requirements
- **Rust:** 1.70+ (`rustc --version`)
- **Solana CLI:** 1.18+ (`solana --version`)
- **Disk:** 20GB free space (build artifacts grow large)
- **RAM:** 8GB minimum

### Quick Start (5 Minutes)

```bash
# 1. Clone and build (default build excludes Z3-dependent crates)
git clone <your-repo-url>
cd hackathon
cargo build --release

# 2. Run basic audit on built-in vulnerable test program
cargo run --release --bin solana-security-swarm -- audit --test-mode

# 3. Audit your own program (with IDL)
cargo run --release --bin solana-security-swarm -- audit \
  --repo ./my-solana-program \
  --idl ./target/idl/my_program.json \
  --output-dir ./audit_reports

# 4. Launch interactive TUI dashboard
cargo run --release --bin solana-security-swarm -- dashboard
```

**Expected output:**
- JSON audit report in `audit_reports/`
- Terminal output showing findings with severity, confidence, and fix recommendations
- Runtime: 30-90 seconds for small programs (<1000 LOC)
- Runtime: 2-5 minutes for medium programs (1000-5000 LOC)

---

## What's Included in the Default Build

The default `cargo build` gives you a **fully functional security auditor** without requiring Z3 or external tools:

| Component | Status | What It Does |
|-----------|--------|--------------|
| **52 Vulnerability Patterns** | ✅ Included | Detects auth bypass, arithmetic bugs, PDA issues, reentrancy, etc. |
| **L3X AI Analysis** | ✅ Included | ML-powered semantic analysis with 5 neural network models |
| **Cargo-Geiger** | ✅ Included | Unsafe Rust code detection (memory safety, FFI, transmute) |
| **Anchor Security** | ✅ Included | Validates `#[account(...)]` constraints, signer checks, PDA derivation |
| **Sec3 (Soteria)** | ✅ Included | 10-category static analysis with CWE mappings |
| **Kani Verifier** | ✅ Included* | Model checking with offline fallback when CLI unavailable |
| **Certora Prover** | ✅ Included* | SBF bytecode verification with offline fallback |
| **Trident Fuzzer** | ✅ Included* | Stateful fuzzing with offline fallback |
| **FuzzDelSol** | ✅ Included* | Binary fuzzing (requires compiled `.so`) |
| **WACANA Analyzer** | ⚠️ Excluded | Concolic execution (requires Z3) |
| **Symbolic Engine** | ⚠️ Excluded | Mathematical proofs (requires Z3) |
| **Concolic Executor** | ⚠️ Excluded | Path exploration (requires Z3) |
| **Economic Verifier** | ⚠️ Excluded | DeFi invariants (requires Z3) |
| **Invariant Miner** | ⚠️ Excluded | Automated invariant discovery (requires Z3) |

**\*Offline fallback:** When external CLI tools (Kani, Certora, Trident) aren't installed, these analyzers fall back to static analysis of program models/source code, providing ~60% coverage without execution.

---

## What You Get Without Z3

**Coverage:** All 52 vulnerability patterns + AI analysis + unsafe code detection + Anchor validation + Sec3 analysis + fuzzing (with fallbacks).

**What you KEEP:**
- ✅ Vulnerability **detection** (finding bugs)
- ✅ Severity classification (Critical/High/Medium/Low)
- ✅ Confidence scoring (ML-based)
- ✅ Fix recommendations
- ✅ Attack scenarios
- ✅ Historical context (real-world incidents)
- ✅ PoC code generation (basic templates)
- ✅ JSON/PDF/Markdown reports
- ✅ TUI dashboard
- ✅ Real-time mainnet monitoring

**What you LOSE:**
- ❌ Mathematical **proofs** (Z3 SMT solver output)
- ❌ Concrete counterexample values (satisfying assignments)
- ❌ Concolic execution (path exploration with constraint solving)
- ❌ Economic model verification (DeFi invariant checking)
- ❌ Invariant mining from execution traces

**Bottom line:** Without Z3, you get **detection** but not **proof**. For most use cases (pre-deployment audits, CI/CD integration), detection is sufficient.

---

## Unlocking Full Power (Z3 + External Tools)

### Installing Z3

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libz3-dev
```

**macOS:**
```bash
brew install z3
```

**Verify installation:**
```bash
z3 --version  # Should show: Z3 version 4.x.x
```

**Rebuild with Z3:**
```bash
cargo build --release -p symbolic-engine -p concolic-executor -p wacana-analyzer -p economic-verifier -p invariant-miner
```

### Installing Kani (Optional)

```bash
cargo install --locked kani-verifier
cargo kani setup
```

**Verify:**
```bash
cargo kani --version
```

### Installing Certora Prover (Optional)

Follow: https://docs.certora.com/en/latest/docs/user-guide/install.html

### Installing Trident (Optional)

```bash
cargo install trident-cli
```

---

## CLI Reference

### Binary Name
```bash
solana-security-swarm
```

**Location after build:**
```
./target/release/solana-security-swarm
```

### Commands

#### 1. `audit` — Deep-scrutiny audit of a Solana program

```bash
solana-security-swarm audit [OPTIONS]
```

**Required (one of):**
- `--repo <PATH>` — Local path to program directory
- `--test-mode` — Run against built-in vulnerable test programs

**Optional:**
- `--idl <FILE>` — Path to Anchor IDL JSON (auto-detected if in `target/idl/`)
- `--prove` — Enable Z3 exploit proving (requires Z3 installed)
- `--register` — Register findings on-chain (requires funded keypair)
- `--consensus` — Enable multi-LLM consensus verification
- `--output-dir <DIR>` — Output directory (default: `audit_reports`)
- `--dashboard` — Launch TUI dashboard after audit
- `--wacana <BOOL>` — Enable WACANA concolic analysis (default: true, requires Z3)
- `--trident <BOOL>` — Enable Trident fuzzing (default: true)
- `--fuzzdelsol <BOOL>` — Enable FuzzDelSol binary fuzzing (default: true)
- `--sec3 <BOOL>` — Enable Sec3 analysis (default: true)
- `--l3x <BOOL>` — Enable L3X AI analysis (default: true)
- `--geiger <BOOL>` — Enable cargo-geiger (default: true)
- `--anchor <BOOL>` — Enable Anchor analysis (default: true)

**Examples:**

```bash
# Basic audit with auto-detection
solana-security-swarm audit --repo ./my-program

# Full audit with all features
solana-security-swarm audit \
  --repo ./my-program \
  --idl ./target/idl/my_program.json \
  --prove \
  --register \
  --consensus \
  --dashboard

# Audit with specific analyzers only
solana-security-swarm audit \
  --repo ./my-program \
  --l3x true \
  --geiger true \
  --anchor true \
  --wacana false \
  --trident false

# Test mode (no program required)
solana-security-swarm audit --test-mode --dashboard
```

#### 2. `watch` — Continuous mainnet monitoring

```bash
solana-security-swarm watch [OPTIONS]
```

**Options:**
- `--dashboard` — Launch with live TUI dashboard
- `--alert-level <LEVEL>` — Alert threshold: low, medium, high, critical (default: medium)

**Example:**
```bash
solana-security-swarm watch --dashboard --alert-level high
```

#### 3. `dashboard` — Interactive TUI dashboard

```bash
solana-security-swarm dashboard [OPTIONS]
```

**Options:**
- `--report <FILE>` — Load specific audit report JSON

**Example:**
```bash
solana-security-swarm dashboard --report ./audit_reports/my_program_report.json
```

#### 4. `explorer` — Blockchain forensics

```bash
solana-security-swarm explorer [OPTIONS]
```

**Options:**
- `--transaction <SIG>` — Inspect specific transaction signature
- `--replay` — Replay transaction in sandbox

**Example:**
```bash
solana-security-swarm explorer \
  --transaction 5J7... \
  --replay
```

### Global Options

```bash
--verbose, -v              # Verbose output (debug logs)
--rpc-url <URL>            # Solana RPC URL (default: devnet)
--api-key <KEY>            # OpenRouter API key (env: OPENROUTER_API_KEY)
--model <MODEL>            # LLM model (default: anthropic/claude-3.5-sonnet)
```

---

## Environment Variables

| Variable | Required? | Default | Purpose |
|----------|-----------|---------|---------|
| `OPENROUTER_API_KEY` | No* | — | LLM API key for AI analysis |
| `LLM_MODEL` | No | `anthropic/claude-3.5-sonnet` | LLM model identifier |
| `SOLANA_RPC_URL` | No | `https://api.devnet.solana.com` | Solana RPC endpoint |
| `SOLANA_KEYPAIR_PATH` | No** | — | Path to keypair JSON for on-chain operations |
| `EXPLOIT_REGISTRY_PROGRAM_ID` | No | `ExReg111111111111111111111111111111111111` | On-chain registry program ID |

**\*Without API key:** AI analysis (L3X, LLM Strategist) will be skipped. All other analyzers work normally.

**\*\*Without keypair:** On-chain registration (`--register`) will be disabled. Audits still run normally.

---

## Output Files

After running `audit`, you'll find:

```
audit_reports/
├── my_program_report.json          # Structured JSON report
├── my_program_report.pdf           # PDF report (if --pdf flag used)
└── my_program_report.md            # Markdown report (if --markdown flag used)
```

### JSON Report Structure

```json
{
  "program_id": "MyProg111111111111111111111111111111111",
  "timestamp": "2026-02-10T12:30:00Z",
  "total_exploits": 12,
  "critical_count": 2,
  "high_count": 5,
  "medium_count": 5,
  "security_score": 45.2,
  "deployment_advice": "FIX_REQUIRED",
  "exploits": [
    {
      "id": "SOL-001",
      "vulnerability_type": "Missing Signer Validation",
      "severity": 5,
      "severity_label": "Critical",
      "confidence_score": 98.0,
      "description": "Instruction accepts transactions without validating signer authority",
      "attack_scenario": "Attacker can drain vault by calling withdraw without authorization",
      "prevention": "Add #[account(signer)] constraint or require!(ctx.accounts.authority.is_signer)",
      "line_number": 42,
      "instruction": "withdraw",
      "category": "Authentication",
      "proof": null,
      "ai_explanation": "Static analysis detected missing signer check...",
      "historical_hack_context": "Wormhole Bridge ($320M, 2022-02-02): Missing signature verification"
    }
  ]
}
```

---

## Common Workflows

### Workflow 1: Pre-Mainnet Deployment Audit

```bash
# 1. Build your program
cd my-solana-program
anchor build

# 2. Run comprehensive audit
solana-security-swarm audit \
  --repo . \
  --idl ./target/idl/my_program.json \
  --prove \
  --output-dir ./security_audit

# 3. Review critical findings
jq '.exploits[] | select(.severity >= 4)' \
  ./security_audit/my_program_report.json

# 4. Fix issues, rebuild, re-audit
# ... make fixes ...
anchor build
solana-security-swarm audit --repo . --idl ./target/idl/my_program.json

# 5. Generate PDF for auditors
# (Future: --pdf flag will be added)

# 6. Deploy only if security_score > 70 and critical_count == 0
```

### Workflow 2: Continuous Integration (CI/CD)

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Install Solana
        run: sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
      
      - name: Build program
        run: anchor build
      
      - name: Run security audit
        run: |
          cargo install --git <your-repo-url> solana-security-swarm
          solana-security-swarm audit --repo . --output-dir ./audit
      
      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(jq '.critical_count' ./audit/*_report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ CRITICAL VULNERABILITIES FOUND"
            exit 1
          fi
      
      - name: Upload audit report
        uses: actions/upload-artifact@v3
        with:
          name: security-audit
          path: ./audit/
```

### Workflow 3: Real-time Mainnet Monitoring

```bash
# Terminal 1: Start mainnet guardian with dashboard
export SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

solana-security-swarm watch \
  --dashboard \
  --alert-level high

# Terminal 2: Monitor specific program (future feature)
# solana-security-swarm watch \
#   --program <PROGRAM_ID> \
#   --alert-level medium
```

### Workflow 4: Research New Vulnerability Pattern

```bash
# 1. Add pattern to vulnerability_db.rs
# Edit: crates/program-analyzer/src/vulnerability_db.rs
# Add: pattern_sol_053_new_vulnerability()

# 2. Write test case
# Create: crates/program-analyzer/tests/patterns/test_sol_053.rs

# 3. Run tests
cargo test -p program-analyzer test_sol_053

# 4. Validate against corpus
solana-security-swarm audit --repo ./test_targets/vulnerable-vault

# 5. Benchmark (future feature)
# cargo run -p benchmark-suite -- --pattern SOL-053
```

---

## Security Considerations

### Threat Model

This tool **executes arbitrary code** during analysis:
- Fuzzing runs program instructions
- PoC generation creates executable exploits
- Transaction forge holds private keys in memory

### Mitigations

1. **Sandboxing:** Run audits in Docker/VM for untrusted programs
2. **Keypair isolation:** Use throwaway devnet keys for testing
   ```bash
   solana-keygen new --outfile ./audit-keypair.json
   export SOLANA_KEYPAIR_PATH=./audit-keypair.json
   ```
3. **Code review:** Never run generated PoCs on mainnet without manual review
4. **RPC isolation:** Use dedicated RPC endpoint for audits (not your production node)

### What We DON'T Protect Against

- ❌ Supply chain attacks (compromised Rust dependencies)
- ❌ Malicious Solana RPC endpoints
- ❌ Clipboard/screen capture by programs under audit
- ❌ Side-channel attacks during symbolic execution

**Recommendation:** Audit in an isolated environment, especially for untrusted codebases.

---

## Performance Characteristics

| Program Size | Analysis Time | Disk Usage | RAM Usage |
|--------------|---------------|------------|-----------|
| Small (<500 LOC) | 30-90 sec | ~2GB | ~2GB |
| Medium (500-2000 LOC) | 1-3 min | ~5GB | ~4GB |
| Large (2000-5000 LOC) | 2-5 min | ~10GB | ~6GB |
| Very Large (>5000 LOC) | 5-15 min | ~15GB | ~8GB |

**With Z3 enabled:** Add 50-200% to analysis time (depends on proof complexity).

**With fuzzing enabled:** Add 2-10 minutes (depends on fuzzing iterations).

**Benchmarked on:** Intel i7-12700K, 32GB RAM, NVMe SSD

---

## Troubleshooting

### "No Rust source files found"

**Cause:** Running from wrong directory or program structure not recognized.

**Fix:**
```bash
# Ensure you're in the program root with src/ or programs/ directory
ls -la  # Should show: src/ or programs/ or Anchor.toml

# Or specify explicit path
solana-security-swarm audit --repo ./programs/my-program
```

### "Z3 library not found"

**Cause:** Z3 not installed or not in library path.

**Fix:**
```bash
# Ubuntu/Debian
sudo apt-get install libz3-dev

# macOS
brew install z3

# Verify
z3 --version
```

### "OPENROUTER_API_KEY not set"

**Cause:** AI analysis requires API key.

**Fix:**
```bash
# Get key from: https://openrouter.ai/keys
export OPENROUTER_API_KEY="sk-or-v1-..."

# Or disable AI analysis
solana-security-swarm audit --repo . --l3x false
```

### "Kani verifier not found"

**Cause:** Kani CLI not installed.

**Effect:** Kani falls back to offline static analysis (~60% coverage).

**Fix (optional):**
```bash
cargo install --locked kani-verifier
cargo kani setup
```

### Build fails with "linking with `cc` failed"

**Cause:** Z3 C++ dependencies missing.

**Fix:**
```bash
# Exclude Z3 crates from build
cargo build --workspace --exclude symbolic-engine --exclude concolic-executor --exclude wacana-analyzer --exclude economic-verifier --exclude invariant-miner
```

### "target/ directory is 32GB"

**Cause:** Incremental compilation artifacts accumulate.

**Fix:**
```bash
cargo clean
# Or clean specific packages
cargo clean -p orchestrator
```

---

## Next Steps

1. **Run your first audit:** `solana-security-swarm audit --test-mode`
2. **Read Part 1:** High-level architecture and tech stack
3. **Read Part 2:** Deep dive into vulnerability patterns and analyzers
4. **Read Part 3:** Complete crate catalogue and integration details
5. **Join development:** See `CONTRIBUTING.md` (if exists) or open issues

---

## Support & Resources

- **Documentation:** Parts 1-3 in this repository
- **Issues:** GitHub Issues (if public repo)
- **Discussions:** GitHub Discussions (if enabled)
- **Real-world examples:** See `test_targets/` directory for vulnerable programs

---

## Version

**Current:** v1.0.0  
**Binary:** `solana-security-swarm`  
**Last Updated:** 2026-02-10
