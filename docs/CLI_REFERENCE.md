# Solana Security Swarm - CLI Reference

> **Enterprise-Grade Autonomous Solana Security Auditor**

This document provides a comprehensive reference for all available command-line flags and options.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Available Commands](#available-commands)
- [Flag Reference](#flag-reference)
- [Environment Variables](#environment-variables)
- [Usage Examples](#usage-examples)
- [Output Formats](#output-formats)

---

## Quick Start

```bash
# Basic scan of a GitHub repository
solana-security-swarm --repo https://github.com/example/solana-program --api-key YOUR_KEY

# Run against built-in test programs (no external target needed)
solana-security-swarm --test-mode --api-key YOUR_KEY --dry-run

# Continuous mainnet monitoring
solana-security-swarm --watcher --api-key YOUR_KEY
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/solana-security-swarm
cd solana-security-swarm

# Build the project
cargo build --release

# The binary will be at: ./target/release/solana-security-swarm
```

---

## Available Commands

| Binary | Description |
|--------|-------------|
| `solana-security-swarm` | Main security auditor CLI |
| `test_sealevel` | Test runner for sealevel-attacks benchmark |

---

## Flag Reference

### Input Options

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--repo` | `-r` | `STRING` | No | Target program repository URL (GitHub) |
| `--idl` | `-i` | `PATH` | No | Path to Anchor IDL JSON file |
| `--test-mode` | - | `FLAG` | No | Run against built-in vulnerable test programs |
| `--watcher` | - | `FLAG` | No | Run as continuous mainnet watcher |

### API & Authentication

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--api-key` | - | `STRING` | **Yes** | - | OpenRouter API key for LLM features |
| `--hackathon-api-key` | - | `STRING` | No | - | Hackathon platform API key |
| `--model` | - | `STRING` | No | `anthropic/claude-3.5-sonnet` | LLM model ID to use |

### Network Configuration

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--rpc-url` | - | `STRING` | No | `https://api.devnet.solana.com` | Solana RPC endpoint URL |

### Output Options

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--output-dir` | `-o` | `PATH` | No | `audit_reports` | Directory for saving reports |
| `--post-to-forum` | - | `FLAG` | No | `false` | Submit results to hackathon forum |
| `--auto-submit` | - | `FLAG` | No | `false` | Auto-submit project when analysis completes |

### Analysis Features

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--prove` | - | `FLAG` | No | `false` | Enable automated exploit execution/proving |
| `--register` | - | `FLAG` | No | `false` | Register verified exploits on-chain |
| `--consensus` | - | `FLAG` | No | `false` | Enable multi-LLM consensus verification |
| `--wacana` | - | `FLAG` | No | `true` | Enable WACANA concolic analysis (default: true) |
| `--dry-run` | - | `FLAG` | No | `false` | Simulation mode - no real transactions |

---

## Environment Variables

All flags with `env` support can be set via environment variables:

| Variable | Corresponding Flag | Description |
|----------|-------------------|-------------|
| `OPENROUTER_API_KEY` | `--api-key` | OpenRouter API key |
| `SOLANA_RPC_URL` | `--rpc-url` | Solana RPC endpoint |
| `LLM_MODEL` | `--model` | LLM model identifier |
| `HACKATHON_API_KEY` | `--hackathon-api-key` | Hackathon platform key |

### Setting Environment Variables

```bash
# Option 1: Export in shell
export OPENROUTER_API_KEY="sk-or-v1-xxxxx"
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"

# Option 2: .env file (create in project root)
echo 'OPENROUTER_API_KEY=sk-or-v1-xxxxx' >> .env
echo 'SOLANA_RPC_URL=https://api.mainnet-beta.solana.com' >> .env

# Option 3: Inline with command
OPENROUTER_API_KEY="your-key" solana-security-swarm --test-mode
```

---

## Usage Examples

### 1. Basic Repository Scan

Scan a public GitHub repository for vulnerabilities:

```bash
solana-security-swarm \
  --repo https://github.com/coral-xyz/sealevel-attacks \
  --api-key $OPENROUTER_API_KEY \
  --output-dir ./my_audit
```

### 2. Test Mode (Built-in Vulnerable Programs)

Run against the included vulnerable test programs:

```bash
solana-security-swarm \
  --test-mode \
  --api-key $OPENROUTER_API_KEY \
  --dry-run
```

### 3. Analyze with IDL File

Provide an Anchor IDL for more accurate analysis:

```bash
solana-security-swarm \
  --repo https://github.com/raydium-io/raydium-amm \
  --idl ./target/idl/raydium_amm.json \
  --api-key $OPENROUTER_API_KEY
```

### 4. Continuous Mainnet Watcher

Monitor mainnet for new program deployments and auto-audit:

```bash
solana-security-swarm \
  --watcher \
  --rpc-url https://api.mainnet-beta.solana.com \
  --api-key $OPENROUTER_API_KEY \
  --output-dir ./mainnet_audits
```

### 5. Full Audit with Exploit Proving

Run comprehensive audit with automated exploit verification:

```bash
solana-security-swarm \
  --repo https://github.com/target/vulnerable-program \
  --api-key $OPENROUTER_API_KEY \
  --prove \
  --rpc-url https://api.devnet.solana.com
```

### 6. Multi-LLM Consensus Mode

Use multiple AI models to verify findings (reduces false positives):

```bash
solana-security-swarm \
  --repo https://github.com/target/program \
  --api-key $OPENROUTER_API_KEY \
  --consensus \
  --dry-run
```

### 7. Post Results to Hackathon Forum

Automatically submit findings to the hackathon platform:

```bash
solana-security-swarm \
  --test-mode \
  --api-key $OPENROUTER_API_KEY \
  --hackathon-api-key $HACKATHON_API_KEY \
  --post-to-forum \
  --auto-submit
```

### 8. Dry Run (No Transactions)

Test the full pipeline without executing any on-chain transactions:

```bash
solana-security-swarm \
  --repo https://github.com/target/program \
  --api-key $OPENROUTER_API_KEY \
  --prove \
  --register \
  --dry-run
```

### 9. Custom LLM Model

Use a different LLM model for analysis:

```bash
solana-security-swarm \
  --test-mode \
  --api-key $OPENROUTER_API_KEY \
  --model "google/gemini-pro" \
  --dry-run
```

### 10. Using test_sealevel Binary

Run the vulnerability benchmark test suite:

```bash
# Compile and run
cargo run --bin test_sealevel

# Output includes analysis of:
# - sealevel-attacks (11 intentionally vulnerable programs)
# - raydium-amm (production code)
```

---

## Output Formats

The tool generates reports in multiple formats:

| Format | File | Description |
|--------|------|-------------|
| JSON | `*_report.json` | Machine-readable structured data |
| Markdown | `*_report.md` | Human-readable report |
| HTML | `*_report.html` | Styled web report |

### Sample Output Structure

```
audit_reports/
├── vulnerable_vault_report.json
├── vulnerable_vault_report.md
├── vulnerable_vault_report.html
├── raydium_amm_report.json
├── raydium_amm_report.md
└── raydium_amm_report.html
```

---

## Vulnerability Categories Detected

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| SOL-001 | Missing Signer Check | CRITICAL | Authority not validated as signer |
| SOL-002 | Integer Overflow | HIGH | Unchecked arithmetic operations |
| SOL-003 | Missing Owner Check | CRITICAL | Account owner not validated |
| SOL-004 | Type Cosplay | CRITICAL | Account type confusion |
| SOL-005 | Arbitrary CPI | CRITICAL | Unvalidated CPI target program |
| SOL-006 | Duplicate Accounts | HIGH | Same account passed multiple times |
| SOL-007 | Bump Seed Issues | HIGH | Non-canonical PDA bump |
| SOL-008 | PDA Sharing | HIGH | Shared PDA across users |
| SOL-009 | Account Closing | HIGH | Revival attack on closed accounts |
| SOL-010 | Sysvar Issues | MEDIUM | Fake sysvar injection |
| SOL-011 | Reinitialization | HIGH | Account can be reinitialized |
| SOL-012 | Data Mismatch | HIGH | Account relationship not validated |
| WACANA-001 | Memory Safety | CRITICAL | Bytecode out-of-bounds access |
| WACANA-002 | Type Confusion | CRITICAL | Indirect call to invalid type |
| WACANA-003 | Reentrancy | HIGH | State write after external call |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - analysis completed |
| `1` | Error - analysis failed |
| `2` | Configuration error |

---

## Troubleshooting

### Common Issues

**1. "API key required"**
```bash
# Solution: Set the API key
export OPENROUTER_API_KEY="your-key-here"
```

**2. "Parse error" on source files**
```bash
# Solution: Ensure the target has valid Rust syntax
# Some Anchor macros may not parse without dependencies
```

**3. "RPC connection failed"**
```bash
# Solution: Check RPC URL and network connectivity
solana-security-swarm --rpc-url https://api.devnet.solana.com ...
```

---

## See Also

- [CONTRIBUTING.md](../CONTRIBUTING.md) - How to contribute
- [SECURITY.md](../SECURITY.md) - Security policy
- [README.md](../README.md) - Project overview

---

*Generated: 2026-02-09 | Solana Security Swarm v0.1.0*
