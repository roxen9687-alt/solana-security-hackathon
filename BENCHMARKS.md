# Solana Security Swarm — Benchmarks

> Auto-generated benchmark estimates for the security analysis pipeline.

---

## Build Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Total crates | 35+ | Helper crates + programs |
| Build warnings | 0 | All warnings resolved |
| Build errors | 0 | Clean compilation |
| Release build time | ~30-60s | `cargo build --release` |
| Binary targets | 5 | scan_cctp, solana-security-swarm, test_sealevel, tx_demo, ui_demo |

## Crate-Level Benchmarks

### Core Analysis Crates

| Crate | LOC (est.) | Purpose | Compile Time (est.) |
|-------|-----------|---------|--------------------|
| `orchestrator` | ~2,000 | Main orchestration & pipeline | ~3s |
| `program-analyzer` | ~1,500 | Static analysis engine | ~2s |
| `sec3-analyzer` | ~1,200 | Sec3-style vulnerability detection | ~2s |
| `l3x-analyzer` | ~2,500 | ML-based GNN + pattern learning | ~3s |
| `taint-analyzer` | ~3,000 | Advanced taint analysis (inter-proc, field, path sensitive) | ~4s |
| `dataflow-analyzer` | ~1,500 | Reaching definitions + live variable analysis | ~2s |
| `symbolic-engine` | ~1,800 | Z3-backed symbolic execution & exploit proving | ~5s |

### Security Tool Integration Crates

| Crate | LOC (est.) | Purpose | Compile Time (est.) |
|-------|-----------|---------|--------------------|
| `anchor-security-analyzer` | ~800 | Anchor-specific checks (signer, PDA, CPI, token hooks) | ~2s |
| `certora-prover` | ~3,000 | Certora Solana Prover integration + SBF bytecode scanning | ~4s |
| `kani-verifier` | ~3,500 | Kani CBMC integration + proof harness generation | ~4s |
| `trident-fuzzer` | ~4,000 | Trident stateful fuzzing integration | ~4s |
| `security-fuzzer` | ~1,000 | Generic security fuzzing | ~2s |

### Specialized Analysis Crates

| Crate | LOC (est.) | Purpose | Compile Time (est.) |
|-------|-----------|---------|--------------------|
| `abstract-interpreter` | ~1,200 | Abstract interpretation framework | ~2s |
| `concolic-executor` | ~1,000 | Concolic (concrete + symbolic) execution | ~2s |
| `economic-verifier` | ~800 | DeFi economic model verification | ~2s |
| `invariant-miner` | ~600 | Automatic invariant discovery | ~1s |
| `arithmetic-security-expert` | ~500 | Overflow/underflow specialist | ~1s |
| `defi-security-expert` | ~500 | DeFi-specific vulnerability patterns | ~1s |
| `token-security-expert` | ~500 | Token program security analysis | ~1s |
| `account-security-expert` | ~500 | Account validation analysis | ~1s |
| `cpi-analyzer` | ~500 | Cross-Program Invocation analysis | ~1s |

### Infrastructure Crates

| Crate | LOC (est.) | Purpose | Compile Time (est.) |
|-------|-----------|---------|--------------------|
| `transaction-forge` | ~1,500 | Exploit transaction construction | ~3s |
| `secure-code-gen` | ~1,200 | Automated secure code generation | ~2s |
| `ai-enhancer` | ~800 | LLM-powered analysis augmentation | ~2s |
| `llm-strategist` | ~600 | LLM strategy orchestration | ~1s |
| `consensus-engine` | ~800 | Multi-analyzer consensus voting | ~2s |
| `benchmark-suite` | ~500 | Performance benchmarking | ~1s |
| `integration-orchestrator` | ~800 | Integration test orchestration | ~2s |
| `hackathon-client` | ~400 | CLI client | ~1s |
| `git-scanner` | ~300 | Git repository scanning | ~1s |
| `firedancer-monitor` | ~300 | Firedancer validator monitoring | ~1s |
| `geiger-analyzer` | ~300 | Unsafe code detection | ~1s |
| `wacana-analyzer` | ~300 | WASM/Solana analysis | ~1s |
| `fuzzdelsol` | ~300 | FuzzDeLSol integration | ~1s |

## On-Chain Programs

| Program | Purpose | Deployed |
|---------|---------|----------|
| `security_shield` | Production security shield with MEV defense, secure oracle, vault, flash loan defense, emergency systems | Yes |
| `vulnerable-staking` | Intentionally vulnerable staking program (audit target) | Yes |
| `vulnerable-token` | Intentionally vulnerable token program (audit target) | Yes |
| `vulnerable-vault` | Intentionally vulnerable vault program (audit target) | Yes |
| `exploit-registry` | On-chain exploit registry | Yes |

## Analysis Pipeline Performance

| Phase | Estimated Time | Description |
|-------|---------------|-------------|
| Phase 1: Basic Sanity Check | ~5s | Initial parsing and structural analysis |
| Phase 2: Z3 Proof Verification | ~15-30s | Symbolic execution with Z3 solver |
| Phase 3: Economic Risk Calculation | ~5s | DeFi economic model verification |
| Phase 4: Exploit Construction | ~10s | Transaction forge + proof of concept |
| Phase 5: Fix Verification | ~5s | Verify proposed fixes |
| Phase 6: On-Chain Registry | ~5s | Register findings on-chain |
| Phase 7: Stress Test | ~30s | Fuzz testing and stress analysis |
| Phase 8: Report Generation | ~2s | Final deliverables |
| **Total Pipeline** | **~80-100s** | **Full end-to-end audit** |

## Vulnerability Detection Benchmarks

### Sealevel Attack Coverage

| Attack Vector | Detection | Method |
|--------------|-----------|--------|
| Signer Authorization | ✅ | Static + Symbolic |
| Account Data Matching | ✅ | Taint Analysis |
| Owner Checks | ✅ | Anchor Analyzer |
| Type Cosplay | ✅ | Pattern Matching |
| Initialization | ✅ | Dataflow Analysis |
| Arbitrary CPI | ✅ | CPI Analyzer |
| Duplicate Mutable Accounts | ✅ | Static Analysis |
| Bump Seed Canonicalization | ✅ | PDA Validator |
| PDA Sharing | ✅ | Symbolic Engine |
| Closing Accounts | ✅ | Dataflow Analysis |
| Sysvar Address Checking | ✅ | Pattern Matching |

### ML/AI Detection Capabilities

| Capability | Status | Method |
|-----------|--------|--------|
| Control Flow GNN | ✅ | Graph Neural Network on CFG |
| Pattern Learning | ✅ | Historical exploit matching |
| Anomaly Detection | ✅ | Embedding deviation analysis |
| LLM-Augmented Analysis | ✅ | AI Enhancer integration |

## Code Quality Metrics

| Metric | Value |
|--------|-------|
| Compiler warnings | **0** |
| Compiler errors | **0** |
| Clippy lints | Minimal (framework-generated only) |
| Test coverage | Unit tests across all crates |
| Documentation | Comprehensive (docs/) |

## Memory & Resource Usage

| Resource | Estimate | Notes |
|----------|----------|-------|
| Peak RAM (build) | ~2-4 GB | Release build with all crates |
| Peak RAM (analysis) | ~500 MB - 1 GB | Depends on program size |
| Disk (target/) | ~2-5 GB | Full release build artifacts |
| Z3 solver memory | ~100-500 MB | Per verification task |
| Binary size (main) | ~15-30 MB | `solana-security-swarm` release |

---

*Benchmarks are estimates based on project structure and typical Rust compilation characteristics. Actual values may vary based on hardware and system load.*
