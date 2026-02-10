# ⛓️ PHASE 6: Test the On-Chain Registry

> **Objective:** Verify that vulnerability proofs can be registered on-chain via the exploit-registry Solana program on devnet.  
> **Status:** 🔄 **NOT YET TESTED**

---

## Command 9: Register a Proof On-Chain

```bash
cargo run -p orchestrator --bin solana-security-swarm -- \
  audit \
  --repo /home/elliot/Music/hackathon/programs/vulnerable-vault \
  --prove \
  --register \
  --verbose 2>&1 | grep "REGISTRY"
```

### Expected Output:
```
[REGISTRY] Submitting proof for SOL-019
[REGISTRY] Transaction: 5K7x9wH... (devnet)
[REGISTRY] Proof hash: 0xdeadbeef...
[REGISTRY] Discoverer: ElliotPubkey...
```

### Actual Output:
```
🔄 Not yet executed
```

---

## Verify on Solana Explorer

After the registry transaction succeeds, verify it:

```bash
# Extract the transaction signature from logs, then:
open "https://explorer.solana.com/tx/[SIGNATURE]?cluster=devnet"
```

### What to Check on Explorer:
- ✅ Transaction succeeded (green status)
- ✅ Program ID matches your `exploit-registry` program
- ✅ Instruction data contains vulnerability proof hash
- ✅ Discoverer field matches your wallet pubkey

---

## Registry Architecture

The on-chain registry stores vulnerability proofs as PDAs:

```
┌─────────────────────────────────────────┐
│          Exploit Registry PDA           │
├─────────────────────────────────────────┤
│  vulnerability_id: "SOL-019"           │
│  proof_hash: 0x...                      │
│  discoverer: <Pubkey>                   │
│  timestamp: <unix_ts>                   │
│  target_program: <Pubkey>               │
│  severity: CRITICAL                     │
│  value_at_risk: 900000                  │
│  proof_status: PROVEN_VIA_Z3            │
└─────────────────────────────────────────┘
```

### PDA Seeds:
```rust
seeds = [
    b"exploit_proof",
    vulnerability_id.as_bytes(),
    target_program.as_ref(),
]
```

---

## Prerequisites

Before running the registry:

### 1. Solana CLI Configured
```bash
solana config get
# Should show:
# RPC URL: https://api.devnet.solana.com
# Keypair Path: /home/elliot/.config/solana/id.json
```

### 2. Devnet SOL for Transaction Fees
```bash
solana airdrop 2 --url devnet
solana balance --url devnet
# Should show >= 0.1 SOL
```

### 3. Exploit Registry Program Deployed
```bash
# Check if the registry program is deployed on devnet
solana program show <REGISTRY_PROGRAM_ID> --url devnet
```

---

## What the Registry Proves

| Without Registry | With Registry |
|-----------------|---------------|
| "We found a bug" (claim) | "We found a bug" (on-chain proof) |
| Timestamp is self-reported | Timestamp is blockchain-verified |
| Discoverer is unverified | Discoverer signed with their key |
| Proof can be disputed | Proof hash is immutable |
| No incentive alignment | Bug bounty payout verification |

### Use Cases:
1. **Bug Bounty Verification** — Prove you discovered a bug before anyone else
2. **Responsible Disclosure** — On-chain timestamp proves timeline
3. **Audit Trail** — Immutable record of all findings
4. **Incentive Alignment** — Discoverer gets credit (and potential reward)

---

## Verification Checklist

| # | Check | Status |
|---|-------|--------|
| 1 | `--register` flag accepted | 🔄 Not yet |
| 2 | Registry transaction submitted | 🔄 Not yet |
| 3 | Transaction succeeded on devnet | 🔄 Not yet |
| 4 | Proof hash matches Z3 output | 🔄 Not yet |
| 5 | Discoverer pubkey correct | 🔄 Not yet |
| 6 | Viewable on Solana Explorer | 🔄 Not yet |
| 7 | PDA derivation correct | 🔄 Not yet |

---

## Summary

The on-chain registry is the **final mile** of the exploit synthesis pipeline:

```
Static Analysis → Z3 Proving → PoC Generation → On-Chain Registration
                                                        ↑
                                                   YOU ARE HERE
```

This phase converts mathematical proofs into **verifiable on-chain records**, enabling trustless bug bounty verification and responsible disclosure.
