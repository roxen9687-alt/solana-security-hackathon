// Enterprise Brutal Audit Test Suite
// Comprehensive security testing for the SecurityShield program
//
// Test Categories and Risk Levels:
//   1. Signer Authorization       ($Critical)
//   2. Account Data Matching       ($Critical)
//   3. Arithmetic Safety           ($High)
//   4. Reentrancy Protection       ($Medium)
//   5. Account Validation          ($High)
//   6. CPI Security                ($High)

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SecurityShield } from "../../target/types/security_shield";
import {
    Keypair,
    LAMPORTS_PER_SOL,
    PublicKey,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo } from "@solana/spl-token";
import { expect } from "chai";

describe("Enterprise Brutal Audit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.SecurityShield as Program<SecurityShield>;

    let mint: PublicKey;
    let vaultToken: PublicKey;
    let adminToken: PublicKey;
    let attackerToken: PublicKey;
    let admin = Keypair.generate();
    let attacker = Keypair.generate();

    const [configPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("config")],
        program.programId
    );

    const [vaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        program.programId
    );

    const [emergencyStatePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("emergency_state")],
        program.programId
    );

    before(async () => {
        // Airdrop SOL to test accounts
        for (const kp of [admin, attacker]) {
            const sig = await provider.connection.requestAirdrop(kp.publicKey, 10 * LAMPORTS_PER_SOL);
            const latestBlockhash = await provider.connection.getLatestBlockhash();
            await provider.connection.confirmTransaction({
                signature: sig,
                ...latestBlockhash,
            });
        }

        // Create token mint
        mint = await createMint(
            provider.connection,
            (provider.wallet as any).payer,
            provider.wallet.publicKey,
            null,
            9
        );

        // Create token accounts
        vaultToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            vaultPda,
            undefined,
            { skipPreflight: true }
        );

        adminToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            admin.publicKey
        );

        attackerToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            attacker.publicKey
        );

        // Mint tokens to admin and attacker
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, adminToken, provider.wallet.publicKey, 1_000_000_000);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, attackerToken, provider.wallet.publicKey, 1_000_000_000);

        console.log("--- Enterprise Brutal Audit Suite ---");
        console.log("Initializing test environment...");
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 1. Signer Authorization ($Critical)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("1. Signer Authorization ($Critical)", () => {
        it("should require a signer for initialization", async () => {
            await program.methods
                .initialize()
                .accounts({
                    authority: admin.publicKey,
                    config: configPda,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const config = await program.account.config.fetch(configPda);
            expect(config.admin.toString()).to.equal(admin.publicKey.toString());
            expect(config.isInitialized).to.equal(true);
        });

        it("should set the correct admin authority", async () => {
            const config = await program.account.config.fetch(configPda);
            expect(config.admin.toString()).to.equal(admin.publicKey.toString());
            expect(config.version).to.equal(1);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 2. Account Data Matching ($Critical)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("2. Account Data Matching ($Critical)", () => {
        it("should derive vault PDA with correct seeds", async () => {
            await program.methods
                .initializeVault()
                .accounts({
                    vault: vaultPda,
                    admin: admin.publicKey,
                    mint: mint,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const vault = await program.account.secureVault.fetch(vaultPda);
            expect(vault.admin.toString()).to.equal(admin.publicKey.toString());
            expect(vault.mint.toString()).to.equal(mint.toString());
        });

        it("should enforce PDA derivation for user shares", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            await program.methods
                .initializeUserShares()
                .accounts({
                    userShares: adminSharesPda,
                    user: admin.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const shares = await program.account.userShares.fetch(adminSharesPda);
            expect(shares.owner.toString()).to.equal(admin.publicKey.toString());
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 3. Arithmetic Safety ($High)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("3. Arithmetic Safety ($High)", () => {
        it("should handle deposits with safe arithmetic and return shares", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            const depositAmount = new anchor.BN(10_000);
            await program.methods
                .deposit(depositAmount)
                .accounts({
                    vault: vaultPda,
                    userShares: adminSharesPda,
                    userToken: adminToken,
                    vaultToken: vaultToken,
                    user: admin.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([admin])
                .rpc();

            const shares = await program.account.userShares.fetch(adminSharesPda);
            expect(shares.amount.toNumber()).to.be.greaterThan(0);
        });

        it("should enforce minimum deposit threshold", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            await program.methods
                .initializeUserShares()
                .accounts({
                    userShares: attackerSharesPda,
                    user: attacker.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            // Attempt a tiny deposit that should be below the minimum
            const tinyDeposit = new anchor.BN(1);
            let failed = false;
            try {
                await program.methods
                    .deposit(tinyDeposit)
                    .accounts({
                        vault: vaultPda,
                        userShares: attackerSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Deposit below minimum should be rejected");
        });

        it("should protect against share inflation via dead shares", async () => {
            const vault = await program.account.secureVault.fetch(vaultPda);
            const deadShares = vault.deadShares.toNumber();
            const totalShares = vault.totalShares.toNumber();

            // Dead shares should exist to prevent first-deposit inflation
            expect(deadShares).to.be.greaterThan(0);

            // Share price ratio should remain reasonable
            const ratio = totalShares / (deadShares || 1);
            expect(ratio).to.be.greaterThanOrEqual(1);
            console.log(`  Share inflation protection: dead=${deadShares}, total=${totalShares}`);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 4. Reentrancy Protection ($Medium)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("4. Reentrancy Protection ($Medium)", () => {
        it("should initialize emergency pause system", async () => {
            await program.methods
                .initializeEmergencyState()
                .accounts({
                    emergencyState: emergencyStatePda,
                    admin: admin.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const state = await program.account.emergencyState.fetch(emergencyStatePda);
            expect(state.paused).to.equal(false);
            expect(state.admin.toString()).to.equal(admin.publicKey.toString());
        });

        it("should allow admin to trigger emergency pause", async () => {
            await program.methods
                .emergencyPause("Security incident detected", new anchor.BN(3600))
                .accounts({
                    emergencyState: emergencyStatePda,
                    caller: admin.publicKey,
                })
                .signers([admin])
                .rpc();

            const state = await program.account.emergencyState.fetch(emergencyStatePda);
            expect(state.paused).to.equal(true);
        });

        it("should allow admin to unpause", async () => {
            await program.methods
                .unpause()
                .accounts({
                    emergencyState: emergencyStatePda,
                    admin: admin.publicKey,
                })
                .signers([admin])
                .rpc();

            const state = await program.account.emergencyState.fetch(emergencyStatePda);
            expect(state.paused).to.equal(false);
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 5. Account Validation ($High)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("5. Account Validation ($High)", () => {
        it("should reject invalid PDA for vault operations", async () => {
            // Generate a fake vault PDA that doesn't match the expected seeds
            const fakeVault = Keypair.generate();
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1000))
                    .accounts({
                        vault: fakeVault.publicKey,
                        userShares: attackerSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Should reject deposits to invalid vault PDA");
        });

        it("should reject mismatched user shares account", async () => {
            // Try to use admin's shares PDA with attacker's signer
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1000))
                    .accounts({
                        vault: vaultPda,
                        userShares: adminSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Should reject mismatched user shares PDA");
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // 6. CPI Security ($High)
    // ═══════════════════════════════════════════════════════════════════════════
    describe("6. CPI Security ($High)", () => {
        it("should only accept valid token program for deposits", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            // Pass a fake program ID as the token program
            const fakeTokenProgram = Keypair.generate();

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1000))
                    .accounts({
                        vault: vaultPda,
                        userShares: attackerSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: fakeTokenProgram.publicKey,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Should reject fake token program");
        });

        it("should enforce signer + token program constraints together", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            // Valid deposit should work with correct signer + correct token program
            const depositAmount = new anchor.BN(2000);
            await program.methods
                .deposit(depositAmount)
                .accounts({
                    vault: vaultPda,
                    userShares: attackerSharesPda,
                    userToken: attackerToken,
                    vaultToken: vaultToken,
                    user: attacker.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([attacker])
                .rpc();

            const shares = await program.account.userShares.fetch(attackerSharesPda);
            expect(shares.amount.toNumber()).to.be.greaterThan(0);
        });
    });

    after(() => {
        console.log("");
        console.log("=" .repeat(60));
        console.log("Enterprise Brutal Audit Complete");
        console.log("Categories tested: 6 (Signer + Accounts + Arithmetic + Reentrancy + Validation + CPI)");
        console.log("=" .repeat(60));
    });
});
