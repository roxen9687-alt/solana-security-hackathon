// =============================================================================
// Vault Security Integration Tests
// =============================================================================
//
// PREREQUISITE: These tests require a running Solana validator.
// They are designed to run via Anchor's test framework:
//
//   anchor test
//
// Or with a local validator already running:
//
//   anchor test --skip-local-validator
//
// They will NOT work with standalone `ts-mocha` because they depend on:
//   1. A running solana-test-validator
//   2. Deployed program IDL (target/types/security_shield.ts)
//   3. Anchor workspace configuration (Anchor.toml)
//
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SecurityShield } from "../target/types/security_shield";
import { expect } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo } from "@solana/spl-token";

describe("vault-security", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.SecurityShield as Program<SecurityShield>;

    let mint: PublicKey;
    let vaultToken: PublicKey;
    let attackerToken: PublicKey;
    let victimToken: PublicKey;
    let attacker = Keypair.generate();
    let victim = Keypair.generate();

    const [vaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        program.programId
    );

    before(async () => {
        // Airdrop SOL
        for (const k of [attacker, victim]) {
            const sig = await provider.connection.requestAirdrop(k.publicKey, 10 * LAMPORTS_PER_SOL);
            const latestBlockhash = await provider.connection.getLatestBlockhash();
            await provider.connection.confirmTransaction({
                signature: sig,
                ...latestBlockhash
            });
        }

        // Create Mint - using provder wallet as authority for simplicity in setup
        mint = await createMint(
            provider.connection,
            (provider.wallet as any).payer,
            provider.wallet.publicKey,
            null,
            9
        );

        vaultToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            vaultPda,
            undefined,
            { skipPreflight: true }
        );

        attackerToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            attacker.publicKey
        );

        victimToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            victim.publicKey
        );

        // Mint some tokens to attacker and victim
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, attackerToken, provider.wallet.publicKey, 1_000_000_000);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, victimToken, provider.wallet.publicKey, 1_000_000_000);
    });

    it("Initializes the vault with dead shares", async () => {
        await program.methods
            .initializeVault()
            .accounts({
                vault: vaultPda,
                admin: attacker.publicKey,
                mint: mint,
                systemProgram: anchor.web3.SystemProgram.programId,
            })
            .signers([attacker])
            .rpc();

        const vault = await program.account.secureVault.fetch(vaultPda);
        expect(vault.totalShares.toString()).to.equal("1000000"); // INITIAL_DEAD_SHARES
        expect(vault.deadShares.toString()).to.equal("1000000");
    });

    it("Prevents small first deposit inflation (Attack Scenario)", async () => {
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

        // 1. Attacker deposits small amount (must be >= MINIMUM_DEPOSIT)
        const depositAmount = new anchor.BN(1001);
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

        // 2. Attacker 'donates' to vault to inflate price
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, vaultToken, provider.wallet.publicKey, 1_000_000_000);

        // 3. Victim tries to deposit
        const [victimSharesPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("user_shares"), victim.publicKey.toBuffer()],
            program.programId
        );

        await program.methods
            .initializeUserShares()
            .accounts({
                userShares: victimSharesPda,
                user: victim.publicKey,
                systemProgram: anchor.web3.SystemProgram.programId,
            })
            .signers([victim])
            .rpc();

        const victimDeposit = new anchor.BN(500_000_000);

        await program.methods
            .deposit(victimDeposit)
            .accounts({
                vault: vaultPda,
                userShares: victimSharesPda,
                userToken: victimToken,
                vaultToken: vaultToken,
                user: victim.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([victim])
            .rpc();

        const victimShares = await program.account.userShares.fetch(victimSharesPda);
        expect(victimShares.amount.toNumber()).to.be.greaterThan(0);
        console.log("Victim received shares:", victimShares.amount.toNumber());
    });
});
