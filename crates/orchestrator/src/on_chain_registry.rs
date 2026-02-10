//! On-Chain Registry for Audit Results
//!
//! Registers vulnerability findings and exploit proofs on Solana blockchain
//! for permanent, verifiable record-keeping.

use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub rpc_url: String,
    pub registry_program_id: String,
    pub commitment: CommitmentConfig,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.devnet.solana.com".to_string(),
            registry_program_id: "RegVp1vuLPu7X7PMtj5e6v5DqdQ8TS42sZq8vHPLNM1".to_string(),
            commitment: CommitmentConfig::confirmed(),
        }
    }
}

/// A registered exploit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitEntry {
    pub id: String,
    pub program_id: String,
    pub vulnerability_type: String,
    pub severity: u8,
    pub finder: String,
    pub timestamp: i64,
    pub proof_hash: String,
    pub tx_signature: Option<String>,
}

/// A registered audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub program_id: String,
    pub auditor: String,
    pub findings_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub report_hash: String,
    pub timestamp: i64,
    pub tx_signature: Option<String>,
}

/// Main on-chain registry client
pub struct OnChainRegistry {
    client: RpcClient,
    config: RegistryConfig,
    payer: Option<Keypair>,
}

impl OnChainRegistry {
    /// Create a new registry client
    pub fn new(config: RegistryConfig) -> Self {
        let client = RpcClient::new_with_commitment(config.rpc_url.clone(), config.commitment);

        Self {
            client,
            config,
            payer: None,
        }
    }

    /// Create with default devnet configuration
    pub fn devnet() -> Self {
        Self::new(RegistryConfig::default())
    }

    /// Set the payer keypair for transactions
    pub fn with_payer(mut self, payer: Keypair) -> Self {
        self.payer = Some(payer);
        self
    }

    /// Register an exploit finding on-chain
    pub async fn register_exploit(
        &self,
        program_id: &str,
        vulnerability_type: &str,
        severity: u8,
        proof_data: &[u8],
    ) -> Result<String, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;

        // Create a hash of the proof data
        let proof_hash = self.hash_data(proof_data);

        // Build instruction data
        let mut instruction_data = vec![0x01]; // RegisterExploit discriminator
        instruction_data.extend_from_slice(&severity.to_le_bytes());
        instruction_data.extend_from_slice(proof_hash.as_bytes());
        instruction_data.extend_from_slice(vulnerability_type.as_bytes());

        // Create the registry PDA for this finding
        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target_program = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (pda, _bump) = Pubkey::find_program_address(
            &[b"exploit", target_program.as_ref(), proof_hash.as_bytes()],
            &registry_program,
        );

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true), // Payer/finder
            AccountMeta::new(pda, false),           // Exploit record PDA
            AccountMeta::new_readonly(target_program, false), // Target program
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: registry_program,
            accounts,
            data: instruction_data,
        };

        let recent_blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        let message = Message::new(&[instruction], Some(&payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[payer], recent_blockhash);

        // SEND AND CONFIRM: Real ledger interaction
        match self.client.send_and_confirm_transaction(&transaction) {
            Ok(sig) => Ok(sig.to_string()),
            Err(e) => Err(RegistryError::RpcError(format!(
                "Live ledger registration failed: {}",
                e
            ))),
        }
    }

    /// Register a complete audit on-chain
    #[allow(clippy::too_many_arguments)]
    pub async fn register_audit(
        &self,
        program_id: &str,
        findings_count: u32,
        critical_count: u32,
        high_count: u32,
        medium_count: u32,
        low_count: u32,
        report_data: &[u8],
    ) -> Result<AuditEntry, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;

        let report_hash = self.hash_data(report_data);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Build instruction data
        let mut instruction_data = vec![0x02]; // RegisterAudit discriminator
        instruction_data.extend_from_slice(&findings_count.to_le_bytes());
        instruction_data.extend_from_slice(&critical_count.to_le_bytes());
        instruction_data.extend_from_slice(&high_count.to_le_bytes());
        instruction_data.extend_from_slice(&medium_count.to_le_bytes());
        instruction_data.extend_from_slice(&low_count.to_le_bytes());
        instruction_data.extend_from_slice(report_hash.as_bytes());

        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target_program = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (pda, _bump) = Pubkey::find_program_address(
            &[b"audit", target_program.as_ref(), &timestamp.to_le_bytes()],
            &registry_program,
        );

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(target_program, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: registry_program,
            accounts,
            data: instruction_data,
        };

        // Create and simulate transaction
        let recent_blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        let message = Message::new(&[instruction], Some(&payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[payer], recent_blockhash);

        let tx_signature = match self.client.send_and_confirm_transaction(&transaction) {
            Ok(sig) => Some(sig.to_string()),
            Err(_) => None,
        };

        Ok(AuditEntry {
            id: format!("audit_{}_{}", program_id, timestamp),
            program_id: program_id.to_string(),
            auditor: payer.pubkey().to_string(),
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            report_hash,
            timestamp,
            tx_signature,
        })
    }

    /// Query audit history for a program
    pub async fn get_audit_history(
        &self,
        _program_id: &str,
    ) -> Result<Vec<AuditEntry>, RegistryError> {
        // Implement on-chain record retrieval
        Ok(Vec::new())
    }

    /// Query exploit reports for a program
    pub async fn get_exploit_reports(
        &self,
        _program_id: &str,
    ) -> Result<Vec<ExploitEntry>, RegistryError> {
        // Implement on-chain telemetry retrieval
        Ok(Vec::new())
    }

    pub async fn verify_exploit_registration(
        &self,
        tx_signature: &str,
    ) -> Result<bool, RegistryError> {
        // Validation of transaction signature on-chain
        let sig = solana_sdk::signature::Signature::from_str(tx_signature)
            .map_err(|e| RegistryError::InvalidSignature(e.to_string()))?;

        match self.client.get_signature_status(&sig) {
            Ok(Some(status)) => Ok(status.is_ok()),
            Ok(None) => Ok(false),
            Err(e) => Err(RegistryError::RpcError(e.to_string())),
        }
    }

    /// Helper to hash data
    fn hash_data(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

/// Registry errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("No payer keypair set")]
    NoPayer,
    #[error("Invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = OnChainRegistry::devnet();
        assert!(registry.payer.is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = RegistryConfig::default();
        assert!(config.rpc_url.contains("devnet"));
    }
}
