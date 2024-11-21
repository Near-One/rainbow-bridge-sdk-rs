use std::{str::FromStr, sync::Arc};

use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::{abi::Address, prelude::*};
use near_connector::NearConnector;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::prover_args::EvmVerifyProofArgs;
use omni_types::prover_result::ProofKind;
use omni_types::Fee;
use omni_types::{
    locker_args::BindTokenArgs, near_events::Nep141LockerEvent, ChainKind, OmniAddress,
};
use sha3::{Digest, Keccak256};

use evm_bridge_client::EvmBridgeClient;
use near_bridge_client::NearBridgeClient;
use solana_bridge_client::SolanaBridgeClient;

#[derive(Builder, Default)]
#[builder(pattern = "owned")]
pub struct OmniConnector {
    near_bridge_client: Option<NearBridgeClient>,
    evm_bridge_client: Option<EvmBridgeClient>,
    solana_bridge_client: Option<SolanaBridgeClient>,
}

impl OmniConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn evm_deploy_token(&self, near_transaction_hash: CryptoHash) -> Result<TxHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_transaction_hash, None, "LogMetadataEvent")
            .await?;

        evm_bridge_client
            .deploy_token(serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?)
            .await
    }

    pub async fn evm_fin_transfer(&self, near_transaction_hash: CryptoHash) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client()?;
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_transaction_hash, None, "SignTransferEvent")
            .await?;

        evm_bridge_client
            .fin_transfer(serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?)
            .await
    }

    pub async fn near_bind_token_with_evm_proof(&self, tx_hash: TxHash) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client()?;

        let proof = evm_bridge_client.get_proof_for_event(tx_hash, ProofKind::DeployToken).await?;

        let verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::DeployToken,
            proof,
        };
        
        near_bridge_client
            .bind_token(BindTokenArgs {
                chain_kind: ChainKind::Eth,
                prover_args: borsh::to_vec(&verify_proof_args).map_err(|_| {
                    BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                })?,
            })
            .await
    }

    fn near_bridge_client(&self) -> Result<&NearBridgeClient> {
        self.near_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError("NEAR bridge client not configured".to_string()))
    }

    fn evm_bridge_client(&self) -> Result<&EvmBridgeClient> {
        self.evm_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError("EVM bridge client not configured".to_string()))
    }
}
