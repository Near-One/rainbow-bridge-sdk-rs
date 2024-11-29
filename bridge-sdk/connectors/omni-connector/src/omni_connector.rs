use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::prelude::*;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionOutcomeView;
use near_token::NearToken;
use omni_types::locker_args::{ClaimFeeArgs, StorageDepositAction};
use omni_types::prover_args::EvmVerifyProofArgs;
use omni_types::prover_result::ProofKind;
use omni_types::{locker_args::BindTokenArgs, near_events::Nep141LockerEvent, ChainKind};
use omni_types::{Fee, OmniAddress};

use evm_bridge_client::EvmBridgeClient;
use near_bridge_client::NearBridgeClient;
use solana_bridge_client::SolanaBridgeClient;
use wormhole_bridge_client::WormholeBridgeClient;

#[derive(Builder, Default)]
#[builder(pattern = "owned")]
pub struct OmniConnector {
    near_bridge_client: Option<NearBridgeClient>,
    eth_bridge_client: Option<EvmBridgeClient>,
    base_bridge_client: Option<EvmBridgeClient>,
    arb_bridge_client: Option<EvmBridgeClient>,
    solana_bridge_client: Option<SolanaBridgeClient>,
    wormhole_bridge_client: Option<WormholeBridgeClient>,
}

// TODO: Refactor and add solana support
pub enum InitTransferArgs {
    NearInitTransfer {
        near_token_id: String,
        amount: u128,
        receiver: String,
    },
    EvmInitTransfer {
        chain_kind: ChainKind,
        near_token_id: String,
        amount: u128,
        receiver: String,
        fee: Fee,
    },
}

pub enum FinTransferArgs {
    NearFinTransfer {
        chain_kind: ChainKind,
        storage_deposit_actions: Vec<StorageDepositAction>,
        prover_args: Vec<u8>,
    },
    EvmFinTransfer {
        chain_kind: ChainKind,
        event: Nep141LockerEvent,
    },
    EvmFinTransferWithLog {
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    },
}

impl OmniConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn evm_deploy_token(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    ) -> Result<TxHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "LogMetadataEvent")
            .await?;

        evm_bridge_client
            .deploy_token(
                serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
            )
            .await
    }

    pub async fn evm_fin_transfer(
        &self,
        chain_kind: ChainKind,
        near_tx_hash: CryptoHash,
    ) -> Result<TxHash> {
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;
        let near_bridge_client = self.near_bridge_client()?;

        let transfer_log = near_bridge_client
            .extract_transfer_log(near_tx_hash, None, "SignTransferEvent")
            .await?;

        evm_bridge_client
            .fin_transfer(
                serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
            )
            .await
    }

    pub async fn near_bind_token_with_evm_proof(
        &self,
        chain_kind: ChainKind,
        tx_hash: TxHash,
    ) -> Result<CryptoHash> {
        let near_bridge_client = self.near_bridge_client()?;
        let evm_bridge_client = self.evm_bridge_client(chain_kind)?;

        let proof = evm_bridge_client
            .get_proof_for_event(tx_hash, ProofKind::DeployToken)
            .await?;

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

    pub async fn near_sign_transfer(
        &self,
        origin_nonce: u64,
        fee_recipient: Option<AccountId>,
        fee: Option<Fee>,
    ) -> Result<FinalExecutionOutcomeView> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .sign_transfer(origin_nonce, fee_recipient, fee)
            .await
    }

    pub async fn near_claim_fee(
        &self,
        claim_fee_args: ClaimFeeArgs,
    ) -> Result<FinalExecutionOutcomeView> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client.claim_fee(claim_fee_args).await
    }

    pub async fn near_sign_claim_native_fee(
        &self,
        nonces: Vec<u128>,
        recipient: OmniAddress,
    ) -> Result<FinalExecutionOutcomeView> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .sign_claim_native_fee(nonces, recipient)
            .await
    }

    pub async fn near_get_required_storage_deposit(
        &self,
        token_id: AccountId,
        account_id: AccountId,
    ) -> Result<u128> {
        let near_bridge_client = self.near_bridge_client()?;
        near_bridge_client
            .get_required_storage_deposit(token_id, account_id)
            .await
    }

    pub async fn init_transfer(&self, init_transfer_args: InitTransferArgs) -> Result<String> {
        match init_transfer_args {
            InitTransferArgs::NearInitTransfer {
                near_token_id,
                amount,
                receiver,
            } => self
                .near_bridge_client()
                .map_err(|_| BridgeSdkError::UnknownError)?
                .init_transfer(near_token_id, amount, receiver)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            InitTransferArgs::EvmInitTransfer {
                chain_kind,
                near_token_id,
                amount,
                receiver,
                fee,
            } => self
                .evm_bridge_client(chain_kind)
                .map_err(|_| BridgeSdkError::UnknownError)?
                .init_transfer(near_token_id, amount, receiver, fee)
                .await
                .map(|tx_hash| tx_hash.to_string()),
        }
    }

    pub async fn fin_transfer(&self, fin_transfer_args: FinTransferArgs) -> Result<String> {
        match fin_transfer_args {
            FinTransferArgs::NearFinTransfer {
                chain_kind,
                storage_deposit_actions,
                prover_args,
            } => self
                .near_bridge_client()
                .map_err(|_| BridgeSdkError::UnknownError)?
                .fin_transfer(omni_types::locker_args::FinTransferArgs {
                    chain_kind,
                    storage_deposit_actions,
                    prover_args,
                })
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransfer { chain_kind, event } => self
                .evm_bridge_client(chain_kind)
                .map_err(|_| BridgeSdkError::UnknownError)?
                .fin_transfer(event)
                .await
                .map(|tx_hash| tx_hash.to_string()),
            FinTransferArgs::EvmFinTransferWithLog {
                chain_kind,
                near_tx_hash,
            } => self
                .evm_fin_transfer(chain_kind, near_tx_hash)
                .await
                .map(|tx_hash| tx_hash.to_string()),
        }
    }

    pub async fn wormhole_get_vaa<E>(
        &self,
        chain_id: u64,
        emitter: E,
        sequence: u64,
    ) -> Result<String>
    where
        E: std::fmt::Display,
    {
        let wormhole_bridge_client = self.wormhole_bridge_client()?;
        wormhole_bridge_client
            .get_vaa(chain_id, emitter, sequence)
            .await
    }

    pub fn near_bridge_client(&self) -> Result<&NearBridgeClient> {
        self.near_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "NEAR bridge client not configured".to_string(),
            ))
    }

    pub fn evm_bridge_client(&self, chain_kind: ChainKind) -> Result<&EvmBridgeClient> {
        let bridge_client = match chain_kind {
            ChainKind::Base => self.base_bridge_client.as_ref(),
            ChainKind::Arb => self.arb_bridge_client.as_ref(),
            ChainKind::Eth => self.eth_bridge_client.as_ref(),
            _ => unreachable!("Unsupported chain kind"),
        };

        bridge_client.ok_or(BridgeSdkError::ConfigError(
            "EVM bridge client not configured".to_string(),
        ))
    }

    pub fn wormhole_bridge_client(&self) -> Result<&WormholeBridgeClient> {
        self.wormhole_bridge_client
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Wormhole bridge client not configured".to_string(),
            ))
    }
}
