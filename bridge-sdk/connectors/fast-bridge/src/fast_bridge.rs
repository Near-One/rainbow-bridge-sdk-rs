use base64::prelude::*;
use borsh::BorshSerialize;
use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use ethers::prelude::*;
use near_crypto::SecretKey;
use near_primitives::{hash::CryptoHash, types::AccountId};
use serde_json::json;
use std::{str::FromStr, sync::Arc};
use crate::{types::*, utils::get_fast_bridge_transfer_storage_key};

abigen!(
    FastBridgeContract,
    r#"[
      function transferTokens(address _token, address payable _recipient, uint256 _nonce, uint256 _amount, string _unlock_recipient, uint256 _valid_till_block_height)
    ]"#
);

#[derive(Builder)]
pub struct FastBridge {
    #[doc = r"Ethereum RPC endpoint. Required for `complete_transfer_on_eth`, `lp_unlock`"]
    eth_endpoint: Option<String>,
    #[doc = r"Ethereum chain id. Required for `complete_transfer_on_eth`, `lp_unlock`"]
    eth_chain_id: Option<u64>,
    #[doc = r"Ethereum private key. Required for `complete_transfer_on_eth`"]
    eth_private_key: Option<String>,
    #[doc = r"NEAR RPC endpoint. Required for `transfer`, `complete_transfer_on_eth`, `lp_unlock`, `withdraw`"]
    near_endpoint: Option<String>,
    #[doc = r"NEAR private key. Required for `transfer`, `lp_unlock`, `withdraw`"]
    near_private_key: Option<String>,
    #[doc = r"NEAR account id of the transaction signer. Required for `transfer`, `lp_unlock`, `withdraw`"]
    near_signer: Option<String>,
    #[doc = r"Fast Bridge account id on Near. Required for `transfer`, `lp_unlock`, `withdraw`"]
    fast_bridge_account_id: Option<String>,
    #[doc = r"Fast bridge address on Ethereum. Required for `complete_transfer_on_eth`"]
    fast_bridge_address: Option<String>,
}

impl FastBridge {
    /// Initiates fast bridge transfer by sending tokens to the fast bridge contract on NEAR
    #[tracing::instrument(skip_all, name = "TRANSFER")]
    pub async fn transfer(
        &self,
        token_id: AccountId,
        amount: u128,
        fee_amount: u128,
        eth_token_address: Address,
        recipient: Address,
        valid_till: u64,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;
        let fast_bridge_account_id = self.fast_bridge_account_id()?.to_string();

        let message = TransferMessage {
            valid_till,
            transfer: TransferDataEthereum {
                token_near: token_id.clone(),
                token_eth: eth_token_address.into(),
                amount: NearU128(amount),
            },
            fee: TransferDataNear {
                token: token_id.clone(),
                amount: NearU128(fee_amount),
            },
            recipient: recipient.into(),
            valid_till_block_height: None,
            aurora_sender: None,
        };

        let mut buffer: Vec<u8> = Vec::new();
        message.serialize(&mut buffer)?;
        let msg = BASE64_STANDARD.encode(&buffer);

        let args = format!(
            r#"{{"receiver_id":"{fast_bridge_account_id}","amount":"{amount}","msg":"{msg}"}}"#
        )
        .to_string()
        .into_bytes();

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            token_id.to_string(),
            "ft_transfer_call".to_string(),
            args,
            200_000_000_000_000,
            1,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent tokens to the fast bridge contract"
        );

        Ok(tx_hash)
    }

    /// Completes fast bridge transfer by sending tokens to the recipient on Ethereum. The proof from this transaction is to be used to unlock tokens on NEAR for unlock_recipient
    #[tracing::instrument(skip_all, name = "TRANSFER ON ETH")]
    pub async fn complete_transfer_on_eth(
        &self,
        nonce: U256,
        unlock_recipient: String,
    ) -> Result<TxHash> {
        let fast_bridge = self.fast_bridge_contract()?;
        let near_endpoint = self.near_endpoint()?;

        let response = near_rpc_client::view(
            near_endpoint,
            AccountId::from_str(self.fast_bridge_account_id()?)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid fast bridge account id".to_string()))?,
            "get_pending_transfer".to_string(),
            json!({
                "id": nonce.to_string(),
            })
        ).await?;

        let json = String::from_utf8(response)?;
        let pending_transfer: (AccountId, TransferMessage) = serde_json::from_str(&json)?;

        let amount = pending_transfer.1.transfer.amount.0.into();
        let transfer_call = fast_bridge
            .transfer_tokens(
                pending_transfer.1.transfer.token_eth.into(),
                pending_transfer.1.recipient.into(),
                nonce,
                amount,
                unlock_recipient,
                pending_transfer.1.valid_till_block_height
                    .ok_or(BridgeSdkError::UnknownError)?
                    .into(),
            )
            .value(amount);

        let tx = transfer_call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Completed fast bridge transfer"
        );

        Ok(tx.tx_hash())
    }

    /// Unlocks tokens on Near following a successful transfer completion on Ethereum.
    #[tracing::instrument(skip_all, name = "LP UNLOCK")]
    pub async fn lp_unlock(&self, tx_hash: TxHash, log_index: u64) -> Result<CryptoHash> {
        let eth_endpoint = self.eth_endpoint()?;
        let near_endpoint = self.near_endpoint()?;

        let proof = eth_proof::get_event_proof(tx_hash, log_index, eth_endpoint).await?;

        let serialized_proof = serde_json::to_string(&proof)?;
        let args = format!(r#"{{"proof":{serialized_proof}}}"#)
            .to_string()
            .into_bytes();

        tracing::debug!("Retrieved Ethereum proof");

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            self.fast_bridge_account_id()?.to_string(),
            "lp_unlock".to_string(),
            args,
            120_000_000_000_000,
            0,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent lp unlock transaction"
        );

        Ok(tx_hash)
    }

    pub async fn unlock(&self, nonce: u64) -> Result<CryptoHash> {
        let eth_endpoint = self.eth_endpoint()?;
        let near_endpoint = self.near_endpoint()?;

        let response = near_rpc_client::view(
            near_endpoint,
            AccountId::from_str(self.fast_bridge_account_id()?)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid fast bridge account id".to_string()))?,
            "get_pending_transfer".to_string(),
            json!({
                "id": nonce.to_string(),
            })
        ).await?;

        let json = String::from_utf8(response)?;
        let pending_transfer: (AccountId, TransferMessage) = serde_json::from_str(&json)?;

        let slot_to_prove = get_fast_bridge_transfer_storage_key(
            pending_transfer.1.transfer.token_eth,
            pending_transfer.1.recipient,
            U256::from(nonce),
            U256::from(pending_transfer.1.transfer.amount.0),
        );
        
        let proof = eth_proof::get_storage_proof(
            self.fast_bridge_address()?,
            H256(slot_to_prove),
            pending_transfer.1.valid_till_block_height
                .ok_or(BridgeSdkError::UnknownError)?,
            eth_endpoint,
        ).await?;

        let mut buffer: Vec<u8> = Vec::new();
        proof.serialize(&mut buffer)?;
        let proof = BASE64_STANDARD.encode(&buffer);

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            self.fast_bridge_account_id()?.to_owned(),
            "unlock".to_owned(),
            json!({
                "nonce": nonce.to_string(),
                "proof": proof,
            }).to_string().into_bytes(),
            300_000_000_000_000,
            0
        ).await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent unlock transaction"
        );

        Ok(tx_hash)
    }

    /// Withdraw tokens from the fast bridge contract.
    #[tracing::instrument(skip_all, name = "WITHDRAW")]
    pub async fn withdraw(
        &self,
        token_id: AccountId,
        amount: Option<U128>,
        recipient_id: Option<AccountId>,
        msg: Option<String>,
    ) -> Result<CryptoHash> {
        let near_endpoint = self.near_endpoint()?;

        let mut json = format!(r#"{{"token_id": "{token_id}""#);
        if let Some(recipient_id) = recipient_id {
            json.push_str(&format!(r#","recipient_id": "{recipient_id}""#));
        }
        if let Some(amount) = amount {
            json.push_str(&format!(r#","amount": "{amount}""#));
        }
        if let Some(msg) = msg {
            json.push_str(&format!(r#","msg": "{msg}""#));
        }
        json.push_str("}");

        let args = json.to_string().into_bytes();

        let tx_hash = near_rpc_client::change(
            near_endpoint,
            self.near_signer()?,
            self.fast_bridge_account_id()?.to_string(),
            "withdraw".to_string(),
            args,
            20_000_000_000_000,
            0,
        )
        .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent withdraw transaction"
        );

        Ok(tx_hash)
    }

    fn near_signer(&self) -> Result<near_crypto::InMemorySigner> {
        let near_private_key =
            self.near_private_key
                .as_ref()
                .ok_or(BridgeSdkError::ConfigError(
                    "Near account private key is not set".to_string(),
                ))?;
        let near_signer = self
            .near_signer
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near signer account id is not set".to_string(),
            ))?;

        Ok(near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(near_signer).map_err(|_| {
                BridgeSdkError::ConfigError("Invalid near signer account id".to_string())
            })?,
            SecretKey::from_str(near_private_key)
                .map_err(|_| BridgeSdkError::ConfigError("Invalid near private key".to_string()))?,
        ))
    }

    fn fast_bridge_contract(
        &self,
    ) -> Result<FastBridgeContract<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let eth_endpoint = self
            .eth_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum rpc endpoint is not set".to_string(),
            ))?;

        let eth_provider = Provider::<Http>::try_from(eth_endpoint).map_err(|_| {
            BridgeSdkError::ConfigError("Invalid ethereum rpc endpoint url".to_string())
        })?;

        let wallet = self.eth_signer()?;

        let signer = SignerMiddleware::new(eth_provider, wallet);
        let client = Arc::new(signer);

        Ok(FastBridgeContract::new(self.fast_bridge_address()?, client))
    }

    fn eth_signer(&self) -> Result<LocalWallet> {
        let eth_private_key = self
            .eth_private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum private key is not set".to_string(),
            ))?;

        let eth_chain_id = self
            .eth_chain_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum chain id is not set".to_string(),
            ))?
            .clone();

        let private_key_bytes = hex::decode(eth_private_key).map_err(|_| {
            BridgeSdkError::ConfigError(
                "Ethereum private key is not a valid hex string".to_string(),
            )
        })?;

        if private_key_bytes.len() != 32 {
            return Err(BridgeSdkError::ConfigError(
                "Ethereum private key is of invalid length".to_string(),
            ));
        }

        Ok(LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid ethereum private key".to_string()))?
            .with_chain_id(eth_chain_id))
    }

    fn fast_bridge_address(&self) -> Result<Address> {
        self.fast_bridge_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Fast bridge address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "fast_bridge_address is not a valid Ethereum address".to_string(),
                    )
                })
            })
    }

    fn eth_endpoint(&self) -> Result<&str> {
        Ok(self
            .eth_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Ethereum rpc endpoint is not set".to_string(),
            ))?)
    }

    fn near_endpoint(&self) -> Result<&str> {
        Ok(self
            .near_endpoint
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near rpc endpoint is not set".to_string(),
            ))?)
    }

    fn fast_bridge_account_id(&self) -> Result<&str> {
        Ok(self
            .fast_bridge_account_id
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Fast bridge account id is not set".to_string(),
            ))?)
    }
}
