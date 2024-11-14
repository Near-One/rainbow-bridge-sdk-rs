use bridge_connector_common::result::{BridgeSdkError, Result};
use ethers::{abi::Address, prelude::*};
use near_connector::NearConnector;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::prover_args::EvmVerifyProofArgs;
use omni_types::prover_result::ProofKind;
use omni_types::{
    locker_args::BindTokenArgs, near_events::Nep141LockerEvent, ChainKind, OmniAddress,
};
use sha3::{Digest, Keccak256};
use std::{str::FromStr, sync::Arc};

abigen!(
    BridgeTokenFactory,
    r#"[
      struct MetadataPayload { string token; string name; string symbol; uint8 decimals; }
      struct FinTransferPayload { uint128 nonce; string token; uint128 amount; address recipient; string feeRecipient; }
      struct ClaimFeePayload { uint128[] nonces; uint128 amount; address recipient; }
      function deployToken(bytes signatureData, MetadataPayload metadata) external returns (address)
      function finTransfer(bytes, FinTransferPayload) external
      function initTransfer(string token, uint128 amount, uint128 fee, uint128 nativeFee, string memory recipient) external
      function claimNativeFee(bytes calldata signatureData, ClaimFeePayload memory payload) external
      function nearToEthToken(string nearTokenId) external view returns (address)
    ]"#
);

abigen!(
    ERC20,
    r#"[
      function allowance(address _owner, address _spender) public view returns (uint256 remaining)
      function approve(address spender, uint256 amount) external returns (bool)
    ]"#
);

/// Bridging NEAR-originated NEP-141 tokens to EVM and back
#[derive(Builder, Default)]
pub struct EvmConnector {
    #[doc = r"EVM RPC endpoint. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    endpoint: Option<String>,
    #[doc = r"EVM chain id. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    chain_id: Option<u64>,
    #[doc = r"EVM private key. Required for `deploy_token`, `mint`, `burn`"]
    private_key: Option<String>,
    #[doc = r"Bridged token factory address on EVM. Required for `deploy_token`, `mint`, `burn`"]
    bridge_token_factory_address: Option<String>,
    #[doc = r"NEAR connector. Required for `deploy_token`, `mint`, `burn`, `withdraw`"]
    near_connector: Option<NearConnector>,
}

impl EvmConnector {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deploys an ERC-20 token that will be used when bridging NEP-141 tokens to EVM. Requires a receipt from log_metadata transaction on Near
    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN")]
    pub async fn evm_deploy_token(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .near_connector()?
            .extract_transfer_log(transaction_hash, sender_id, "LogMetadataEvent")
            .await?;

        self.evm_deploy_token_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM DEPLOY TOKEN WITH LOG")]
    pub async fn evm_deploy_token_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let payload = MetadataPayload {
            token: metadata_payload.token,
            name: metadata_payload.name,
            symbol: metadata_payload.symbol,
            decimals: metadata_payload.decimals,
        };

        let serialized_signature = signature.to_bytes();

        assert!(serialized_signature.len() == 65);

        let call = factory
            .deploy_token(serialized_signature.into(), payload)
            .gas(500_000);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent new bridge token transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Mints the corresponding bridged tokens on EVM. Requires an MPC signature
    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER")]
    pub async fn evm_fin_transfer(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .near_connector()?
            .extract_transfer_log(transaction_hash, sender_id, "SignTransferEvent")
            .await?;

        self.evm_fin_transfer_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM FIN TRANSFER WITH LOG")]
    pub async fn evm_fin_transfer_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let bridge_deposit = FinTransferPayload {
            nonce: message_payload.nonce.into(),
            token: message_payload.token.to_string(),
            amount: message_payload.amount.into(),
            recipient: match message_payload.recipient {
                OmniAddress::Eth(addr) | OmniAddress::Base(addr) | OmniAddress::Arb(addr) => {
                    H160(addr.0)
                }
                _ => return Err(BridgeSdkError::UnknownError),
            },
            fee_recipient: message_payload
                .fee_recipient
                .map_or_else(String::new, |addr| addr.to_string()),
        };

        let call = factory.fin_transfer(signature.to_bytes().into(), bridge_deposit);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent finalize transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    /// Burns bridged tokens on EVM. The proof from this transaction is then used to withdraw the corresponding tokens on Near
    #[tracing::instrument(skip_all, name = "EVM INIT TRANSFER")]
    pub async fn evm_init_transfer(
        &self,
        near_token_id: String,
        amount: u128,
        receiver: String,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let erc20_address = factory
            .near_to_eth_token(near_token_id.clone())
            .call()
            .await?;

        tracing::debug!(
            address = format!("{:?}", erc20_address),
            "Retrieved ERC20 address"
        );

        let bridge_token = &self.bridge_token(erc20_address)?;

        let signer = self.signer()?;
        let bridge_token_factory_address = self.bridge_token_factory_address()?;
        let allowance = bridge_token
            .allowance(signer.address(), bridge_token_factory_address)
            .call()
            .await?;

        let amount256: ethers::types::U256 = amount.into();
        if allowance < amount256 {
            bridge_token
                .approve(bridge_token_factory_address, amount256 - allowance)
                .send()
                .await?
                .await
                .map_err(ContractError::from)?;

            tracing::debug!("Approved tokens for spending");
        }

        // TODO: Provide fee and nativeFee
        let withdraw_call = factory.init_transfer(near_token_id, amount, 0, 0, receiver);
        let tx = withdraw_call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent transfer transaction"
        );

        Ok(tx.tx_hash())
    }

    pub async fn bind_token_with_eth_prover(&self, tx_hash: TxHash) -> Result<CryptoHash> {
        let endpoint = self.endpoint()?;

        let event_topic = H256::from_str(&hex::encode(Keccak256::digest(
            "DeployToken(address,string,string,string,uint8)".as_bytes(),
        )))
        .map_err(|_| BridgeSdkError::UnknownError)?;

        let proof = eth_proof::get_proof_for_event(tx_hash, event_topic, endpoint).await?;

        let evm_verify_proof_args = EvmVerifyProofArgs {
            proof_kind: ProofKind::DeployToken,
            proof,
        };

        self.near_connector()?
            .bind_token(BindTokenArgs {
                chain_kind: ChainKind::Eth,
                prover_args: borsh::to_vec(&evm_verify_proof_args).map_err(|_| {
                    BridgeSdkError::EthProofError("Failed to serialize proof".to_string())
                })?,
            })
            .await
    }

    /// Claims fee on EVM chain
    #[tracing::instrument(skip_all, name = "EVM CLAIM NATIVE FEE")]
    pub async fn evm_claim_native_fee(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<TxHash> {
        let transfer_log = self
            .near_connector()?
            .extract_transfer_log(transaction_hash, sender_id, "SignClaimNativeFeeEvent")
            .await?;

        self.evm_claim_native_fee_with_log(
            serde_json::from_str(&transfer_log).map_err(|_| BridgeSdkError::UnknownError)?,
        )
        .await
    }

    #[tracing::instrument(skip_all, name = "EVM CLAIM NATIVE FEE WITH LOG")]
    pub async fn evm_claim_native_fee_with_log(
        &self,
        transfer_log: Nep141LockerEvent,
    ) -> Result<TxHash> {
        let factory = self.bridge_token_factory()?;

        let Nep141LockerEvent::SignClaimNativeFeeEvent {
            signature,
            claim_payload,
        } = transfer_log
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let (OmniAddress::Eth(recipient)
        | OmniAddress::Base(recipient)
        | OmniAddress::Arb(recipient)) = claim_payload.recipient
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let payload = ClaimFeePayload {
            nonces: claim_payload.nonces.into_iter().map(Into::into).collect(),
            amount: claim_payload.amount.into(),
            recipient: H160(recipient.0),
        };

        let serialized_signature = signature.to_bytes();

        assert!(serialized_signature.len() == 65);

        let call = factory
            .claim_native_fee(serialized_signature.into(), payload)
            .gas(500_000);
        let tx = call.send().await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx.tx_hash()),
            "Sent claim native fee transaction"
        );

        Ok(tx.tx_hash())
    }

    fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "EVM rpc endpoint is not set".to_string(),
        ))?)
    }

    fn bridge_token_factory_address(&self) -> Result<Address> {
        self.bridge_token_factory_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Bridge token factory address is not set".to_string(),
            ))
            .and_then(|addr| {
                Address::from_str(addr).map_err(|_| {
                    BridgeSdkError::ConfigError(
                        "bridge_token_factory_address is not a valid EVM address".to_string(),
                    )
                })
            })
    }

    fn bridge_token_factory(
        &self,
    ) -> Result<BridgeTokenFactory<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let endpoint = self.endpoint()?;

        let provider = Provider::<Http>::try_from(endpoint)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;

        let wallet = self.signer()?;

        let signer = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(signer);

        Ok(BridgeTokenFactory::new(
            self.bridge_token_factory_address()?,
            client,
        ))
    }

    fn bridge_token(
        &self,
        address: Address,
    ) -> Result<ERC20<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let endpoint = self.endpoint()?;

        let provider = Provider::<Http>::try_from(endpoint)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM rpc endpoint url".to_string()))?;

        let wallet = self.signer()?;

        let signer = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(signer);

        Ok(ERC20::new(address, client))
    }

    fn signer(&self) -> Result<LocalWallet> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "EVM private key is not set".to_string(),
            ))?;

        let chain_id = self.chain_id.as_ref().ok_or(BridgeSdkError::ConfigError(
            "EVM chain id is not set".to_string(),
        ))?;

        let private_key_bytes = hex::decode(private_key).map_err(|_| {
            BridgeSdkError::ConfigError("EVM private key is not a valid hex string".to_string())
        })?;

        if private_key_bytes.len() != 32 {
            return Err(BridgeSdkError::ConfigError(
                "EVM private key is of invalid length".to_string(),
            ));
        }

        Ok(LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|_| BridgeSdkError::ConfigError("Invalid EVM private key".to_string()))?
            .with_chain_id(*chain_id))
    }

    pub fn near_connector(&self) -> Result<&NearConnector> {
        self.near_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near connector is not set".to_string(),
            ))
    }
}
