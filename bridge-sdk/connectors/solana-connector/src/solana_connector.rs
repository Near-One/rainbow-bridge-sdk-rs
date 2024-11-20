use bridge_connector_common::result::{BridgeSdkError, Result};
use derive_builder::Builder;
use near_connector::NearConnector;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::{near_events::Nep141LockerEvent, OmniAddress};
use solana_bridge_client::{
    DeployTokenData, DepositPayload, FinalizeDepositData, MetadataPayload, SolanaBridgeClient,
    TransferId,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
};

#[derive(Builder, Default)]
pub struct SolanaConnector {
    endpoint: Option<String>,
    bridge_address: Option<String>,
    wormhole_address: Option<String>,
    keypair: Option<String>,

    near_connector: Option<NearConnector>,
}

impl SolanaConnector {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn initialize(&self, program_keypair: Keypair) -> Result<Signature> {
        // Derived based on near bridge account id and derivation path (bridge-1)
        const DERIVED_NEAR_BRIDGE_ADDRESS: [u8; 64] = [
            19, 55, 243, 130, 164, 28, 152, 3, 170, 254, 187, 182, 135, 17, 208, 98, 216, 182, 238,
            146, 2, 127, 83, 201, 149, 246, 138, 221, 29, 111, 186, 167, 150, 196, 102, 219, 89,
            69, 115, 114, 185, 116, 6, 233, 154, 114, 222, 142, 167, 206, 157, 39, 177, 221, 224,
            86, 146, 61, 226, 206, 55, 2, 119, 12,
        ];

        let tx_hash = self
            .client()?
            .initialize(
                DERIVED_NEAR_BRIDGE_ADDRESS,
                program_keypair,
                self.keypair()?,
            )
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent initialize transaction"
        );

        Ok(tx_hash)
    }

    pub async fn deploy_token(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<Signature> {
        let transfer_log = self
            .near_connector()?
            .extract_transfer_log(transaction_hash, sender_id, "LogMetadataEvent")
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = serde_json::from_str(&transfer_log)?
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let mut signature = signature.to_bytes();
        signature[64] -= 27; // TODO: Remove recovery_id modification in OmniTypes and add it specifically when submitting to EVM chains

        let payload = DeployTokenData {
            metadata: MetadataPayload {
                token: metadata_payload.token,
                name: metadata_payload.name,
                symbol: metadata_payload.symbol,
                decimals: metadata_payload.decimals,
            },
            signature: signature
                .try_into()
                .map_err(|_| BridgeSdkError::UnknownError)?,
        };

        let tx_hash = self
            .client()?
            .deploy_token(payload, self.keypair()?)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent deploy token transaction"
        );

        Ok(tx_hash)
    }

    pub async fn finalize_transfer(
        &self,
        transaction_hash: CryptoHash,
        solana_token: Pubkey, // TODO: retrieve from near contract
        sender_id: Option<AccountId>,
    ) -> Result<Signature> {
        let transfer_log = self
            .near_connector()?
            .extract_transfer_log(transaction_hash, sender_id, "SignTransferEvent")
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = serde_json::from_str(&transfer_log)?
        else {
            return Err(BridgeSdkError::UnknownError);
        };

        let mut signature = signature.to_bytes();
        signature[64] -= 27;

        let payload = FinalizeDepositData {
            payload: DepositPayload {
                destination_nonce: message_payload.destination_nonce,
                transfer_id: TransferId {
                    origin_chain: 1,
                    origin_nonce: message_payload.transfer_id.origin_nonce,
                },
                token: "wrap.testnet".to_string(),
                amount: message_payload.amount.into(),
                recipient: match message_payload.recipient {
                    OmniAddress::Sol(addr) => Pubkey::new_from_array(addr.0),
                    _ => return Err(BridgeSdkError::UnknownError),
                },
                fee_recipient: message_payload.fee_recipient.map(|addr| addr.to_string()),
            },
            signature: signature
                .try_into()
                .map_err(|_| BridgeSdkError::UnknownError)?,
        };

        let tx_hash = self
            .client()?
            .finalize_transfer(payload, solana_token, self.keypair()?)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent finalize transfer transaction"
        );

        Ok(tx_hash)
    }

    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature> {
        let tx_hash = self
            .client()?
            .log_metadata(token, self.keypair()?)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent register token transaction"
        );

        Ok(tx_hash)
    }

    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
    ) -> Result<Signature> {
        let tx_hash = self
            .client()?
            .init_transfer(token, amount, recipient, self.keypair()?)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent init transfer native transaction"
        );

        Ok(tx_hash)
    }

    pub async fn init_transfer_sol(&self, amount: u128, recipient: String) -> Result<Signature> {
        let tx_hash = self
            .client()?
            .init_transfer_sol(amount, recipient, self.keypair()?)
            .await
            .map_err(|_| BridgeSdkError::UnknownError)?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_hash),
            "Sent init transfer SOL transaction"
        );

        Ok(tx_hash)
    }

    fn client(&self) -> Result<SolanaBridgeClient> {
        Ok(SolanaBridgeClient::new(
            self.endpoint()?.to_string(),
            self.bridge_address()?
                .parse()
                .map_err(|_| BridgeSdkError::ConfigError("Invalid bridge address".to_string()))?,
            self.wormhole_address()?
                .parse()
                .map_err(|_| BridgeSdkError::ConfigError("Invalid wormhole address".to_string()))?,
        ))
    }

    fn endpoint(&self) -> Result<&str> {
        Ok(self.endpoint.as_ref().ok_or(BridgeSdkError::ConfigError(
            "Solana rpc endpoint is not set".to_string(),
        ))?)
    }

    fn bridge_address(&self) -> Result<&str> {
        Ok(self
            .bridge_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Solana bridge address is not set".to_string(),
            ))?)
    }

    fn wormhole_address(&self) -> Result<&str> {
        Ok(self
            .wormhole_address
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Solana wormhole address is not set".to_string(),
            ))?)
    }

    fn keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_base58_string(self.keypair.as_ref().ok_or(
            BridgeSdkError::ConfigError("Solana keypair is not set".to_string()),
        )?))
    }

    fn near_connector(&self) -> Result<&NearConnector> {
        self.near_connector
            .as_ref()
            .ok_or(BridgeSdkError::ConfigError(
                "Near connector is not set".to_string(),
            ))
    }
}
