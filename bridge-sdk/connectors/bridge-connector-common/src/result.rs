use eth_proof::{EthClientError, EthProofError};
use ethers::{
    contract::ContractError,
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::LocalWallet,
};
use near_light_client_on_eth::NearLightClientOnEthError;
use near_rpc_client::NearRpcError;
use std::result;

pub type Result<T> = result::Result<T, BridgeSdkError>;

#[derive(thiserror::Error, Debug)]
pub enum BridgeSdkError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Error communicating with Ethereum RPC: {0}")]
    EthRpcError(#[source] EthRpcError),
    #[error("Error communicating with Near RPC: {0}")]
    NearRpcError(#[from] NearRpcError),
    #[error("Error creating Ethereum proof: {0}")]
    EthProofError(String),
    #[error("Error creating Near proof: {0}")]
    NearProofError(String),
    #[error("{0}")]
    DataError(#[source] DataError),
    #[error("Unexpected error occured")]
    UnknownError,
}

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub enum DataError {
    BorshError(#[source] borsh::io::Error),
    JsonError(#[source] serde_json::Error),
    Utf8Error(#[source] std::string::FromUtf8Error),
}

impl From<serde_json::Error> for BridgeSdkError {
    fn from(error: serde_json::Error) -> Self {
        BridgeSdkError::DataError(DataError::JsonError(error))
    }
}

impl From<borsh::io::Error> for BridgeSdkError {
    fn from(error: borsh::io::Error) -> Self {
        BridgeSdkError::DataError(DataError::BorshError(error))
    }
}

impl From<std::string::FromUtf8Error> for BridgeSdkError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        BridgeSdkError::DataError(DataError::Utf8Error(error))
    }
}

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub enum EthRpcError {
    SignerContractError(#[source] ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>),
    ProviderContractError(#[source] ContractError<Provider<Http>>),
    EthClientError(#[source] EthClientError),
}

impl From<EthProofError> for BridgeSdkError {
    fn from(error: EthProofError) -> Self {
        match error {
            EthProofError::TrieError(e) => BridgeSdkError::EthProofError(e.to_string()),
            EthProofError::EthClientError(e) => {
                BridgeSdkError::EthRpcError(EthRpcError::EthClientError(e))
            }
            EthProofError::Other(e) => BridgeSdkError::EthProofError(e),
        }
    }
}

impl From<NearLightClientOnEthError> for BridgeSdkError {
    fn from(error: NearLightClientOnEthError) -> Self {
        match error {
            NearLightClientOnEthError::ConfigError(e) => BridgeSdkError::ConfigError(e),
            NearLightClientOnEthError::EthRpcError(e) => {
                BridgeSdkError::EthRpcError(EthRpcError::ProviderContractError(e))
            }
        }
    }
}

impl From<ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>> for BridgeSdkError {
    fn from(error: ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>) -> Self {
        BridgeSdkError::EthRpcError(EthRpcError::SignerContractError(error))
    }
}
