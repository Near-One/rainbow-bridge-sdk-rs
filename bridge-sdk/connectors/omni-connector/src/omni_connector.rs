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
pub struct OmniConnector {
    near_bridge_client: Option<NearBridgeClient>,
    evm_bridge_client: Option<EvmBridgeClient>,
    solana_bridge_client: Option<SolanaBridgeClient>,
}
