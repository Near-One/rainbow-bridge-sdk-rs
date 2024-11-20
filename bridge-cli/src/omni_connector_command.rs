use crate::{combined_config, CliConfig, Network};
use clap::Subcommand;
use ethers_core::types::TxHash;
use evm_connector::{EvmConnector, EvmConnectorBuilder};
use near_connector::NearConnectorBuilder;
use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::{
    locker_args::{BindTokenArgs, FinTransferArgs},
    ChainKind, Fee,
};
use std::str::FromStr;

#[derive(Subcommand, Debug)]
pub enum OmniConnectorSubCommand {
    LogMetadata {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    StorageDeposit {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmDeployToken {
        #[clap(short, long)]
        tx_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearInitTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        receiver: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmFinTransfer {
        #[clap(short, long)]
        tx_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    EvmInitTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        receiver: String,
        #[clap(short, long)]
        fee: u128,
        #[clap(short, long)]
        native_fee: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearFinTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        receiver: String,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    SignTransfer {
        #[clap(short, long)]
        nonce: u64,
        #[clap(short, long)]
        fee: u128,
        #[clap(long)]
        native_fee: u128,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    BindTokenEvm {
        #[clap(short, long)]
        tx_hash: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    BindTokenWormhole {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    NearDeployToken {
        #[clap(short, long)]
        source_chain_id: u8,
        #[clap(short, long)]
        vaa: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: OmniConnectorSubCommand, network: Network) {
    match cmd {
        OmniConnectorSubCommand::LogMetadata { token, config_cli } => {
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .log_token_metadata(token)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::StorageDeposit {
            token,
            amount,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .storage_deposit_for_token(token, amount)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmDeployToken {
            tx_hash,
            sender_id,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .deploy_token(
                    CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    sender_id.map(|id| AccountId::from_str(&id).expect("Invalid sender_id")),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearInitTransfer {
            token,
            amount,
            receiver,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .init_transfer(token, amount, receiver)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::SignTransfer {
            nonce,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .sign_transfer(
                    nonce,
                    None,
                    Some(Fee {
                        fee: fee.into(),
                        native_fee: native_fee.into(),
                    }),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmFinTransfer {
            tx_hash,
            sender_id,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .fin_transfer(
                    CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),
                    sender_id.map(|id| AccountId::from_str(&id).expect("Invalid sender_id")),
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::EvmInitTransfer {
            token,
            amount,
            receiver,
            fee,
            native_fee,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .init_transfer(
                    token,
                    amount,
                    receiver,
                    Fee {
                        fee: fee.into(),
                        native_fee: native_fee.into(),
                    },
                )
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearDeployToken {
            source_chain_id,
            vaa,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .deploy_token(ChainKind::try_from(source_chain_id).unwrap(), &vaa)
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::NearFinTransfer {
            token,
            source_chain_id,
            receiver,
            vaa,
            config_cli,
        } => {
            let args = omni_types::prover_args::WormholeVerifyProofArgs {
                proof_kind: omni_types::prover_result::ProofKind::InitTransfer,
                vaa,
            };
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .fin_transfer(FinTransferArgs {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    storage_deposit_args: omni_types::locker_args::StorageDepositArgs {
                        token: AccountId::from_str(&token).unwrap(),
                        accounts: vec![(AccountId::from_str(&receiver).unwrap(), true)],
                    },
                    prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                })
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BindTokenEvm {
            tx_hash,
            config_cli,
        } => {
            omni_connector(network, config_cli)
                .bind_token_with_eth_prover(TxHash::from_str(&tx_hash).expect("Invalid tx_hash"))
                .await
                .unwrap();
        }
        OmniConnectorSubCommand::BindTokenWormhole {
            source_chain_id,
            vaa,
            config_cli,
        } => {
            let args = omni_types::prover_args::WormholeVerifyProofArgs {
                proof_kind: omni_types::prover_result::ProofKind::DeployToken,
                vaa,
            };
            omni_connector(network, config_cli)
                .near_connector()
                .unwrap()
                .bind_token(BindTokenArgs {
                    chain_kind: ChainKind::try_from(source_chain_id).unwrap(),
                    prover_args: near_primitives::borsh::to_vec(&args).unwrap(),
                })
                .await
                .unwrap();
        }
    }
}

fn omni_connector(network: Network, cli_config: CliConfig) -> EvmConnector {
    let combined_config = combined_config(cli_config, network);

    let near_connector = NearConnectorBuilder::default()
        .endpoint(combined_config.near_rpc)
        .private_key(combined_config.near_private_key)
        .signer(combined_config.near_signer)
        .token_locker_id(combined_config.near_token_locker_id)
        .build()
        .unwrap();

    EvmConnectorBuilder::default()
        .endpoint(combined_config.eth_rpc)
        .chain_id(combined_config.eth_chain_id)
        .private_key(combined_config.eth_private_key)
        .bridge_token_factory_address(combined_config.bridge_token_factory_address)
        .near_connector(Some(near_connector))
        .build()
        .unwrap()
}
