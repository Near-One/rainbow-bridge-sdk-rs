use clap::Subcommand;
use near_bridge_client::NearBridgeClientBuilder;
use solana_connector::{SolanaConnector, SolanaConnectorBuilder};
use solana_sdk::signature::Keypair;

use crate::{combined_config, CliConfig, Network};

#[derive(Subcommand, Debug)]
pub enum SolanaConnectorSubCommand {
    Initialize {
        #[clap(short, long)]
        program_keypair: Vec<u8>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    DeployToken {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeTransfer {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[clap(short, long)]
        solana_token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    FinalizeTransferSol {
        #[clap(short, long)]
        transaction_hash: String,
        #[clap(short, long)]
        sender_id: Option<String>,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    LogMetadata {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    InitTransfer {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    InitTransferSol {
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
}

pub async fn match_subcommand(cmd: SolanaConnectorSubCommand, network: Network) {
    match cmd {
        SolanaConnectorSubCommand::Initialize {
            program_keypair,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .initialize(Keypair::from_bytes(&program_keypair).unwrap())
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::DeployToken {
            transaction_hash,
            sender_id,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .deploy_token(
                    transaction_hash.parse().unwrap(),
                    sender_id.map(|id| id.parse().unwrap()),
                )
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::FinalizeTransfer {
            transaction_hash,
            sender_id,
            solana_token,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .finalize_transfer(
                    transaction_hash.parse().unwrap(),
                    solana_token.parse().unwrap(),
                    sender_id.map(|id| id.parse().unwrap()),
                )
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::FinalizeTransferSol { .. } => {}
        SolanaConnectorSubCommand::LogMetadata { token, config_cli } => {
            solana_connector(network, config_cli)
                .log_metadata(token.parse().unwrap())
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::InitTransfer {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .init_transfer(token.parse().unwrap(), amount, recipient)
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::InitTransferSol {
            amount,
            recipient,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .init_transfer_sol(amount, recipient)
                .await
                .unwrap();
        }
    }
}

fn solana_connector(network: Network, cli_config: CliConfig) -> SolanaConnector {
    let combined_config = combined_config(cli_config, network);

    let near_bridge_client = NearBridgeClientBuilder::default()
        .endpoint(combined_config.near_rpc)
        .signer(combined_config.near_signer)
        .build()
        .unwrap();

    SolanaConnectorBuilder::default()
        .endpoint(combined_config.solana_rpc)
        .bridge_address(combined_config.solana_bridge_address)
        .wormhole_address(combined_config.solana_wormhole_address)
        .keypair(combined_config.solana_keypair)
        .near_bridge_client(Some(near_bridge_client))
        .build()
        .unwrap()
}
