use clap::Subcommand;
use near_connector::NearConnectorBuilder;
use solana_connector::{SolanaConnector, SolanaConnectorBuilder};

use crate::{combined_config, CliConfig, Network};

#[derive(Subcommand, Debug)]
pub enum SolanaConnectorSubCommand {
    Initialize {
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
        #[command(flatten)]
        config_cli: CliConfig,
    },
    RegisterToken {
        #[clap(short, long)]
        token: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    InitTransferNative {
        #[clap(short, long)]
        token: String,
        #[clap(short, long)]
        amount: u128,
        #[clap(short, long)]
        recipient: String,
        #[command(flatten)]
        config_cli: CliConfig,
    },
    InitTransferBridged {
        #[clap(short, long)]
        token: String,
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
        SolanaConnectorSubCommand::Initialize { config_cli } => {
            solana_connector(network, config_cli)
                .initialize()
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
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .finalize_transfer(
                    transaction_hash.parse().unwrap(),
                    sender_id.map(|id| id.parse().unwrap()),
                )
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::RegisterToken { token, config_cli } => {
            solana_connector(network, config_cli)
                .register_token(token.parse().unwrap())
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::InitTransferNative {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .init_transfer_native(token.parse().unwrap(), amount, recipient)
                .await
                .unwrap();
        }
        SolanaConnectorSubCommand::InitTransferBridged {
            token,
            amount,
            recipient,
            config_cli,
        } => {
            solana_connector(network, config_cli)
                .init_transfer_bridged(token, amount, recipient)
                .await
                .unwrap();
        }
    }
}

fn solana_connector(network: Network, cli_config: CliConfig) -> SolanaConnector {
    let combined_config = combined_config(cli_config, network);

    let near_connector = NearConnectorBuilder::default()
        .endpoint(combined_config.near_rpc)
        .signer(combined_config.near_signer)
        .build()
        .unwrap();

    SolanaConnectorBuilder::default()
        .endpoint(combined_config.solana_rpc)
        .bridge_address(combined_config.solana_bridge_address)
        .wormhole_address(combined_config.solana_wormhole_address)
        .keypair(combined_config.solana_keypair)
        .near_connector(Some(near_connector))
        .build()
        .unwrap()
}
