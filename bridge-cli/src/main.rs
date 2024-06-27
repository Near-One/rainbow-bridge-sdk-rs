use clap::{Args, Parser, Subcommand, ValueEnum};
use eth_connector_command::EthConnectorSubCommand;
use nep141_connector_command::Nep141ConnectorSubCommand;
use serde::Deserialize;
use std::{env, fs::File, io::BufReader};

mod defaults;
mod eth_connector_command;
mod nep141_connector_command;

#[derive(Args, Debug, Clone, Deserialize)]
struct CliConfig {
    #[arg(long)]
    eth_rpc: Option<String>,
    #[arg(long)]
    eth_chain_id: Option<u64>,
    #[arg(long)]
    near_rpc: Option<String>,
    #[arg(long)]
    near_signer: Option<String>,
    #[arg(long)]
    near_private_key: Option<String>,
    #[arg(long)]
    eth_private_key: Option<String>,
    #[arg(long)]
    token_locker_id: Option<String>,
    #[arg(long)]
    bridge_token_factory_address: Option<String>,
    #[arg(long)]
    near_light_client_eth_address: Option<String>,
    #[arg(long)]
    eth_custodian_address: Option<String>,
    #[arg(long)]
    eth_connector_account_id: Option<String>,
    #[arg(long)]
    config_file: Option<String>,
}

impl CliConfig {
    fn or(self, other: Self) -> Self {
        Self {
            eth_rpc: self.eth_rpc.or(other.eth_rpc),
            eth_chain_id: self.eth_chain_id.or(other.eth_chain_id),
            near_rpc: self.near_rpc.or(other.near_rpc),
            near_signer: self.near_signer.or(other.near_signer),
            near_private_key: self.near_private_key.or(other.near_private_key),
            eth_private_key: self.eth_private_key.or(other.eth_private_key),
            token_locker_id: self.token_locker_id.or(other.token_locker_id),
            bridge_token_factory_address: self
                .bridge_token_factory_address
                .or(other.bridge_token_factory_address),
            near_light_client_eth_address: self
                .near_light_client_eth_address
                .or(other.near_light_client_eth_address),
            eth_custodian_address: self.eth_custodian_address.or(other.eth_custodian_address),
            eth_connector_account_id: self
                .eth_connector_account_id
                .or(other.eth_connector_account_id),
            config_file: self.config_file.or(other.config_file),
        }
    }

    fn empty() -> Self {
        Self {
            eth_rpc: None,
            eth_chain_id: None,
            near_rpc: None,
            near_signer: None,
            near_private_key: None,
            eth_private_key: None,
            token_locker_id: None,
            bridge_token_factory_address: None,
            near_light_client_eth_address: None,
            eth_custodian_address: None,
            eth_connector_account_id: None,
            config_file: None,
        }
    }
}

fn env_config() -> CliConfig {
    CliConfig {
        eth_rpc: env::var("ETH_RPC").ok(),
        eth_chain_id: env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|val| val.parse::<u64>().ok()),
        near_rpc: env::var("NEAR_RPC").ok(),
        near_signer: env::var("NEAR_SIGNER").ok(),
        near_private_key: env::var("NEAR_PRIVATE_KEY").ok(),
        eth_private_key: env::var("ETH_PRIVATE_KEY").ok(),
        token_locker_id: env::var("TOKEN_LOCKER_ID").ok(),
        bridge_token_factory_address: env::var("BRIDGE_TOKEN_FACTORY_ADDRESS").ok(),
        near_light_client_eth_address: env::var("NEAR_LIGHT_CLIENT_ADDRESS").ok(),
        eth_custodian_address: env::var("ETH_CUSTODIAN_ADDRESS").ok(),
        eth_connector_account_id: env::var("ETH_CONNECTOR_ACCOUNT_ID").ok(),
        config_file: None,
    }
}

fn default_config(network: Network) -> CliConfig {
    match network {
        Network::Mainnet => CliConfig {
            eth_rpc: Some(defaults::ETH_RPC_MAINNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_MAINNET),
            near_rpc: Some(defaults::NEAR_RPC_MAINNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            eth_private_key: None,
            token_locker_id: Some(defaults::TOKEN_LOCKER_ID_MAINNET.to_owned()),
            bridge_token_factory_address: Some(
                defaults::BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET.to_owned(),
            ),
            near_light_client_eth_address: Some(
                defaults::NEAR_LIGHT_CLIENT_ETH_ADDRESS_MAINNET.to_owned(),
            ),
            eth_connector_account_id: Some(defaults::ETH_CONNECTOR_ACCOUNT_ID_MAINNET.to_owned()),
            eth_custodian_address: Some(defaults::ETH_CUSTODIAN_ADDRESS_MAINNET.to_owned()),
            config_file: None,
        },
        Network::Testnet => CliConfig {
            eth_rpc: Some(defaults::ETH_RPC_TESTNET.to_owned()),
            eth_chain_id: Some(defaults::ETH_CHAIN_ID_TESTNET),
            near_rpc: Some(defaults::NEAR_RPC_TESTNET.to_owned()),
            near_signer: None,
            near_private_key: None,
            eth_private_key: None,
            token_locker_id: Some(defaults::TOKEN_LOCKER_ID_TESTNET.to_owned()),
            bridge_token_factory_address: Some(
                defaults::BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET.to_owned(),
            ),
            near_light_client_eth_address: Some(
                defaults::NEAR_LIGHT_CLIENT_ETH_ADDRESS_TESTNET.to_owned(),
            ),
            eth_connector_account_id: Some(defaults::ETH_CONNECTOR_ACCOUNT_ID_TESTNET.to_owned()),
            eth_custodian_address: Some(defaults::ETH_CUSTODIAN_ADDRESS_TESTNET.to_owned()),
            config_file: None,
        },
    }
}

fn file_config(path: &str) -> CliConfig {
    let file = File::open(path).expect("Unable to open config file");
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).expect("Unable to parse config file")
}

fn combined_config(cli_config: CliConfig, network: Network) -> CliConfig {
    let file_config = match &cli_config.config_file {
        Some(path) => file_config(path),
        None => CliConfig::empty(),
    };

    cli_config
        .or(env_config())
        .or(file_config)
        .or(default_config(network))
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Nep141Connector {
        #[clap(subcommand)]
        cmd: Nep141ConnectorSubCommand,
    },
    EthConnector {
        #[clap(subcommand)]
        cmd: EthConnectorSubCommand,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum Network {
    Mainnet,
    Testnet,
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    network: Network,
    #[command(subcommand)]
    cmd: SubCommand,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Arguments::parse();

    match args.cmd {
        SubCommand::Nep141Connector { cmd } => {
            nep141_connector_command::match_subcommand(cmd, args.network).await
        }
        SubCommand::EthConnector { cmd } => {
            eth_connector_command::match_subcommand(cmd, args.network).await
        }
    }
}
