#[macro_use]
extern crate derive_builder;

mod evm_connector;

pub use evm_connector::{EvmConnector, EvmConnectorBuilder};
