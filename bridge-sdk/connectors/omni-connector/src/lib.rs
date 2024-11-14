#[macro_use]
extern crate derive_builder;

mod omni_connector;

pub use omni_connector::{EvmConnector, EvmConnectorBuilder};
