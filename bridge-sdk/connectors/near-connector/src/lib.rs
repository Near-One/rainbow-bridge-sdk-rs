#[macro_use]
extern crate derive_builder;

mod near_connector;

pub use near_connector::{NearConnector, NearConnectorBuilder};
