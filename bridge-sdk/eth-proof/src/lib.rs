mod error;
mod eth_rpc_client;
mod proof_generator;

pub use error::EthProofError;
pub use eth_rpc_client::EthClientError;
pub use proof_generator::get_proof_for_event;
pub use proof_generator::get_proof_for_event_with_log_index;
