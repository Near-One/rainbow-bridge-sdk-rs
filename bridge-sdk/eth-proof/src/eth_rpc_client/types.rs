use ethereum_types::{Address, Bloom, H256, U128, U256, U64};
use rlp::{Encodable, RlpStream};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Bytes(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub struct U8(pub u8);

impl Encodable for U8 {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s);
    }
}

impl Encodable for Bytes {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s);
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub sha3_uncles: H256,
    pub miner: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: U128,
    pub number: Bytes,
    pub gas_limit: Bytes,
    pub gas_used: Bytes,
    pub timestamp: Bytes,
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: Bytes,
    pub base_fee_per_gas: Option<U64>,
    pub withdrawals_root: Option<H256>,
    pub blob_gas_used: Option<U64>,
    pub excess_blob_gas: Option<U64>,
    pub parent_beacon_block_root: Option<H256>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
    pub log_index: U64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub block_number: U64,
    pub transaction_index: U64,
    #[serde(rename = "type")]
    pub transaction_type: U8,
    pub cumulative_gas_used: Bytes,
    pub logs_bloom: Bloom,
    pub logs: Vec<Log>,
    pub status: U8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageEntryProof {
    pub key: H256,
    pub value: Bytes,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    pub address: Address,
    pub balance: U256,
    pub nonce: U64,
    pub storage_hash: H256,
    pub code_hash: H256,
    pub storage_proof: Vec<StorageEntryProof>,
    pub account_proof: Vec<Bytes>,
}
