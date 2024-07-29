use crate::{
    error::EthProofError,
    eth_rpc_client::{
        types::{BlockHeader, Log, StorageProof, TransactionReceipt, U8},
        EthRPCClient,
    },
};
use borsh::BorshSerialize;
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethereum_types::{Address, H256};
use hasher::HasherKeccak;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, BorshSerialize, Serialize, Deserialize)]
pub struct EventProof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, BorshSerialize)]
pub struct StorageSlotProof {
    pub header_data: Vec<u8>,
    pub account_proof: Vec<Vec<u8>>,
    pub account_data: Vec<u8>,
    pub storage_proof: Vec<Vec<u8>>,
}

pub async fn get_storage_proof(
    contract_address: Address,
    storage_key: H256,
    block_number: u64,
    node_url: &str,
) -> Result<StorageSlotProof, EthProofError> {
    let client = EthRPCClient::new(node_url);
    let storage_proof = client.get_proof(contract_address, storage_key, block_number.into()).await?;
    let header = client.get_block_by_number(block_number.into()).await?;

    Ok(StorageSlotProof {
        header_data: encode_header(&header),
        account_data: encode_account(&storage_proof),
        account_proof: storage_proof.account_proof
            .into_iter()
            .map(|b| b.0)
            .collect(),
        storage_proof: storage_proof.storage_proof[0].proof
            .clone()
            .into_iter()
            .map(|b| b.0)
            .collect(),
    })
}

pub async fn get_event_proof(
    tx_hash: H256,
    log_index: u64,
    node_url: &str,
) -> Result<EventProof, EthProofError> {
    let client = EthRPCClient::new(node_url);

    let receipt = client.get_transaction_receipt_by_hash(&tx_hash).await?;
    let block_header = client.get_block_by_number(receipt.block_number).await?;
    let block_receipts = client.get_block_receipts(receipt.block_number).await?;

    let mut trie = build_receipt_trie(&block_receipts)?;
    trie.root()?;

    let receipt_key = rlp::encode(&receipt.transaction_index);
    let proof = trie.get_proof(&receipt_key)?;

    let mut log_data: Option<Vec<u8>> = None;
    let mut log_index_in_receipt = 0;
    for (i, log) in receipt.logs.iter().enumerate() {
        if log.log_index == log_index.into() {
            log_data = Some(encode_log(log));
            log_index_in_receipt = i;
        }
    }

    Ok(EventProof {
        log_index: log_index_in_receipt as u64,
        log_entry_data: log_data.ok_or(EthProofError::Other(
            "Log not found based on the transaction hash and index provided".to_string(),
        ))?,
        receipt_index: receipt.transaction_index.as_u64(),
        receipt_data: encode_receipt(&receipt),
        header_data: encode_header(&block_header),
        proof,
    })
}

fn build_receipt_trie(
    receipts: &[TransactionReceipt],
) -> Result<PatriciaTrie<MemoryDB, HasherKeccak>, EthProofError> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(memdb, hasher);

    for receipt in receipts {
        let receipt_key = rlp::encode(&receipt.transaction_index).to_vec();
        let receipt_data = encode_receipt(receipt);

        trie.insert(receipt_key, receipt_data)?;
    }

    Ok(trie)
}

fn encode_receipt(receipt: &TransactionReceipt) -> Vec<u8> {
    let mut stream = RlpStream::new();

    if receipt.transaction_type != U8(0) {
        stream.append(&receipt.transaction_type);
    }

    stream.begin_list(4);
    stream
        .append(&receipt.status)
        .append(&receipt.cumulative_gas_used)
        .append(&receipt.logs_bloom);

    stream.begin_list(receipt.logs.len());
    for log in &receipt.logs {
        stream.begin_list(3);
        stream.append(&log.address);

        stream.begin_list(log.topics.len());
        for topic in &log.topics {
            stream.append(topic);
        }

        stream.append(&log.data);
    }

    stream.out().to_vec()
}

fn encode_log(log: &Log) -> Vec<u8> {
    let mut stream = RlpStream::new();
    stream.begin_list(3);

    stream.append(&log.address);

    stream.begin_list(log.topics.len());
    for topic in &log.topics {
        stream.append(topic);
    }

    stream.append(&log.data);

    stream.out().to_vec()
}

fn encode_header(header: &BlockHeader) -> Vec<u8> {
    let mut stream = RlpStream::new();
    stream.begin_unbounded_list();

    stream
        .append(&header.parent_hash)
        .append(&header.sha3_uncles)
        .append(&header.miner)
        .append(&header.state_root)
        .append(&header.transactions_root)
        .append(&header.receipts_root)
        .append(&header.logs_bloom)
        .append(&header.difficulty)
        .append(&header.number)
        .append(&header.gas_limit)
        .append(&header.gas_used)
        .append(&header.timestamp)
        .append(&header.extra_data)
        .append(&header.mix_hash)
        .append(&header.nonce);

    header.base_fee_per_gas.map(|v| stream.append(&v));
    header.withdrawals_root.as_ref().map(|v| stream.append(v));
    header.blob_gas_used.map(|v| stream.append(&v));
    header.excess_blob_gas.map(|v| stream.append(&v));
    header
        .parent_beacon_block_root
        .as_ref()
        .map(|v| stream.append(v));

    stream.finalize_unbounded_list();
    stream.out().to_vec()
}

fn encode_account(account: &StorageProof) -> Vec<u8> {
    let mut stream = RlpStream::new();
    stream.begin_list(4);

    stream.append(&account.nonce);
    stream.append(&account.balance);
    stream.append(&account.storage_hash);
    stream.append(&account.code_hash);

    stream.out().to_vec()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use hasher::Hasher;
    use serde_json::Value;
    use std::path::PathBuf;
    use std::{fs, str::FromStr};

    const RPC_URL: &str = "https://eth.llamarpc.com";
    const RPC_WITH_STORAGE_PROOF_URL: &str = "https://ethereum-sepolia.blockpi.network/v1/rpc/public";

    /*
     * Test data format:
     * log_index - index of the log within transaction receipt (can be obtained from ETH RPC)
     * receipt_index - index of the transaction receipt within the block (can be obtained from ETH RPC)
     * block_hash - hash of the block containing the transaction
     * receipt - RLP encoded transaction receipt (can be generated using other libraries, like eth-object.js)
     * log - RLP encoded log entry (can be generated using other libraries, like eth-object.js)
     * proof - merkle proof that receipt is part of the block receipt trie. To get the proof, first create a Merkle-Patricia tree including
     *   all RLP encoded transaction receipts of the block. The root of the tree must be the same as the receiptsRoot field of the block header.
     *   Then calculate merkle proof. One can use merkle-patricia-tree.js to build and generate the proof for the tree.
     */

    #[tokio::test]
    async fn generate_event_proof_pre_shapella() {
        let tx_hash =
            H256::from_str("0xc4a6c5cde1d243b26b013f805f71f6de91536f66c993abfee746f373203b68cc")
                .unwrap();
        let proof = get_event_proof(tx_hash, 251, RPC_URL).await.unwrap();
        verify_event_proof(proof, "pre_shapella_proof.json");
    }

    #[tokio::test]
    async fn generate_event_proof_post_shapella() {
        let tx_hash =
            H256::from_str("0xd6ae351d6946f98c4b63589e2154db668e703e8c09fbd4e5c6807b5d356453c3")
                .unwrap();
        let proof = get_event_proof(tx_hash, 172, RPC_URL).await.unwrap();
        verify_event_proof(proof, "post_shapella_proof.json");
    }

    #[tokio::test]
    async fn generate_event_proof_post_dencun() {
        let tx_hash =
            H256::from_str("0x42639810a1238a76ca947b848f5b88a854ac36471d1c4f6a15631393790f89af")
                .unwrap();
        let proof = get_event_proof(tx_hash, 360, RPC_URL).await.unwrap();
        verify_event_proof(proof, "post_dencun_proof.json");
    }

    #[tokio::test]
    async fn generate_storage_proof() {
        let contract_address = Address::from_str("0x0B2C4871C9bAD795746C05c1539A8B1f26c26357").unwrap();
        let slot = H256::from_str("504ba9bf6f3d94319f952eb234e16252edc14dd40394e9610a36b904ce989c69").unwrap();
        let block_number = 6327228;

        let proof = get_storage_proof(contract_address, slot, block_number, RPC_WITH_STORAGE_PROOF_URL).await.unwrap();
        verify_storage_proof(proof, "storage_proof.json");
    }

    fn read_event_proof_data(file_name: &str) -> (u64, u64, String, String, String, Vec<String>) {
        let mut data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        data_dir.push("src/test_data");
        data_dir.push(file_name);

        let data = fs::read_to_string(data_dir).unwrap();
        let obj: Value = serde_json::from_str(&data).unwrap();

        let expected_log_index = obj["log_index"].as_u64().unwrap();
        let expected_receipt_index = obj["receipt_index"].as_u64().unwrap();
        let expected_header = obj["block_hash"].as_str().unwrap().into();
        let expected_receipt = obj["receipt"].as_str().unwrap().into();
        let expected_log = obj["log"].as_str().unwrap().into();
        let expected_proof = obj["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect::<Vec<String>>();

        (
            expected_log_index,
            expected_receipt_index,
            expected_header,
            expected_receipt,
            expected_log,
            expected_proof,
        )
    }

    fn verify_event_proof(proof: EventProof, test_file: &str) {
        let (
            expected_log_index,
            expected_receipt_index,
            expected_header,
            expected_receipt,
            expected_log,
            expected_proof,
        ) = read_event_proof_data(test_file);

        let hasher = HasherKeccak::new();
        assert_eq!(
            hasher.digest(&proof.header_data),
            hex::decode(expected_header).unwrap()
        );

        assert_eq!(proof.log_index, expected_log_index);
        assert_eq!(proof.receipt_index, expected_receipt_index);
        assert_eq!(proof.receipt_data, hex::decode(expected_receipt).unwrap());
        assert_eq!(proof.log_entry_data, hex::decode(expected_log).unwrap());
        assert_eq!(proof.proof.len(), expected_proof.len());
        assert!(proof
            .proof
            .into_iter()
            .eq(expected_proof.iter().map(|x| hex::decode(x).unwrap())));
    }

    fn read_storage_proof_data(file_name: &str) -> (String, String, Vec<String>, Vec<String>) {
        let mut data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        data_dir.push("src/test_data");
        data_dir.push(file_name);

        let data = fs::read_to_string(data_dir).unwrap();
        let obj: Value = serde_json::from_str(&data).unwrap();
        
        let expected_header = obj["header_data"].as_str().unwrap().into();
        let expected_account = obj["account_data"].as_str().unwrap().into();
        let expected_account_proof = obj["account_proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect::<Vec<String>>();
        let expected_storage_proof = obj["storage_proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect::<Vec<String>>();

        (
            expected_header,
            expected_account,
            expected_account_proof,
            expected_storage_proof,
        )
    }

    fn verify_storage_proof(proof: StorageSlotProof, test_file: &str) {
        let (
            expected_header,
            expected_account,
            expected_account_proof,
            expected_storage_proof,
        ) = read_storage_proof_data(test_file);

        assert_eq!(proof.header_data, hex::decode(expected_header).unwrap());
        assert_eq!(proof.account_data, hex::decode(expected_account).unwrap());
        
        assert_eq!(proof.account_proof.len(), expected_account_proof.len());
        assert!(proof
            .account_proof
            .into_iter()
            .eq(expected_account_proof.iter().map(|x| hex::decode(x).unwrap())));

        assert_eq!(proof.storage_proof.len(), expected_storage_proof.len());
        assert!(proof
            .storage_proof
            .into_iter()
            .eq(expected_storage_proof.iter().map(|x| hex::decode(x).unwrap())));
    }
}
