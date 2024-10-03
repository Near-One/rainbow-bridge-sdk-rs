use crate::error::NearRpcError;
use crate::light_client_proof::LightClientExecutionProof;
use lazy_static::lazy_static;
use near_jsonrpc_client::{methods, JsonRpcClient, JsonRpcClientConnector};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{FinalExecutionOutcomeView, QueryRequest};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use tokio::time;

pub const DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC: u64 = 500;

lazy_static! {
    static ref DEFAULT_CONNECTOR: JsonRpcClientConnector = JsonRpcClient::with(
        new_near_rpc_client(Some(std::time::Duration::from_secs(30)))
    );
}

fn new_near_rpc_client(timeout: Option<std::time::Duration>) -> reqwest::Client {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let mut builder = reqwest::Client::builder().default_headers(headers);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout).connect_timeout(timeout);
    }
    builder.build().unwrap()
}

pub async fn view(
    server_addr: &str,
    contract_account_id: AccountId,
    method_name: String,
    args: serde_json::Value,
) -> Result<Vec<u8>, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: contract_account_id,
            method_name,
            args: FunctionArgs::from(args.to_string().into_bytes()),
        },
    };

    let response = client.call(request).await?;
    if let QueryResponseKind::CallResult(result) = response.kind {
        Ok(result.result)
    } else {
        Err(NearRpcError::ResultError)
    }
}

pub async fn get_light_client_proof(
    server_addr: &str,
    id: near_primitives::types::TransactionOrReceiptId,
    light_client_head: CryptoHash,
) -> Result<LightClientExecutionProof, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);

    let request =
        near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id,
            light_client_head,
        };

    Ok(client.call(request).await?.into())
}

pub async fn get_final_block_timestamp(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::Finality(Finality::Final),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.timestamp)
}

pub async fn get_last_near_block_height(server_addr: &str) -> Result<u64, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest {
        block_reference: BlockReference::latest(),
    };

    let block_info = client.call(request).await?;
    Ok(block_info.header.height as u64)
}

pub async fn get_block(
    server_addr: &str,
    block_reference: BlockReference,
) -> Result<near_primitives::views::BlockView, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let request = methods::block::RpcBlockRequest { block_reference };
    let block_info = client.call(request).await?;
    Ok(block_info)
}

pub async fn change(
    server_addr: &str,
    signer: near_crypto::InMemorySigner,
    receiver_id: String,
    method_name: String,
    args: Vec<u8>,
    gas: u64,
    deposit: u128,
) -> Result<CryptoHash, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let rpc_request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::latest(),
        request: near_primitives::views::QueryRequest::ViewAccessKey {
            account_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
        },
    };
    let access_key_query_response = client.call(rpc_request).await?;

    let current_nonce = match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => access_key.nonce,
        _ => Err(NearRpcError::NonceError)?,
    };
    let transaction = Transaction {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: current_nonce + 1,
        receiver_id: receiver_id.parse().unwrap(),
        block_hash: access_key_query_response.block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name,
            args,
            gas,
            deposit,
        }))],
    };
    let request = methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
        signed_transaction: transaction.sign(&signer),
    };

    Ok(client.call(request).await?)
}

pub async fn change_and_wait_for_outcome(
    server_addr: &str,
    signer: near_crypto::InMemorySigner,
    receiver_id: String,
    method_name: String,
    args: serde_json::Value,
    gas: u64,
    deposit: u128,
) -> Result<FinalExecutionOutcomeView, NearRpcError> {
    let tx_hash = change(
        server_addr,
        signer.clone(),
        receiver_id,
        method_name,
        args.to_string().into_bytes(),
        gas,
        deposit,
    )
    .await?;

    wait_for_tx_final_outcome(
        tx_hash,
        signer.account_id,
        server_addr,
        DEFAULT_WAIT_FINAL_OUTCOME_TIMEOUT_SEC,
    )
    .await
}

pub async fn wait_for_tx_final_outcome(
    hash: CryptoHash,
    account_id: AccountId,
    server_addr: &str,
    timeout_sec: u64,
) -> Result<FinalExecutionOutcomeView, NearRpcError> {
    let client = DEFAULT_CONNECTOR.connect(server_addr);
    let sent_at = time::Instant::now();
    let tx_info = TransactionInfo::TransactionId {
        tx_hash: hash,
        sender_account_id: account_id,
    };

    loop {
        let response = client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: tx_info.clone(),
                wait_until: near_primitives::views::TxExecutionStatus::Executed,
            })
            .await;

        let delta = (time::Instant::now() - sent_at).as_secs();
        if delta > timeout_sec {
            Err(NearRpcError::FinalizationError)?;
        }

        match response {
            Err(err) => match err.handler_error() {
                Some(_err) => {
                    time::sleep(time::Duration::from_secs(2)).await;
                    continue;
                }
                _ => Err(NearRpcError::RpcTransactionError(err))?,
            },
            Ok(response) => match response.final_execution_outcome {
                None => {
                    time::sleep(time::Duration::from_secs(2)).await;
                    continue;
                }
                Some(outcome) => return Ok(outcome.into_outcome()),
            },
        }
    }
}
