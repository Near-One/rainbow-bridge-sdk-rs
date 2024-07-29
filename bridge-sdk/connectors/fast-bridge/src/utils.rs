use ethers::types::U256;
use crate::types::EthAddress;

// The slot number of the storage `mapping(bytes32 => bool) public processedHashes;` in the contract `EthErc20FastBridge.sol`.
const STORAGE_KEY_SLOT: u32 = 302;

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

fn get_transfer_hash(
    token: EthAddress,
    recipient: EthAddress,
    nonce: U256,
    amount: U256,
) -> Vec<u8> {
    let mut be_nonce = [0u8; 32];
    nonce.to_big_endian(&mut be_nonce);
    let mut be_amount = [0u8; 32];
    amount.to_big_endian(&mut be_amount);

    let encoded = [
        token.0.as_slice(),
        recipient.0.as_slice(),
        be_nonce.as_slice(),
        be_amount.as_slice(),
    ]
    .concat();

    keccak256(encoded.as_slice())
        .to_vec()
}

// Retrieve storage key that contains the boolean value indicating whether a specific fast bridge transfer has been processed.
pub fn get_fast_bridge_transfer_storage_key(
    token: EthAddress,
    recipient: EthAddress,
    nonce: U256,
    amount: U256,
) -> [u8; 32] {
    let slot = U256::from(STORAGE_KEY_SLOT);
    let mut be_slot = [0u8; 32];
    slot.to_big_endian(&mut be_slot);

    let encoded_slot_key = [
        get_transfer_hash(token, recipient, nonce, amount).as_slice(),
        be_slot.as_slice(),
    ]
    .concat();

    keccak256(&encoded_slot_key)
}
