use borsh::BorshSerialize;
use ethers::types::Address;
use hex::FromHex;
use near_primitives::types::AccountId;
use serde::Deserialize;

#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq)]
pub struct NearU128(pub u128);

impl<'de> Deserialize<'de> for NearU128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let result = s.parse::<u128>().map_err(|err| serde::de::Error::custom(err.to_string()))?;
        Ok(NearU128(result))
    }
}

#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq)]
pub struct EthAddress(pub [u8; 20]);

impl<'de> Deserialize<'de> for EthAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let mut s = <String as Deserialize>::deserialize(deserializer)?;
        if s.starts_with("0x") {
            s = s[2..].to_string();
        }
        let result = Vec::from_hex(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
        Ok(EthAddress(result.try_into().unwrap()))
    }
}

impl From<Address> for EthAddress {
    fn from(address: Address) -> EthAddress {
        EthAddress(address.0)
    }
}

impl Into<Address> for EthAddress {
    fn into(self) -> Address {
        Address::from_slice(&self.0)
    }
}

#[derive(BorshSerialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferDataEthereum {
    pub token_near: AccountId,
    pub token_eth: EthAddress,
    pub amount: NearU128,
}

#[derive(BorshSerialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferDataNear {
    pub token: AccountId,
    pub amount: NearU128,
}

#[derive(BorshSerialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferMessage {
    pub valid_till: u64,
    pub transfer: TransferDataEthereum,
    pub fee: TransferDataNear,
    pub recipient: EthAddress,
    pub valid_till_block_height: Option<u64>,
    pub aurora_sender: Option<EthAddress>,
}