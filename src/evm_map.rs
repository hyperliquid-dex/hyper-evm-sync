use crate::run::{MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};
use alloy::primitives::Address;
use anyhow::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvmContract {
    address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpotToken {
    index: u64,
    #[serde(rename = "evmContract")]
    evm_contract: Option<EvmContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpotMeta {
    tokens: Vec<SpotToken>,
}

fn fetch_spot_meta(chain_id: u64) -> Result<SpotMeta> {
    let url = match chain_id {
        MAINNET_CHAIN_ID => "https://api.hyperliquid.xyz/info",
        TESTNET_CHAIN_ID => "https://api.hyperliquid-testnet.xyz/info",
        _ => return Err(Error::msg("unknown chain id")),
    };
    let client = reqwest::blocking::Client::new();
    let response = client.post(url).json(&serde_json::json!({"type": "spotMeta"})).send()?;
    Ok(response.json()?)
}

pub fn erc20_contract_to_system_address(chain_id: u64) -> Result<BTreeMap<Address, Address>> {
    let meta = fetch_spot_meta(chain_id)?;
    let mut map = BTreeMap::new();
    for token in &meta.tokens {
        if let Some(evm_contract) = &token.evm_contract {
            let mut addr = [0u8; 20];
            addr[0] = 0x20;
            addr[12..20].copy_from_slice(token.index.to_be_bytes().as_ref());
            let addr = Address::from_slice(&addr);

            map.insert(evm_contract.address, addr);
        }
    }
    Ok(map)
}
