use alloy_primitives::Address;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvmContract {
    pub address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpotToken {
    pub index: u64,
    #[serde(rename = "evmContract")]
    pub evm_contract: Option<EvmContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpotMeta {
    tokens: Vec<SpotToken>,
}

fn fetch_spot_meta() -> Result<SpotMeta> {
    let url = "https://api.hyperliquid.xyz";
    let url = format!("{}/info", url);
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(url)
        .json(&serde_json::json!({"type": "spotMeta"}))
        .send()?;
    Ok(response.json()?)
}

pub(crate) fn evm_map() -> Result<BTreeMap<Address, Address>> {
    let meta = fetch_spot_meta()?;
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
