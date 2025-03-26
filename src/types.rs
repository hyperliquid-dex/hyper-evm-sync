use alloy_consensus::TxType;
use alloy_primitives::Log;
use reth_primitives::{Receipt, SealedBlock, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAndReceipts {
    pub block: EvmBlock,
    pub receipts: Vec<LegacyReceipt>,
    #[serde(default)]
    pub system_txs: Vec<SystemTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmBlock {
    Reth115(SealedBlock),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyReceipt {
    tx_type: LegacyTxType,
    success: bool,
    cumulative_gas_used: u64,
    logs: Vec<Log>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum LegacyTxType {
    Legacy = 0,
    Eip2930 = 1,
    Eip1559 = 2,
    Eip4844 = 3,
    Eip7702 = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemTx {
    pub tx: Transaction,
    pub receipt: Option<LegacyReceipt>,
}

impl From<LegacyReceipt> for Receipt {
    fn from(value: LegacyReceipt) -> Self {
        let LegacyReceipt {
            tx_type,
            success,
            cumulative_gas_used,
            logs,
        } = value;
        let tx_type = match tx_type {
            LegacyTxType::Legacy => TxType::Legacy,
            LegacyTxType::Eip2930 => TxType::Eip2930,
            LegacyTxType::Eip1559 => TxType::Eip1559,
            LegacyTxType::Eip4844 => TxType::Eip4844,
            LegacyTxType::Eip7702 => TxType::Eip7702,
        };
        Self {
            tx_type,
            success,
            cumulative_gas_used,
            logs,
        }
    }
}
