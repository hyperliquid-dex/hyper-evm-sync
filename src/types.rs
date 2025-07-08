use alloy::{
    consensus::constants::KECCAK_EMPTY,
    primitives::{Address, Bytes, Log, B256, U256},
};
use reth_primitives::{Receipt, SealedBlock, Transaction, TxType};
use revm::{
    db::AccountState,
    primitives::{AccountInfo, Bytecode},
    InMemoryDB,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAndReceipts {
    pub block: EvmBlock,
    pub receipts: Vec<LegacyReceipt>,
    #[serde(default)]
    pub system_txs: Vec<SystemTx>,
    #[serde(default)]
    pub read_precompile_calls: Vec<(Address, Vec<(ReadPrecompileInput, ReadPrecompileResult)>)>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct ReadPrecompileInput {
    pub input: Bytes,
    pub gas_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadPrecompileResult {
    Ok { gas_used: u64, bytes: Bytes },
    OutOfGas,
    Error,
    UnexpectedError,
}

#[derive(Deserialize)]
pub struct AbciState {
    exchange: Exchange,
}

#[derive(Deserialize)]
struct Exchange {
    hyper_evm: HyperEvm,
}

#[derive(Deserialize)]
struct HyperEvm {
    state2: EvmState,
    latest_block2: EvmBlock,
}

#[derive(Serialize, Deserialize)]
pub struct EvmState {
    evm_db: EvmDb,
    block_hashes: Vec<(U256, B256)>,
}

#[derive(Serialize, Deserialize)]
enum EvmDb {
    InMemory {
        accounts: Vec<(Address, DbAccount)>,
        contracts: Vec<(B256, Bytecode)>,
    },
}

#[derive(Serialize, Deserialize)]
struct DbAccount {
    #[serde(rename = "i", alias = "info", default)]
    info: DbAccountInfo,
    #[serde(rename = "s", alias = "storage", default)]
    storage: Vec<(U256, U256)>,
}

#[derive(Serialize, Deserialize)]
struct DbAccountInfo {
    #[serde(rename = "b", alias = "balance", default)]
    balance: U256,
    #[serde(rename = "n", alias = "nonce", default)]
    nonce: u64,
    #[serde(rename = "c", alias = "code_hash", default = "keccak_empty")]
    code_hash: B256,
}

impl Default for DbAccountInfo {
    fn default() -> Self {
        Self {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: KECCAK_EMPTY,
        }
    }
}

const fn keccak_empty() -> B256 {
    KECCAK_EMPTY
}

impl AbciState {
    pub fn into_next_block_num_and_in_memory_db(self) -> (u64, InMemoryDB) {
        let HyperEvm {
            state2,
            latest_block2,
        } = self.exchange.hyper_evm;
        let EvmBlock::Reth115(sealed_block) = latest_block2;
        let next_block_num = sealed_block.number;
        (next_block_num, state2.into())
    }
}

impl From<InMemoryDB> for EvmState {
    fn from(db: InMemoryDB) -> EvmState {
        let block_hashes = db.block_hashes.into_iter().collect();
        let accounts = db
            .accounts
            .into_iter()
            .map(|(address, db_account)| {
                let revm::db::DbAccount {
                    info:
                        AccountInfo {
                            balance,
                            nonce,
                            code_hash,
                            ..
                        },
                    storage,
                    ..
                } = db_account;
                (
                    address,
                    DbAccount {
                        info: DbAccountInfo {
                            balance,
                            nonce,
                            code_hash,
                        },
                        storage: storage.into_iter().collect(),
                    },
                )
            })
            .collect();
        let contracts = db.contracts.into_iter().collect();
        let evm_db = EvmDb::InMemory {
            accounts,
            contracts,
        };
        Self {
            evm_db,
            block_hashes,
        }
    }
}

impl From<EvmState> for InMemoryDB {
    fn from(state: EvmState) -> Self {
        let mut res = InMemoryDB::default();
        let EvmState {
            evm_db,
            block_hashes,
        } = state;
        let EvmDb::InMemory {
            accounts,
            contracts,
        } = evm_db;
        res.block_hashes = block_hashes.into_iter().collect();
        res.accounts = accounts
            .into_iter()
            .map(|(address, db_account)| {
                let DbAccount { info, storage } = db_account;
                let DbAccountInfo {
                    balance,
                    nonce,
                    code_hash,
                } = info;
                (
                    address,
                    revm::db::DbAccount {
                        info: AccountInfo {
                            balance,
                            nonce,
                            code_hash,
                            code: None,
                        },
                        account_state: AccountState::Touched,
                        storage: storage.into_iter().collect(),
                    },
                )
            })
            .collect();
        res.contracts = contracts.into_iter().collect();

        res
    }
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

impl From<AbciState> for InMemoryDB {
    fn from(value: AbciState) -> Self {
        let mut res = Self::default();
        let EvmState {
            evm_db,
            block_hashes,
        } = value.exchange.hyper_evm.state2;
        let EvmDb::InMemory {
            accounts,
            contracts,
        } = evm_db;
        res.block_hashes = block_hashes.into_iter().collect();
        res.accounts = accounts
            .into_iter()
            .map(|(address, db_account)| {
                let DbAccount { info, storage } = db_account;
                let DbAccountInfo {
                    balance,
                    nonce,
                    code_hash,
                } = info;
                (
                    address,
                    revm::db::DbAccount {
                        info: AccountInfo {
                            balance,
                            nonce,
                            code_hash,
                            code: None,
                        },
                        account_state: AccountState::Touched,
                        storage: storage.into_iter().collect(),
                    },
                )
            })
            .collect();
        res.contracts = contracts.into_iter().collect();
        res
    }
}
