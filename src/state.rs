use alloy::{
    consensus::constants::KECCAK_EMPTY,
    primitives::{address, keccak256, Address, Bytes, B256, U256},
};
use itertools::Itertools;
use revm::{
    db::AccountState,
    primitives::{Account, AccountInfo, Bytecode, HashMap},
    Database, DatabaseCommit, DatabaseRef, InMemoryDB,
};

pub trait State: Database + DatabaseRef {
    fn genesis() -> Self;
    fn commit(&mut self, changes: HashMap<Address, Account>);
    fn insert_block_hash(&mut self, block_num: u64, hash: B256);
    fn inject_contract(&mut self, contract_address: Address, deployed_bytecode: Bytes);
    fn insert_storage(&mut self, address: Address, key: U256, value: U256);
    fn blake3_hash_slow(&self) -> StateHash;
}

#[derive(Debug, PartialEq)]
pub struct StateHash {
    pub accounts_hash: B256,
    pub contracts_hash: B256,
    pub storage_hash: B256,
    pub block_hashes_hash: B256,
}

impl State for InMemoryDB {
    fn genesis() -> Self {
        let mut state = Self::default();
        state.insert_account_info(
            address!("0x2222222222222222222222222222222222222222"),
            AccountInfo {
                balance: U256::from(10u128.pow(27)),
                nonce: 0,
                code_hash: B256::default(),
                code: Option::default(),
            },
        );
        state
    }

    fn commit(&mut self, changes: HashMap<Address, Account>) {
        DatabaseCommit::commit(self, changes);
    }

    fn insert_block_hash(&mut self, block_num: u64, hash: B256) {
        self.block_hashes.insert(U256::from(block_num), hash);
    }

    fn inject_contract(&mut self, contract_address: Address, deployed_bytecode: Bytes) {
        let bytecode_hash = keccak256(&deployed_bytecode);
        let account = self.accounts.entry(contract_address).or_default();
        let bytecode = Bytecode::new_raw(deployed_bytecode);
        account.info.code_hash = bytecode.hash_slow();
        account.info.code = Some(bytecode.clone());
        account.storage.clear();
        account.account_state = AccountState::StorageCleared;
        self.contracts.insert(bytecode_hash, bytecode);
    }

    fn insert_storage(&mut self, address: Address, key: U256, value: U256) {
        self.accounts.entry(address).or_default().storage.insert(key, value);
    }

    fn blake3_hash_slow(&self) -> StateHash {
        let mut hasher = blake3::Hasher::new();
        for (address, db_account) in self.accounts.iter().sorted_by_key(|(address, _)| **address) {
            let AccountInfo { balance, nonce, code_hash, code: _ } = db_account.info;
            if balance.is_zero() && nonce == 0 && code_hash == KECCAK_EMPTY {
                continue;
            }
            let mut res = [0; 72];
            res[0..32].copy_from_slice(&balance.to_be_bytes::<32>());
            res[32..40].copy_from_slice(&nonce.to_be_bytes());
            res[40..72].copy_from_slice(code_hash.as_slice());
            hasher.update(address.as_slice());
            hasher.update(&res);
        }
        let accounts_hash = hasher.finalize().as_bytes().into();

        let mut hasher = blake3::Hasher::new();
        for code_hash in self.contracts.keys().sorted() {
            hasher.update(code_hash.as_slice());
        }
        let contracts_hash = hasher.finalize().as_bytes().into();

        let mut hasher = blake3::Hasher::new();
        for (address, db_account) in self.accounts.iter().sorted_by_key(|(address, _)| **address) {
            if db_account.storage.is_empty() {
                continue;
            }
            if db_account.storage.values().all(U256::is_zero) {
                continue;
            }
            hasher.update(address.as_slice());
            for (&key, value) in db_account.storage.iter().sorted_by_key(|(key, _)| **key) {
                if value.is_zero() {
                    continue;
                }
                hasher.update(B256::from(key).as_slice());
                hasher.update(&value.to_be_bytes::<32>());
            }
        }
        let storage_hash = hasher.finalize().as_bytes().into();

        // Note: this hash may change depending on how block_hashes is pruned
        let mut hasher = blake3::Hasher::new();
        for (block_num, block_hash) in self.block_hashes.iter().sorted_by_key(|(key, _)| **key) {
            hasher.update(&block_num.to_be_bytes::<32>());
            hasher.update(block_hash.as_slice());
        }
        let block_hashes_hash = hasher.finalize().as_bytes().into();

        StateHash { accounts_hash, contracts_hash, storage_hash, block_hashes_hash }
    }
}
