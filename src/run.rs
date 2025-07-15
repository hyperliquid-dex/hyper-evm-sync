use crate::{
    precompile::set_replay_precompiles,
    state::{State, StateHash},
    types::{BlockAndReceipts, EvmBlock, ReadPrecompileInput, ReadPrecompileResult, SystemTx},
};
use alloy::{
    consensus::Transaction as _,
    primitives::{address, bytes, Address, Bytes, B256, U160, U256},
};
use reth_primitives::{transaction::SignedTransactionIntoRecoveredExt, Receipt, SealedBlock, Transaction};
use revm::{
    primitives::{
        Account, BlobExcessGasAndPrice, BlockEnv, CfgEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, HandlerCfg, HashMap,
        ResultAndState, SpecId, TxEnv,
    },
    Database, Evm,
};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

fn deploy_system_contract<S: State>(state: &mut S, contract_address: Address, deployed_bytecode: Bytes) {
    state.inject_contract(contract_address, deployed_bytecode);

    if contract_address == WHYPE_CONTRACT_ADDRESS {
        for (slot, value) in
            [const { encode_short_string("Wrapped HYPE") }, const { encode_short_string("WHYPE") }, U256::from(18)]
                .into_iter()
                .enumerate()
        {
            state.insert_storage(contract_address, U256::from(slot), value);
        }
    }
}

fn fix_mainnet_state_diff(
    block_number: u64,
    tx_index: usize,
    is_system_tx: bool,
    changes: &mut HashMap<Address, Account>,
) {
    // Improper self destructs
    for (block_num, idx, is_system, address) in [
        (1_467_569, 0, false, address!("0x33f6fe38c55cb100ce27b3138e5d2d041648364f")),
        (1_467_631, 0, false, address!("0x33f6fe38c55cb100ce27b3138e5d2d041648364f")),
        (1_499_313, 2, false, address!("0xe27bfc0a812b38927ff646f24af9149f45deb550")),
        (1_499_406, 0, false, address!("0xe27bfc0a812b38927ff646f24af9149f45deb550")),
        (1_499_685, 0, false, address!("0xfee3932b75a87e86930668a6ab3ed43b404c8a30")),
        (1_514_843, 0, false, address!("0x723e5fbbeed025772a91240fd0956a866a41a603")),
        (1_514_936, 0, false, address!("0x723e5fbbeed025772a91240fd0956a866a41a603")),
        (1_530_529, 2, false, address!("0xa694e8fd8f4a177dd23636d838e9f1fb2138d87a")),
        (1_530_622, 2, false, address!("0xa694e8fd8f4a177dd23636d838e9f1fb2138d87a")),
        (1_530_684, 3, false, address!("0xa694e8fd8f4a177dd23636d838e9f1fb2138d87a")),
        (1_530_777, 3, false, address!("0xa694e8fd8f4a177dd23636d838e9f1fb2138d87a")),
        (1_530_839, 2, false, address!("0x692a343fc401a7755f8fc2facf61af426adaf061")),
        (1_530_901, 0, false, address!("0xfd9716f16596715ce765dabaee11787870e04b8a")),
        (1_530_994, 3, false, address!("0xfd9716f16596715ce765dabaee11787870e04b8a")),
        (1_531_056, 4, false, address!("0xdc67c2b8349ca20f58760e08371fc9271e82b5a4")),
        (1_531_149, 0, false, address!("0xdc67c2b8349ca20f58760e08371fc9271e82b5a4")),
        (1_531_211, 3, false, address!("0xdc67c2b8349ca20f58760e08371fc9271e82b5a4")),
        (1_531_366, 1, false, address!("0x9a90a517d27a9e60e454c96fefbbe94ff244ed6f")),
    ] {
        if block_number == block_num && tx_index == idx && is_system_tx == is_system {
            changes.remove(&address);
        }
    }
}

struct ApplyTxArgs<'a, S> {
    chain_id: u64,
    block: &'a SealedBlock,
    precompile_results: &'a Arc<HashMap<Address, Arc<HashMap<ReadPrecompileInput, ReadPrecompileResult>>>>,
    sender: Address,
    transaction: &'a Transaction,
    tx_index: usize,
    is_system_tx: bool,
    cumulative_gas_used: u64,
    db: &'a mut S,
}

fn apply_tx<S>(args: ApplyTxArgs<S>) -> Receipt
where
    S: State,
    <S as Database>::Error: std::fmt::Debug,
{
    let ApplyTxArgs {
        chain_id,
        block,
        precompile_results,
        sender,
        transaction,
        tx_index,
        is_system_tx,
        mut cumulative_gas_used,
        mut db,
    } = args;
    let mut cfg = CfgEnvWithHandlerCfg::new(CfgEnv::default().with_chain_id(chain_id), HandlerCfg::new(SpecId::CANCUN));
    let basefee = if is_system_tx {
        cfg.disable_eip3607 = true;
        0
    } else {
        block.header().base_fee_per_gas.unwrap_or_default()
    };
    let block_env = BlockEnv {
        number: U256::from(block.header().number),
        coinbase: Address::ZERO,
        timestamp: U256::from(block.header().timestamp),
        gas_limit: U256::from(block.header().gas_limit),
        basefee: U256::from(basefee),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(0, false)),
        difficulty: U256::ZERO,
        prevrandao: Some(B256::ZERO),
    };
    let tx_env = TxEnv {
        caller: sender,
        gas_limit: transaction.gas_limit(),
        gas_price: U256::from(transaction.max_fee_per_gas()),
        transact_to: transaction.kind(),
        value: transaction.value(),
        data: transaction.input().clone(),
        nonce: Some(transaction.nonce()),
        chain_id: transaction.chain_id(),
        access_list: transaction.access_list().map_or_else(Vec::new, |access_list| access_list.0.clone()),
        gas_priority_fee: transaction.max_priority_fee_per_gas().map(U256::from),
        blob_hashes: Vec::new(),
        max_fee_per_blob_gas: None,
        authorization_list: None,
    };

    let ResultAndState { result, mut state } = Evm::builder()
        .with_db(&mut db)
        .with_env_with_handler_cfg(EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, tx_env))
        .append_handler_register_box(Box::new(move |handler| {
            set_replay_precompiles(handler, Arc::clone(precompile_results));
        }))
        .build()
        .transact()
        .unwrap();

    if chain_id == MAINNET_CHAIN_ID {
        fix_mainnet_state_diff(block.number, tx_index, is_system_tx, &mut state);
    }
    db.commit(state);

    let gas_used = result.gas_used();
    cumulative_gas_used += gas_used;
    Receipt {
        tx_type: transaction.tx_type(),
        success: result.is_success(),
        cumulative_gas_used,
        logs: result.into_logs().into_iter().collect(),
    }
}

fn process_block<S>(
    chain_id: u64,
    state: &mut S,
    erc20_contract_to_system_address: &BTreeMap<Address, Address>,
    block_and_receipts: &BlockAndReceipts,
) where
    S: State,
    <S as Database>::Error: std::fmt::Debug,
{
    let BlockAndReceipts { block, receipts, system_txs, read_precompile_calls, highest_precompile_address } =
        block_and_receipts;
    let EvmBlock::Reth115(block) = block;
    let precompile_results = {
        let mut res: HashMap<_, _> = read_precompile_calls
            .iter()
            .map(|(address, calls)| (*address, Arc::new(calls.iter().cloned().collect())))
            .collect();
        let highest_precompile_address =
            highest_precompile_address.unwrap_or(address!("0x000000000000000000000000000000000000080d"));
        let mut i = 0x800;
        loop {
            let address = Address::from(U160::from(i));
            if address > highest_precompile_address {
                break;
            }
            res.entry(address).or_default();
            i += 1;
        }
        Arc::new(res)
    };

    if block.number == 1 {
        deploy_system_contract(
            state,
            NATIVE_TOKEN_SYSTEM_ADDRESS,
            bytes!(
                "0x608060405236603f5760405134815233907f88a5966d370b9919b20f3e2c13ff65706f196a4e32cc2c12bf57088f885258749060200160405180910390a2005b600080fdfea2646970667358221220ca425db50898ac19f9e4676e86e8ebed9853baa048942f6306fe8a86b8d4abb964736f6c63430008090033"
            ),
        );
        deploy_system_contract(
            state,
            WHYPE_CONTRACT_ADDRESS,
            bytes!(
                "0x6080604052600436106100bc5760003560e01c8063313ce56711610074578063a9059cbb1161004e578063a9059cbb146102cb578063d0e30db0146100bc578063dd62ed3e14610311576100bc565b8063313ce5671461024b57806370a082311461027657806395d89b41146102b6576100bc565b806318160ddd116100a557806318160ddd146101aa57806323b872dd146101d15780632e1a7d4d14610221576100bc565b806306fdde03146100c6578063095ea7b314610150575b6100c4610359565b005b3480156100d257600080fd5b506100db6103a8565b6040805160208082528351818301528351919283929083019185019080838360005b838110156101155781810151838201526020016100fd565b50505050905090810190601f1680156101425780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561015c57600080fd5b506101966004803603604081101561017357600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060200135610454565b604080519115158252519081900360200190f35b3480156101b657600080fd5b506101bf6104c7565b60408051918252519081900360200190f35b3480156101dd57600080fd5b50610196600480360360608110156101f457600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135811691602081013590911690604001356104cb565b34801561022d57600080fd5b506100c46004803603602081101561024457600080fd5b503561066b565b34801561025757600080fd5b50610260610700565b6040805160ff9092168252519081900360200190f35b34801561028257600080fd5b506101bf6004803603602081101561029957600080fd5b503573ffffffffffffffffffffffffffffffffffffffff16610709565b3480156102c257600080fd5b506100db61071b565b3480156102d757600080fd5b50610196600480360360408110156102ee57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060200135610793565b34801561031d57600080fd5b506101bf6004803603604081101561033457600080fd5b5073ffffffffffffffffffffffffffffffffffffffff813581169160200135166107a7565b33600081815260036020908152604091829020805434908101909155825190815291517fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c9281900390910190a2565b6000805460408051602060026001851615610100027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190941693909304601f8101849004840282018401909252818152929183018282801561044c5780601f106104215761010080835404028352916020019161044c565b820191906000526020600020905b81548152906001019060200180831161042f57829003601f168201915b505050505081565b33600081815260046020908152604080832073ffffffffffffffffffffffffffffffffffffffff8716808552908352818420869055815186815291519394909390927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a350600192915050565b4790565b73ffffffffffffffffffffffffffffffffffffffff83166000908152600360205260408120548211156104fd57600080fd5b73ffffffffffffffffffffffffffffffffffffffff84163314801590610573575073ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff14155b156105ed5773ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020548211156105b557600080fd5b73ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020805483900390555b73ffffffffffffffffffffffffffffffffffffffff808516600081815260036020908152604080832080548890039055938716808352918490208054870190558351868152935191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929081900390910190a35060019392505050565b3360009081526003602052604090205481111561068757600080fd5b33600081815260036020526040808220805485900390555183156108fc0291849190818181858888f193505050501580156106c6573d6000803e3d6000fd5b5060408051828152905133917f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65919081900360200190a250565b60025460ff1681565b60036020526000908152604090205481565b60018054604080516020600284861615610100027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190941693909304601f8101849004840282018401909252818152929183018282801561044c5780601f106104215761010080835404028352916020019161044c565b60006107a03384846104cb565b9392505050565b60046020908152600092835260408084209091529082529020548156fea265627a7a72315820e87684b404839c5657b1e7820bfa5ac4539ac8c83c21e28ec1086123db902cfe64736f6c63430005110032"
            ),
        );
    }

    let mut cumulative_gas_used = 0;
    for (tx_index, system_tx) in system_txs.iter().enumerate() {
        let SystemTx { tx, receipt } = system_tx;
        let computed_receipt = apply_tx(ApplyTxArgs {
            chain_id,
            block,
            precompile_results: &precompile_results,
            sender: if tx.input().is_empty() {
                NATIVE_TOKEN_SYSTEM_ADDRESS
            } else {
                erc20_contract_to_system_address[&tx.to().unwrap()]
            },
            transaction: tx,
            tx_index,
            is_system_tx: true,
            cumulative_gas_used,
            db: state,
        });
        cumulative_gas_used = computed_receipt.cumulative_gas_used;
        if let Some(receipt) = receipt {
            assert_eq!(computed_receipt, receipt.clone().into());
        }
    }

    let mut cumulative_gas_used = 0;
    let mut computed_receipts = Vec::new();
    for (tx_index, tx_signed) in block.body().transactions.iter().enumerate() {
        let (tx_signed, signer) = tx_signed.clone().try_into_ecrecovered().unwrap().into_parts();
        let transaction = tx_signed.transaction;
        let receipt = apply_tx(ApplyTxArgs {
            chain_id,
            block,
            precompile_results: &precompile_results,
            sender: signer,
            transaction: &transaction,
            tx_index,
            is_system_tx: false,
            cumulative_gas_used,
            db: state,
        });
        cumulative_gas_used = receipt.cumulative_gas_used;
        computed_receipts.push(receipt);
    }
    // Before this height threshold, the blockhash opcode would just return keccak256(number.to_string().as_bytes())
    if block.header().number >= NON_PLACEHOLDER_BLOCK_HASH_HEIGHT {
        state.insert_block_hash(block.number, block.hash());
    }
    let expected_receipts: Vec<Receipt> = receipts.iter().cloned().map(Into::into).collect();
    assert_eq!(expected_receipts, computed_receipts);
}

pub fn run_blocks<S>(
    chain_id: u64,
    mut state: S,
    blocks: Vec<(u64, Vec<(u64, BlockAndReceipts)>)>,
    erc20_contract_to_system_address: &BTreeMap<Address, Address>,
) -> StateHash
where
    S: State,
    <S as Database>::Error: std::fmt::Debug,
{
    let start_block = blocks.first().unwrap().1.first().unwrap().0;
    let end_block = blocks.last().unwrap().1.last().unwrap().0;
    let start = Instant::now();
    let mut state_hash = None;
    for (i, chunk) in blocks {
        println!("{i}");
        let start = Instant::now();
        for &(block_num, ref block_and_receipts) in &chunk {
            let BlockAndReceipts { block: EvmBlock::Reth115(block), .. } = block_and_receipts;
            assert_eq!(block_num, block.number);
            process_block(chain_id, &mut state, erc20_contract_to_system_address, block_and_receipts);
            if block_num % 10000 == 0 || block_num == end_block {
                let start = Instant::now();
                let hash = state.blake3_hash_slow();
                println!("Computed state hash after block={block_num}: {hash:?} in {:?}", start.elapsed());
                state_hash = Some(hash);
            }
        }
        println!("Processed blocks {}-{} in {:?}", i, i + (chunk.len() as u64), start.elapsed());
    }
    println!("Processed n={} blocks in {:?}", end_block - start_block + 1, start.elapsed());
    state_hash.unwrap()
}

pub const MAINNET_CHAIN_ID: u64 = 999;
pub const TESTNET_CHAIN_ID: u64 = 998;

const NATIVE_TOKEN_SYSTEM_ADDRESS: Address = address!("0x2222222222222222222222222222222222222222");
const WHYPE_CONTRACT_ADDRESS: Address = address!("0x5555555555555555555555555555555555555555");
const NON_PLACEHOLDER_BLOCK_HASH_HEIGHT: u64 = 243_538;

#[allow(clippy::cast_possible_truncation)] // len(s) <= 31
const fn encode_short_string(s: &str) -> U256 {
    assert!(s.len() <= 31, "short string length must be at most 31 bytes");
    let mut bytes = [0u8; 32];
    let s_bytes = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        bytes[i] = s_bytes[i];
        i += 1;
    }
    bytes[31] = (s.len() * 2) as u8;
    U256::from_be_bytes(bytes)
}
