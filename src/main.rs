use anyhow::Result;
use hyper_evm_sync::{
    evm_map::erc20_contract_to_system_address,
    fs::{read_abci_state, read_blocks},
    run::{run_blocks, MAINNET_CHAIN_ID},
    state::State,
};
use revm::InMemoryDB;
fn main() -> Result<()> {
    let erc20_contract_to_system_address = erc20_contract_to_system_address(MAINNET_CHAIN_ID)?;

    let (start_block, state) =
        std::env::args().nth(3).map_or_else(|| Ok((1, InMemoryDB::genesis())), read_abci_state)?;
    let end_block = std::env::args().nth(2).unwrap().parse::<u64>()?;
    println!("{start_block} -> {end_block}");

    let blocks = read_blocks(&std::env::args().nth(1).unwrap(), start_block, end_block, CHUNK_SIZE);

    run_blocks(MAINNET_CHAIN_ID, state, blocks, &erc20_contract_to_system_address);

    Ok(())
}

const CHUNK_SIZE: u64 = 10000;
