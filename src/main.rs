use anyhow::Result;
use hyper_evm_sync::{evm_map::evm_map, read_blocks::read_blocks, run::run_blocks, state::State};
use revm::InMemoryDB;

fn main() -> Result<()> {
    let evm_map = evm_map()?;

    let start_block = 1;
    let end_block = std::env::args().nth(2).unwrap().parse::<u64>().unwrap();
    println!("{start_block} -> {end_block}");

    let blocks = read_blocks(
        &std::env::args().nth(1).unwrap(),
        start_block,
        end_block,
        CHUNK_SIZE,
    );

    run_blocks(InMemoryDB::genesis(), blocks, &evm_map)?;

    Ok(())
}

const CHUNK_SIZE: u64 = 10000;
