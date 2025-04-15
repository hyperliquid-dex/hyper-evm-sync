use crate::types::{AbciState, BlockAndReceipts};
use anyhow::Result;
use rayon::prelude::*;
use revm::InMemoryDB;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

fn decompress(data: &[u8]) -> Result<Vec<u8>, lz4_flex::frame::Error> {
    let mut decoder = lz4_flex::frame::FrameDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn read_block_and_receipts(file_path: &Path) -> Result<BlockAndReceipts> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let buffer = decompress(&buffer)?;

    let mut input: Vec<_> = rmp_serde::from_slice(&buffer)?;
    assert_eq!(input.len(), 1);
    Ok(input.pop().unwrap())
}

pub fn read_blocks(
    dir: &str,
    start_block: u64,
    end_block: u64,
    chunk_size: u64,
) -> Vec<(u64, Vec<(u64, BlockAndReceipts)>)> {
    let start = Instant::now();
    let ranges: Vec<_> = (start_block..=end_block).step_by(usize::try_from(chunk_size).unwrap()).collect();
    let blocks: Vec<_> = ranges
        .into_par_iter()
        .map(|chunk| {
            let mut blocks: Vec<(_, BlockAndReceipts)> = Vec::new();
            let start = Instant::now();
            let start_block = chunk;
            let end_block = (chunk + chunk_size - 1).min(end_block);
            for block_num in start_block..=end_block {
                let f = ((block_num - 1) / 1_000_000) * 1_000_000;
                let s = ((block_num - 1) / 1_000) * 1_000;
                let path = format!("{dir}/{f}/{s}/{block_num}.rmp.lz4");
                let path = PathBuf::from(path);

                let block_and_receipts = read_block_and_receipts(&path)
                    .inspect_err(|_| println!("failed to read block {block_num}"))
                    .unwrap();

                blocks.push((block_num, block_and_receipts));
            }
            println!("Deserialized blocks {}-{} in {:?}", start_block, end_block, start.elapsed());
            (chunk, blocks)
        })
        .collect();
    println!("Deserialized n={end_block} blocks in {:?}", start.elapsed());
    blocks
}

pub fn read_abci_state(fln: String) -> Result<(u64, InMemoryDB)> {
    let mut file = File::open(fln)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let state: AbciState = rmp_serde::from_slice(&buffer)?;
    Ok(state.into_next_block_num_and_in_memory_db())
}
