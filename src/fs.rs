use crate::types::{AbciState, BlockAndReceipts, EvmBlock, EvmState, PreprocessedBlock};
use anyhow::Result;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_sdk_s3::{types::RequestPayer, Client};
use futures::{stream, StreamExt, TryStreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_primitives::transaction::SignedTransactionIntoRecoveredExt;
use revm::InMemoryDB;
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

const DOWNLOAD_CHUNK_SIZE: u64 = 10000;
const CONCURRENCY_LIMIT: usize = 500;

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

pub fn read_blocks(dir: &str, start_block: u64, end_block: u64, chunk_size: u64) -> Vec<(u64, Vec<PreprocessedBlock>)> {
    let start = Instant::now();
    let ranges: Vec<_> = (start_block..=end_block).step_by(usize::try_from(chunk_size).unwrap()).collect();
    let mut all_blocks = Vec::new();
    for chunk in ranges {
        let start = Instant::now();
        let start_block = chunk;
        let end_block = (chunk + chunk_size - 1).min(end_block);
        let blocks: Vec<_> = (start_block..=end_block)
            .into_par_iter()
            .map(|block_num| {
                let f = ((block_num - 1) / 1_000_000) * 1_000_000;
                let s = ((block_num - 1) / 1_000) * 1_000;
                let path = format!("{dir}/{f}/{s}/{block_num}.rmp.lz4");
                let path = PathBuf::from(path);
                let block_and_receipts = read_block_and_receipts(&path)
                    .inspect_err(|_| println!("failed to read block {block_num}"))
                    .unwrap();
                let BlockAndReceipts { block: EvmBlock::Reth115(block), .. } = &block_and_receipts;
                let signers = block
                    .body()
                    .transactions
                    .iter()
                    .map(|tx_signed| tx_signed.clone().try_into_ecrecovered().unwrap().into_parts().1)
                    .collect_vec();
                PreprocessedBlock { block_num, block_and_receipts, signers }
            })
            .collect();
        // let blocks = stream::iter(futures).buffered(CONCURRENCY_LIMIT).collect().await;
        println!("Deserialized blocks {}-{} in {:?}", start_block, end_block, start.elapsed());
        all_blocks.push((chunk, blocks));
    }
    println!("Deserialized n={} blocks in {:?}", end_block - start_block + 1, start.elapsed());
    all_blocks
}

pub fn read_abci_state(fln: String) -> Result<(u64, InMemoryDB)> {
    let mut file = File::open(fln)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let state: AbciState = rmp_serde::from_slice(&buffer)?;
    Ok(state.into_next_block_num_and_in_memory_db())
}

pub fn read_evm_state(fln: String) -> Result<(u64, InMemoryDB)> {
    let mut file = File::open(fln)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let (next_block_num, evm_state): (u64, EvmState) = rmp_serde::from_slice(&buffer)?;
    Ok((next_block_num, evm_state.into()))
}

fn create_file_with_dirs(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    Ok(File::create(path)?)
}

pub fn snapshot_evm_state(next_block_num: u64, state: &EvmState, fln: String) -> Result<()> {
    let mut file = create_file_with_dirs(Path::new(&fln))?;
    let buffer = rmp_serde::to_vec(&(next_block_num, state))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn block_key(block_num: u64) -> String {
    let f = ((block_num - 1) / 1_000_000) * 1_000_000;
    let s = ((block_num - 1) / 1_000) * 1_000;
    format!("{f}/{s}/{block_num}.rmp.lz4")
}

async fn fetch_block(block_num: u64, dir: PathBuf, s3: Arc<Client>, pb: ProgressBar, bucket: &str) -> Result<()> {
    let key = block_key(block_num);
    let local_path: PathBuf = dir.join(&key);

    if let Some(parent) = local_path.parent() {
        create_dir_all(parent)?;
    }

    if local_path.is_file() {
        pb.inc(1);
        return Ok(());
    }

    let obj = s3.get_object().bucket(bucket).key(key).request_payer(RequestPayer::Requester).send().await?;

    let mut body = obj.body.into_async_read();
    let mut file = tokio::fs::File::create(&local_path).await?;
    tokio::io::copy(&mut body, &mut file).await?;

    pb.inc(1);
    Ok(())
}

pub async fn download_blocks(dir: &str, start_block: u64, end_block: u64) -> Result<()> {
    let pb = ProgressBar::new(end_block - start_block + 1);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("##-"),
    );
    let region = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::defaults(BehaviorVersion::latest()).region(region).load().await;
    let s3 = Arc::new(Client::new(&config));

    let bucket = "hl-mainnet-evm-blocks";
    let mut cur_block = start_block;
    while cur_block <= end_block {
        let next_block = (end_block + 1).min(cur_block + DOWNLOAD_CHUNK_SIZE);
        let mut futures = Vec::with_capacity((next_block - cur_block).try_into().unwrap());
        for block_num in cur_block..next_block {
            let local_path = PathBuf::from(dir);
            let s3 = s3.clone();
            let pb = pb.clone();
            futures.push(fetch_block(block_num, local_path, s3, pb, bucket));
        }
        stream::iter(futures).buffer_unordered(CONCURRENCY_LIMIT).try_collect::<Vec<()>>().await?;
        cur_block = next_block;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        fs::{download_blocks, read_abci_state, read_evm_state, snapshot_evm_state},
        state::State,
    };
    use anyhow::Result;
    use std::time::Instant;

    #[tokio::test]
    async fn test_block_download() -> Result<()> {
        let time = Instant::now();
        download_blocks("hl-mainnet-evm-blocks", 4000000, 4001000).await?;
        println!("downloaded in {:?}", time.elapsed());
        Ok(())
    }

    #[test]
    fn test_evm_state_serde() -> Result<()> {
        let abci_state_path = "tmp/abci_state.rmp";
        let state = read_abci_state(abci_state_path.to_owned())?;
        let snapshot_path = "tmp/snapshot.rmp";
        let hash1 = state.1.blake3_hash_slow();
        snapshot_evm_state(state.0, &state.1.into(), snapshot_path.to_owned())?;
        let state = read_evm_state(snapshot_path.to_owned())?;
        let hash2 = state.1.blake3_hash_slow();
        assert_eq!(hash1, hash2);
        Ok(())
    }
}
