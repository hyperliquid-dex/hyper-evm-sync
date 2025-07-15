use anyhow::Result;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use revm::InMemoryDB;
use tokio::sync::mpsc;

use crate::{
    evm_map::erc20_contract_to_system_address,
    fs::{download_blocks, read_abci_state, read_blocks, read_evm_state},
    run::{run_blocks, MAINNET_CHAIN_ID},
    state::State,
    types::PreprocessedBlock,
};
use anyhow::anyhow;

// take snapshots this often (default)
const CHUNK_SIZE: u64 = 1000;
// only store this many blocks in memory
const READ_LIMIT: u64 = 100000;

#[derive(Parser)]
#[command(name = "hyper-evm-sync")]
pub struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    DownloadBlocks {
        #[arg(short, long)]
        dir: String,
        #[arg(short, long, default_value_t = 1)]
        start_block: u64,
        #[arg(short, long)]
        end_block: u64,
    },
    SyncFromState {
        #[arg(long)]
        is_abci: bool,
        #[arg(short, long)]
        blocks_dir: String,
        #[arg(short, long)]
        fln: Option<String>,
        #[arg(short, long)]
        snapshot_dir: Option<String>,
        #[arg(short, long, default_value_t = CHUNK_SIZE)]
        chunk_size: u64,
        #[arg(short, long)]
        end_block: u64,
    },
    NextBlockNumber {
        #[arg(short, long)]
        abci_state_fln: Option<String>,
        #[arg(short, long)]
        evm_state_fln: Option<String>,
    },
}

impl Cli {
    pub async fn execute(self) -> Result<()> {
        match self.commands {
            Commands::DownloadBlocks { start_block, end_block, dir } => {
                download_blocks(&dir, start_block, end_block).await?;
                println!("Downloaded {start_block} -> {end_block}.");
            }
            Commands::SyncFromState { fln, is_abci, snapshot_dir, chunk_size, blocks_dir, end_block } => {
                run_from_state(blocks_dir, fln, is_abci, snapshot_dir, chunk_size, end_block).await?
            }
            Commands::NextBlockNumber { abci_state_fln, evm_state_fln } => {
                if let Some(fln) = abci_state_fln {
                    println!("{}", read_abci_state(fln)?.0);
                } else if let Some(fln) = evm_state_fln {
                    println!("{}", read_evm_state(fln)?.0);
                } else {
                    return Err(anyhow!("No file specified"));
                }
            }
        }
        Ok(())
    }
}

async fn run_from_state(
    blocks_dir: String,
    state_fln: Option<String>,
    is_abci: bool,
    snapshot_dir: Option<String>,
    chunk_size: u64,
    end_block: u64,
) -> Result<()> {
    let erc20_contract_to_system_address = erc20_contract_to_system_address(MAINNET_CHAIN_ID).await?;
    let (start_block, mut state) = if let Some(state_fln) = state_fln {
        if is_abci {
            read_abci_state(state_fln)?
        } else {
            read_evm_state(state_fln)?
        }
    } else {
        (1, InMemoryDB::genesis())
    };
    println!("{start_block} -> {end_block}");
    let pb = ProgressBar::new(end_block - start_block + 1);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("##-"),
    );
    let (tx, mut rx) = mpsc::channel::<Vec<(u64, Vec<PreprocessedBlock>)>>(1);

    let processor = tokio::spawn(async move {
        while let Some(blocks) = rx.recv().await {
            run_blocks(
                Some(pb.clone()),
                MAINNET_CHAIN_ID,
                &mut state,
                blocks,
                &erc20_contract_to_system_address,
                snapshot_dir.clone(),
                chunk_size,
            );
        }
    });

    let reader = tokio::spawn(async move {
        let mut cur_block = start_block;
        while cur_block <= end_block {
            let last_block_in_chunk = end_block.min(cur_block + READ_LIMIT - 1);
            let blocks = read_blocks(&blocks_dir, cur_block, last_block_in_chunk, chunk_size);
            tx.send(blocks).await.unwrap();
            cur_block = last_block_in_chunk + 1;
        }
    });

    let _ = tokio::join!(processor, reader);
    Ok(())
}
