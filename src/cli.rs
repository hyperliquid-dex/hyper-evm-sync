use anyhow::Result;
use clap::{Parser, Subcommand};
use revm::InMemoryDB;

use crate::{
    evm_map::erc20_contract_to_system_address,
    fs::{download_blocks, read_abci_state, read_blocks, read_evm_state},
    run::{run_blocks, MAINNET_CHAIN_ID},
    state::State,
};

const CHUNK_SIZE: u64 = 10000;

#[derive(Parser)]
#[command(name = "hyper-evm-sync")]
pub struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Download {
        #[arg(short, long)]
        dir: String,
        #[arg(short, long, default_value_t = 1)]
        start_block: u64,
        #[arg(short, long)]
        end_block: u64,
    },
    SyncFromAbciState {
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
    SyncFromEvmState {
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
}

impl Cli {
    pub async fn execute(self) -> Result<()> {
        match self.commands {
            Commands::Download {
                start_block,
                end_block,
                dir,
            } => {
                let max_block = download_blocks(&dir, start_block, end_block).await?;
                match max_block {
                    Some(block_num) => println!("Downloaded {start_block} -> {block_num}."),
                    None => println!("Blocks do not exist yet"),
                };
            }
            Commands::SyncFromAbciState {
                fln,
                snapshot_dir,
                chunk_size,
                blocks_dir,
                end_block,
            } => run_from_state(blocks_dir, fln, true, snapshot_dir, chunk_size, end_block).await?,
            Commands::SyncFromEvmState {
                blocks_dir,
                fln,
                snapshot_dir,
                chunk_size,
                end_block,
            } => {
                run_from_state(blocks_dir, fln, false, snapshot_dir, chunk_size, end_block).await?
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
    let erc20_contract_to_system_address =
        erc20_contract_to_system_address(MAINNET_CHAIN_ID).await?;
    let (start_block, state) = if let Some(state_fln) = state_fln {
        if is_abci {
            read_abci_state(state_fln)?
        } else {
            read_evm_state(state_fln)?
        }
    } else {
        (1, InMemoryDB::genesis())
    };
    println!("{start_block} -> {end_block}");

    let blocks = read_blocks(&blocks_dir, start_block, end_block, chunk_size);

    run_blocks(
        MAINNET_CHAIN_ID,
        state,
        blocks,
        &erc20_contract_to_system_address,
        snapshot_dir,
        chunk_size,
    );
    Ok(())
}
