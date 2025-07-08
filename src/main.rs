use anyhow::Result;
use clap::Parser;
use hyper_evm_sync::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::try_parse()?;
    cli.execute().await?;
    Ok(())
}
