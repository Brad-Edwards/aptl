use clap::Parser;
use gaming_api::{cli::Cli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await
}
