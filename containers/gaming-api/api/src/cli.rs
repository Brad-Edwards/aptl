use clap::{Parser, Subcommand};
use crate::Result;

/// Gaming API CLI - Mock MMO server for security demonstrations
#[derive(Parser)]
#[command(name = "gaming-api")]
#[command(about = "A mock gaming API for account takeover simulations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        self.command.execute().await
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize database and seed with all data
    Run,
}

impl Commands {
    pub async fn execute(self) -> Result<()> {
        match self {
            Commands::Run => {
                println!("Initializing database and seeding data...");
                crate::db::init().await?;
                crate::generators::generate_account_status(&crate::db::get_pool().await?).await?;
                println!("Complete!");
            }
        }
        Ok(())
    }
}