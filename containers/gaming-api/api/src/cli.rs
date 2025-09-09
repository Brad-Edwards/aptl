use clap::Parser;
use crate::Result;

/// Gaming API CLI - Mock MMO server for security demonstrations
#[derive(Parser)]
#[command(name = "gaming-api")]
#[command(about = "A mock gaming API for account takeover simulations")]
pub struct Cli;

impl Cli {
    pub async fn run(self) -> Result<()> {
        println!("Initializing database and seeding data...");
        crate::db::init().await?;
        crate::generators::generate_account_status(&crate::db::get_pool().await?).await?;
        println!("Complete!");
        Ok(())
    }
}